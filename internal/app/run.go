package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/ca"
	"github.com/503329706qq/gha-github-accelerator/internal/control"
	"github.com/503329706qq/gha-github-accelerator/internal/dialer"
	"github.com/503329706qq/gha-github-accelerator/internal/hosts"
	"github.com/503329706qq/gha-github-accelerator/internal/log"
	"github.com/503329706qq/gha-github-accelerator/internal/proxy"
	"github.com/503329706qq/gha-github-accelerator/internal/resolver"
	"github.com/503329706qq/gha-github-accelerator/internal/sni"
	"github.com/503329706qq/gha-github-accelerator/internal/store"
)

// cmdRun 是真正干活的那条命令。
//
// 顺序是刻意的：先绑端口 → 再起控制接口和 CRL → 预热 DNS → 最后才写 hosts。
// 任何一步失败都还没动机器上的解析，用户最多看到"gha 起不来"，而不是整台机器的
// GitHub 突然全断。
func cmdRun(a Args) int {
	if relaunched, code := requireAdmin(a, a.Autostart); relaunched {
		return code
	}
	cfg, cfgFile, err := loadConfig(a)
	if err != nil {
		return fail(err)
	}
	if a.Autostart {
		hideConsole()
	}
	// 自启模式没有控制台：任务计划里只剩一个退出码，什么都看不到。
	// 所以这个模式额外落一份日志文件，否则"开机就失败"根本无从查起。
	var out io.Writer = os.Stdout
	if a.Autostart {
		// 注意：这里只能写文件，不能 io.MultiWriter(os.Stdout, f)。
		// 任务计划启动的进程没有有效的 stdout 句柄，MultiWriter 会在第一个
		// 写入处返回错误，后面的文件就再也写不进去了——日志等于没有。
		if w, closeFn, err := autostartLog(filepath.Join(cfg.P().DataDir, "logs")); err == nil {
			defer closeFn()
			out = w
		} else {
			fmt.Fprintf(os.Stderr, "gha: 自启日志打开失败：%v\n", err)
		}
	}
	logger := log.New(out, log.ParseLevel(cfg.LogLevel))
	p := cfg.P()
	if err := os.MkdirAll(p.CA(), 0o755); err != nil {
		return fail(err)
	}

	c, err := ca.LoadOrCreate(ca.Options{
		CertPath: p.CertPEM(),
		KeyPath:  p.KeyPEM(),
		CRLURL:   cfg.CRLHTTPBase + "/ca.crl",
	})
	if err != nil {
		return fail(fmt.Errorf("加载根证书：%w", err))
	}
	// 每次启动都刷一次 CRL 到存储里：证书可能被手工删过，失败也不致命（还有 HTTP 分发点）。
	if der, err := c.CRL(); err == nil {
		if err := store.InstallCRL(store.LocalMachine, der); err != nil {
			logger.Debug("刷新存储里的 CRL 失败：%v", err)
		}
	} else {
		logger.Debug("生成 CRL 失败：%v", err)
	}
	// 长时间挂机时存储里那份 CRL 会过期（schannel 就会转而依赖 12080 的分发点，
	// 而控制端口一旦不可达证书校验就会失败）。每 24h 重签一次并重新写进存储。
	crlStop := make(chan struct{})
	defer close(crlStop)
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-crlStop:
				return
			case <-t.C:
				der, err := c.CRL()
				if err != nil {
					logger.Debug("重签 CRL 失败：%v", err)
					continue
				}
				if err := store.InstallCRL(store.LocalMachine, der); err != nil {
					logger.Debug("更新存储里的 CRL 失败：%v", err)
				}
			}
		}
	}()

	res := resolver.New(resolver.Options{
		JSON:     cfg.DoHJSON,
		Wire:     cfg.DoHWire,
		Fallback: cfg.FallbackDNS,
		IPv6:     cfg.IPv6,
		Seeds:    cfg.SeedAddrs(),
	})
	dl := dialer.New(dialer.Options{Resolver: res})

	var (
		requests atomic.Int64
		lastErr  atomic.Value
		started  = time.Now()
	)
	// 按需探测：某个 host 的上游请求最终失败（重试耗尽）时，去抖地补一轮
	// 探测，把长尾域名（avatars 之类从不预热的主机）的实测数据补进评分。
	// 20 秒去抖：避免一个坏 IP 在 100 个并发请求里触发 100 轮探测。
	needProbe := newProbeDebouncer(20 * time.Second)
	srv := proxy.New(proxy.Options{
		CA:    c,
		Allow: sni.InAllowlist,
		Dial:  dl.DialContext,
		// 上游 HTTPS 走"拨号 + TLS 一起竞速"的那条路：TCP 假快的黑洞地址会在
		// TLS 握手阶段自己出局，不会赢下竞速再把请求拖进 8s 预算耗尽。
		DialTLS: dl.DialTLSContext,
		Passthrough: func(ctx context.Context, host string) (net.Conn, error) {
			return dl.DialContext(ctx, "tcp", host+":443")
		},
		Logger: logger,
		OnRequest: func(host string, bytes int64, dur time.Duration, status int) {
			requests.Add(1)
			// 吞吐回写给 dialer 的工作在 dialer 内部随连接完成度做（它知道具体 IP），
			// 这里只保留"哪个站点在报 5xx"这一条对排查最有用的信息。
			if status >= 500 {
				lastErr.Store(fmt.Sprintf("%s: HTTP %d", host, status))
			}
		},
		OnUpstreamIPFail: func(ip netip.Addr, err error) {
			// 一次尝试以响应头超时/连接错误收场：精确惩罚这次真正拨到的 IP，
			// 下一次竞速把它排进"已验证失败"档，并摘掉指向它的粘性。
			dl.Penalize(ip)
			logger.Debug("upstream ip fail %s: %v", ip, err)
		},
		OnUpstreamIPOK: func(ip netip.Addr) {
			// 响应头到手：这个地址不只是能握手，是真的在传数据。把它立成该
			// 域名的粘性地址，后续并发请求直接走它——这是唯一能区分
			// "TLS 通但不吐数据"的黑洞地址与好地址的信号。
			dl.Praise(ip)
		},
		OnUpstreamError: func(host string, err error) {
			needProbe.Fire(host, func() {
				probeHost(dl, res, host, logger)
			})
		},
	})

	// 先绑端口：这是"能不能开工"的唯一硬条件。
	httpsLn, err := net.Listen("tcp", cfg.Listen.HTTPS)
	if err != nil {
		fmt.Fprintf(os.Stderr, `gha: 监听 %s 失败：%v

最常见的原因是 80/443 已经被本机另一个加速器/代理占着——任何把 GitHub 域名
指到 127.0.0.1 的工具都要监听这两个端口，同一时间只能有一个生效。
请先退出那个程序（通常在其托盘图标上右键退出），再运行 gha。
`, cfg.Listen.HTTPS, err)
		return 1
	}
	httpLn, err := net.Listen("tcp", cfg.Listen.HTTP)
	if err != nil {
		httpsLn.Close()
		return fail(fmt.Errorf("监听 %s 失败：%w", cfg.Listen.HTTP, err))
	}
	ctrlLn, err := net.Listen("tcp", cfg.Listen.Control)
	if err != nil {
		httpsLn.Close()
		httpLn.Close()
		return fail(fmt.Errorf("监听 %s 失败：%w", cfg.Listen.Control, err))
	}

	var (
		quit     = make(chan struct{})
		quitOnce sync.Once
	)
	stop := func() { quitOnce.Do(func() { close(quit) }) }

	statusFn := func() any {
		present, lines, _ := hosts.Status(hostsPath())
		st := map[string]any{
			"version":    Version,
			"pid":        os.Getpid(),
			"uptime_s":   int(time.Since(started).Seconds()),
			"listen":     map[string]string{"https": cfg.Listen.HTTPS, "http": cfg.Listen.HTTP, "control": cfg.Listen.Control},
			"domains":    len(cfg.AllDomains()),
			"requests":   requests.Load(),
			"hosts":      map[string]any{"present": present, "lines": lines},
			"config":     cfgFile,
			"no_hosts":   a.NoHosts,
			"upstream":   "doh+race",
			"root_ca_cn": c.Certificate().Subject.CommonName,
		}
		if v, ok := lastErr.Load().(string); ok {
			st["last_error"] = v
		}
		return st
	}

	ctrlSrv := &http.Server{
		Handler: control.New(control.Options{
			Token:  cfg.Token,
			CRL:    c.CRL,
			Status: statusFn,
			OnQuit: stop,
			OnReload: func() error {
				if a.NoHosts {
					return nil
				}
				_, err := hosts.ApplyTo(hostsPath(), cfg.AllDomains(), p.BackupDir())
				return err
			},
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := ctrlSrv.Serve(ctrlLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("控制接口退出：%v", err)
		}
	}()
	go func() {
		if err := srv.ServeTLS(httpsLn); err != nil && !isClosedErr(err) {
			logger.Error("HTTPS 服务退出：%v", err)
		}
	}()
	go func() {
		if err := srv.ServeHTTP(httpLn); err != nil && !isClosedErr(err) {
			logger.Error("HTTP 服务退出：%v", err)
		}
	}()

	// DNS 预热放在后台：不阻塞启动，但用户第一次点 GitHub 时大概率已经拿到地址。
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res.Prefetch(ctx, cfg.AllDomains())
	}()

	// 热门域名再做一轮 TLS 探测，把"这排 IP 里哪些真能走流量"提前灌进拨号评分。
	//
	// 起因是 2026-11-03 的实测：同一域名的候选里混着"TCP 三次握手成功、之后
	// 一个字节都不回"的黑洞地址（20.205.243.166、140.82.112.4 等），它们会让
	// 一次请求白等到超时才 502；而当时能用的 140.82.112.3 排在候选后面。
	// 只测 TCP 分辨不出这种地址，所以这里直接做 TLS 握手——通了才算数。
	go func() {
		warmUpUpstreams(dl, res, logger, warmupFullProbe)
		// 周期探测只做小范围确认，见 warmupQuickProbe/warmupInterval 的注释。
		var quietUntil time.Time
		t := time.NewTicker(warmupInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if time.Now().Before(quietUntil) {
					continue
				}
				if warmUpUpstreams(dl, res, logger, warmupQuickProbe) == 0 {
					quietUntil = time.Now().Add(warmupQuiet)
					logger.Info("上游探测整轮无可用地址，%s 内暂停周期探测（避免继续给上游添噪音）", warmupQuiet)
				}
			case <-quit:
				return
			}
		}
	}()

	wroteHosts := false
	if !a.NoHosts {
		if _, err := hosts.ApplyTo(hostsPath(), cfg.AllDomains(), p.BackupDir()); err != nil {
			ctrlSrv.Close()
			srv.Close()
			return fail(fmt.Errorf("写 hosts 失败：%w", err))
		}
		// 不能用 Apply 的 changed 决定"要不要还原"：changed=false 恰恰说明
		// hosts 里已经有一模一样的块（上一次被强杀/断电留下的），这时更需要还原，
		// 否则残留的 127.0.0.1 会永久留在机器上，GitHub 全站拒绝连接。
		// Restore 本身是幂等的（没有块就什么都不做），这里只管"我们接管过"。
		wroteHosts = true
		logger.Info("hosts 已指向本机（%d 个域名）", len(cfg.AllDomains()))
	}
	// 退出时无论如何都要摘掉 hosts：这是"不会把机器搞坏"的最后一道保险。
	// 单独抽成闭包，是为了让"正在退出"那条日志排在还原之后——stdout 如果是
	// 一个卡住的管道（被 Tee/IDE 接管），日志写入会阻塞，而还原绝不能排在它后面。
	restoreHosts := func() {
		if !wroteHosts {
			return
		}
		if _, err := hosts.RestoreTo(hostsPath(), p.BackupDir()); err != nil {
			fmt.Fprintf(os.Stderr, "gha: 还原 hosts 失败：%v\n请手动删除 %s 里的 gha 块\n", err, hostsPath())
			return
		}
		wroteHosts = false
		logger.Info("hosts 已还原")
	}
	defer restoreHosts()

	// 控制台关闭/注销/关机 与 Ctrl+C 都走同一条退出路径。
	unwatch := watchConsole(stop)
	defer unwatch()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		select {
		case <-sig:
			stop()
		case <-quit:
		}
	}()

	fmt.Printf(`
gha %s 正在运行
  HTTPS  %s（GitHub 域名经此终结 TLS）
  HTTP   %s（301 跳转）
  控制   %s（token 在 %s）
  根证书 %s
  hosts  %s

按 Ctrl+C 退出。
`, Version, cfg.Listen.HTTPS, cfg.Listen.HTTP, cfg.Listen.Control, cfgFile, p.CertPEM(),
		map[bool]string{true: "未接管（--no-hosts）", false: "已接管"}[a.NoHosts])

	<-quit
	// 先还原 hosts，再打日志、关服务：退出路径不能依赖"stdout 还能写"。
	restoreHosts()
	logger.Info("正在退出…")
	ctrlSrv.Close()
	srv.Close()
	// 给在途请求一点时间把字节数记完（OnRequest 在写完响应后才回调）
	time.Sleep(100 * time.Millisecond)
	return 0
}

// isClosedErr 把"监听被主动关掉"这类错误过滤掉，别在正常退出时打一堆红字。
func isClosedErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed)
}

// autostartLog 给"登录自启"模式开一个日志文件：这个模式没有控制台，
// 出问题时任务计划里只有一个退出码，没有日志就等于什么都没发生。
// 追加写、不轮转——gha 的日志量很小（一行一个请求），跑一年也就几 MB。
func autostartLog(dir string) (io.Writer, func(), error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "gha.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// hotDomains 是启动时重点探测的域名：覆盖「首页 / API / 代码下载 / 头像」
// 四条主要路径。avatars 上过当：2026-11-03 它不在名单里、也没有种子数据，
// 整段黑洞时所有头像请求一起 502，用户看到的就是"应用挂了"。
// 名单外的长尾域名靠 OnUpstreamError 的按需探测兜底。
var hotDomains = []string{
	"github.com",
	"api.github.com",
	"codeload.github.com",
	"raw.githubusercontent.com",
	"objects.githubusercontent.com",
	"avatars.githubusercontent.com",
}

// probeDebouncer 把"某个 host 需要补一轮探测"的请求按窗口合并：
// 距上次触发不足窗口的请求直接丢弃，其余立即在后台跑 fn。
type probeDebouncer struct {
	window time.Duration
	mu     sync.Mutex
	last   map[string]time.Time
}

func newProbeDebouncer(window time.Duration) *probeDebouncer {
	return &probeDebouncer{window: window, last: make(map[string]time.Time)}
}

// Fire 若该 host 距上次触发超过窗口，就记录时间戳并在后台跑 fn；否则丢弃。
func (p *probeDebouncer) Fire(host string, fn func()) {
	p.mu.Lock()
	now := time.Now()
	if last, ok := p.last[host]; ok && now.Sub(last) < p.window {
		p.mu.Unlock()
		return
	}
	p.last[host] = now
	p.mu.Unlock()
	go fn()
}

const (
	// warmupFullProbe 是启动时每域名探多少个候选。种子表把常年黑洞的
	// Fastly 段（140.82.x）排在最前，能用的 Azure 段（20.x）在第 11 位之后，
	// 只探前几个会永远探不到好地址，所以启动时按种子规模探一遍。
	warmupFullProbe = 24
	// warmupQuickProbe 是周期探测的规模：好地址一旦被实测确认就会排到评分
	// 前面，之后只需要确认头部这几个还有效。
	warmupQuickProbe = 6
	// warmupInterval 是周期探测间隔。原先是 5 分钟 × 每域名 24 个候选 ×
	// 6 个热门域名 ≈ 1700 请求/小时，常年不停、与有没有故障无关，对上游
	// 就是扫描器特征；放宽到 15 分钟、每域名 6 个之后约 144 请求/小时。
	warmupInterval = 15 * time.Minute
	// warmupQuiet：一整轮探测一个可用地址都没有，说明要么链路整段断了、
	// 要么上游正在拦我们。这时候继续按轮打请求只会让情况更糟（2026-11-04
	// 17:00 github.com 整站 403 就是这么被喂出来的），所以静默一段时间。
	warmupQuiet = 30 * time.Minute
)

// warmUpUpstreams 给热门域名做一轮 TLS 探测，把结果记进拨号评分。
//
// 为什么不能只靠第一次真实请求去"试错":一个黑洞地址要等 10–20 秒才报错，
// 用户看到的就是 GitHub 打不开。提前并发探测（每个候选 3 秒）能在启动后
// 几秒内把能用的地址顶到评分前面，代价只是启动时多几个握手。
//
// maxProbe 决定每个域名探多少个候选：启动时用 warmupFullProbe 做一次全量
// 摸底，周期探测只用 warmupQuickProbe 确认头部几个还有效——每多探一个就是
// 多一个打向上游的请求，常年累月的噪音会被上游当扫描器。
// 返回本轮探到的可用地址数。
func warmUpUpstreams(dl *dialer.Dialer, res *resolver.Resolver, lg *log.Logger, maxProbe int) int {
	const (
		probeTimeout = 3 * time.Second
		concurrency  = 8
		// probeWave 是一波同时探几个。分波是为了"够用就停"：健康时段第一波
		// 就有可用地址，不必再把剩下十几个候选挨个摸一遍。种子表把常年黑洞的
		// Fastly 段排在最前，第一波全灭时才会继续往后探——那时才真的需要。
		probeWave = 8
	)
	total := 0
	for _, host := range hotDomains {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addrs, err := res.Lookup(ctx, host)
		cancel()
		if err != nil {
			lg.Debug("warmup %s: %v", host, err)
			continue
		}
		if len(addrs) > maxProbe {
			addrs = addrs[:maxProbe]
		}
		for i := 0; i < len(addrs); i += probeWave {
			end := i + probeWave
			if end > len(addrs) {
				end = len(addrs)
			}
			got := probeChunk(dl, host, addrs[i:end], probeTimeout, concurrency, lg)
			total += len(got)
			if len(got) > 0 {
				break
			}
		}
	}
	lg.Info("上游候选探测完成：%d 个可用地址（%d 个热门域名，每域名最多 %d 个候选）", total, len(hotDomains), maxProbe)
	return total
}

// probeChunk 并发探测一小批候选，返回其中可用的地址。
func probeChunk(dl *dialer.Dialer, host string, addrs []netip.Addr, timeout time.Duration, concurrency int, lg *log.Logger) []netip.Addr {
	sem := make(chan struct{}, concurrency)
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok []netip.Addr
	)
	for _, ip := range addrs {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
			defer cancel()
			if err := dl.ProbeTLS(ctx, host, ip, timeout); err != nil {
				lg.Debug("probe %s %s: %v", host, ip, err)
				return
			}
			mu.Lock()
			ok = append(ok, ip)
			mu.Unlock()
			lg.Debug("probe %s %s: ok", host, ip)
		}(ip)
	}
	wg.Wait()
	return ok
}

// probeHost 给单个域名补一轮探测（OnUpstreamError 的后台回调）。
// 与 warmUpUpstreams 相同的参数；独立成函数是为了方便单测和将来调整。
func probeHost(dl *dialer.Dialer, res *resolver.Resolver, host string, lg *log.Logger) {
	const (
		probeTimeout = 3 * time.Second
		maxProbe     = 24
		probeWave    = 8
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	addrs, err := res.Lookup(ctx, host)
	cancel()
	if err != nil {
		lg.Debug("on-demand lookup %s: %v", host, err)
		return
	}
	if len(addrs) > maxProbe {
		addrs = addrs[:maxProbe]
	}
	// 按需探测同样分波：一组里探到可用地址就够了，不必把全部候选都打一遍。
	// 每个可用地址还会顺手试同 /24 的邻居（见 probeNeighbors）。
	for i := 0; i < len(addrs); i += probeWave {
		end := i + probeWave
		if end > len(addrs) {
			end = len(addrs)
		}
		got := probeChunk(dl, host, addrs[i:end], probeTimeout, probeWave, lg)
		if len(got) > 0 {
			for _, ip := range got {
				probeNeighbors(dl, host, ip, lg)
			}
			break
		}
	}
	lg.Info("按需探测完成：%s（%d 个候选）", host, len(addrs))
}

// probeNeighbors 在某个地址被确认可用后，顺手试同一 /24 里相邻的几个地址，
// 把能用的登记成额外候选（dialer.AddCandidate）。
//
// 为什么值得多打几个 SYN：GitHub 的边缘地址是按号段被拦的，而种子表/DoH
// 只会给出几个固定号码。本机实测 2026-11-04 10:31 那一刻，种子里的
// 140.82.112-116.3/.4 全黑，而同一 /24 的 140.82.112.5/.113.5/.114.5/.116.5
// 全部可连——号段相邻、命运不同。只靠解析结果，这些活地址永远进不了候选池。
//
// 代价可控：只在"按需探测确认了某个地址"之后跑，一次性最多 6 个握手，全部
// 并行，每个 1.5s 封顶。
func probeNeighbors(dl *dialer.Dialer, host string, ip netip.Addr, lg *log.Logger) {
	if !ip.Is4() {
		return
	}
	b := ip.As4()
	var wg sync.WaitGroup
	for _, off := range []int{-2, -1, 1, 2, 3, 5} {
		n := int(b[3]) + off
		if n < 1 || n > 254 {
			continue
		}
		cand := netip.AddrFrom4([4]byte{b[0], b[1], b[2], byte(n)})
		wg.Add(1)
		go func(cand netip.Addr) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := dl.ProbeTLS(ctx, host, cand, 1500*time.Millisecond); err != nil {
				return
			}
			dl.AddCandidate(host, cand)
			lg.Debug("neighbor %s %s: ok（已登记为额外候选）", host, cand)
		}(cand)
	}
	wg.Wait()
}
