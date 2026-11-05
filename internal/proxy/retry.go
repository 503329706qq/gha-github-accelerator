package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/upstream"
)

// retryTransport 给幂等请求加"换一个上游 IP 再来一次"的能力。
//
// 2026-11-03 实测：GitHub 前端会按 IP 段漂移封锁，被封锁的地址表现为
// TCP 连得上、TLS 握得上，然后一个字节都不回。拨号层的评分只能事后修正
// （那一次请求已经白等了），所以这里把单次尝试压到几秒，超时或出错就
// 立刻换一次。上游走 HTTP/1.1（见 proxy.go 的 ForceAttemptHTTP2=false），
// 每个请求独享连接，重试才真正能"换连接换 IP"。
type retryTransport struct {
	base     http.RoundTripper
	attempts int
	onRetry  func(format string, args ...any)
	// onFail 在一次尝试失败时收到该次真正拨到的 IP（Recorder 里取），用于
	// 把这个 IP 记成失败；为 nil 时跳过。
	onFail func(ip netip.Addr, err error)
	// onOK 在一次尝试拿到响应头时收到该次真正拨到的 IP，用于把它记成
	// "这条路真的通"。拨号层只看得到握手，看不到数据，所以这个信号只能
	// 从 HTTP 层回灌；为 nil 时跳过。
	onOK func(ip netip.Addr)
	// onDegraded 在某个 host 被判定为"链路级故障"（短时间内连续多次尝试
	// 都拿不到响应）时调一次，用于把这件事写进日志。
	onDegraded func(host string, failures int)

	mu     sync.Mutex
	health map[string]*hostHealth
}

// 链路级故障（整段上游 IPv4 假死）的识别与快速失败。
//
// 2026-11-04 复现出两种波形，都会在十几分钟后自愈，期间换 IP 毫无用处：
//   - "TLS 握得上、一个字节不回"：拨号成功，Recorder 里有 IP，靠 3s 响应头
//     超时收场，4 次尝试就是 12s；
//   - "TCP SYN 被整段丢弃"：拨号竞速全灭，Recorder 里根本没有 IP。
//
// 所以判据不能依赖 IP：改为按「尝试失败次数」计数，且必须在飞行途中生效。
// 健康时段单个坏 IP 由重试内部消化（第 2 次就换到好地址并成功，noteOK 会
// 把累计清零），只有整段一起哑时才会在短时间内连续攒够失败尝试。一旦降级：
// 每条新请求只赌一次（2.5s 封顶），已经在飞的请求也不再跑完剩余重试，
// 502 快速返回让浏览器自己重试——比整屏请求挂满 12s 强得多。
// 解除要等"连续 3 次拿到响应头"，不能一次成功就解除。
const (
	attemptFailThreshold = 6 // 约等于 1.5 条请求的全部尝试，兼顾并发首波
	attemptFailWindow    = 10 * time.Second
	degradedWindow       = 20 * time.Second
	degradedAttempts     = 1
	degradedCap          = 2500 * time.Millisecond
	// degradedRecoveryStreak 是解除降级需要的连续成功次数。
	//
	// 原先"一次成功就解除"会造成抖动：2026-11-05 08:44–08:47 的故障波形里，
	// 降级窗口被 sporadic 的成功反复关掉又打开，11 个请求又跑满 4 次尝试、
	// 重新变成 12000ms 的 502。故障期间"偶尔漏过一个请求"是常态，得连续
	// 成功几次才说明链路真的回来了。
	degradedRecoveryStreak = 3
)

// hostHealth 记录一个上游 host 当前的失败累计与降级窗口。
type hostHealth struct {
	fails  int       // 本次统计窗口内累计的尝试失败次数
	first  time.Time // 本统计窗口的起点
	until  time.Time // 降级窗口截止（零值表示未降级）
	streak int       // 降级后连续成功的次数，攒够 degradedRecoveryStreak 才解除
}

// degraded 判断该 host 当前是否处于快速失败窗口。
func (t *retryTransport) degraded(host string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.health[host]
	if h == nil {
		return false
	}
	return time.Now().Before(h.until)
}

// noteAttemptFailure 记一次上游尝试失败（不管有没有拨到 IP：TCP 全黑时拨号
// 层来不及写 Recorder，同样是链路故障的观测点）。窗口内累计够阈值就进入
// 降级；返回是否刚刚进入（用于只打一次日志）。
func (t *retryTransport) noteAttemptFailure(host string) bool {
	if host == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.health == nil {
		t.health = make(map[string]*hostHealth)
	}
	h := t.health[host]
	now := time.Now()
	if h == nil {
		h = &hostHealth{first: now}
		t.health[host] = h
	}
	// 失败打断"连续成功"的计数。
	h.streak = 0
	if now.Before(h.until) {
		// 已经在降级窗口内：续期即可，不重复计数、不重复打日志。
		h.until = now.Add(degradedWindow)
		return false
	}
	if now.Sub(h.first) > attemptFailWindow {
		// 统计窗口过期，上一波攒的失败不能算进这一波。
		h.fails = 0
		h.first = now
	}
	h.fails++
	if h.fails < attemptFailThreshold {
		return false
	}
	h.until = now.Add(degradedWindow)
	h.fails = 0
	return true
}

// noteOK 一条请求真的拿到了响应头。连续够 degradedRecoveryStreak 次才算链路
// 真的恢复，清掉该 host 的失败累计与降级；零星成功不清，避免降级窗口抖动。
func (t *retryTransport) noteOK(host string) {
	if host == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.health[host]
	if h == nil {
		return
	}
	h.streak++
	if h.streak >= degradedRecoveryStreak {
		delete(t.health, host)
	}
}

// maxBudget 是所有尝试共享的总预算。到了就不再发起新尝试——
// 全部上游确实不可用时（例如 raw 的四个 Fastly IP 同时被拦），
// 快一点返回 502 比让浏览器转 20 秒更有用。
//
// 2026-11-04 从 8s 抬到 12s：3 次尝试 × 3s 响应头超时 = 9s，预算 8s 先到，
// 等于第三次尝试永远跑不完，日志里 502 的耗时整齐地钉在 8000ms。抬到 12s
// 后 4 次尝试（4×3s）恰好装得下；而且每次尝试现在都会换一个 IP（Penalize
// 会把刚失败的地址摘出粘性并进回避窗口），所以第 4 次是"第 4 个地址"，
// 不是"同一个哑地址的第 4 次"。
const maxBudget = 12 * time.Second

// minRetryWindow：剩余预算低于这个值就不再重试——一次尝试要花
// ResponseHeaderTimeout（3s）+ 一次 TLS 握手，明知等不完还发起，只会把
// 502 拖得更晚。实测（2026-11-03）预算检查只留 2s 时，第三次尝试照样
// 在 6.2s 起跑、9.2s 才收场，整个请求 10.9s——把窗口抬高到覆盖一次完整尝试。
const minRetryWindow = 4 * time.Second

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 只重试幂等请求：POST 可能已经在服务端生效，重发有副作用（比如建 issue）。
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return t.base.RoundTrip(req)
	}
	attempts := t.attempts
	if attempts < 1 {
		attempts = 1
	}
	host := req.URL.Hostname()
	// 链路级故障窗口内只赌一次：换 IP 没用，等外部封锁过去比拖满预算强。
	if t.degraded(host) {
		attempts = degradedAttempts
	}
	deadline := time.Now().Add(maxBudget)
	var lastErr error
	for i := 1; i <= attempts; i++ {
		// i > 1 时强制新连接：上一次失败的很可能是条被黑洞的空闲连接
		// （h1 连接池会复用它），不清掉的话重试会撞上同一条死连接。
		if i > 1 {
			if fc, ok := t.base.(interface{ CloseIdleConnections() }); ok {
				fc.CloseIdleConnections()
			}
		}
		// Recorder 记录"这一趟真正拨到的 IP"：失败时交给 onFail 精确惩罚，
		// 下一次竞速把它排进"已验证失败"档。
		rec := upstream.NewRecorder()
		ctx, cancel := context.WithCancel(upstream.With(req.Context(), rec))
		// 单次尝试的硬上限 = 剩余预算。dial 竞速（5s/候选）和 TLS 握手
		//（TLSHandshakeTimeout）不受 ResponseHeaderTimeout 约束，没有这层
		// 封顶时，最后一次尝试能把整个请求拖到 10.9s（2026-11-03 实测）。
		// 响应头一到就撤销计时器——响应体的流式传输不受预算限制，
		// 大文件下载不会被掐断。降级窗口内进一步压到 degradedCap，
		// 让故障期间的请求秒级返回而不是挂满 3s。
		remaining := time.Until(deadline)
		if remaining <= 0 {
			cancel()
			break
		}
		isDegraded := t.degraded(host)
		cap := remaining
		if isDegraded && degradedCap < cap {
			cap = degradedCap
		}
		timer := time.AfterFunc(cap, cancel)
		resp, err := t.base.RoundTrip(req.Clone(ctx))
		if err == nil {
			// 软拦截空壳不算成功。GitHub 对"看着像滥用"的客户端会回 200 +
			// text/plain 的极短正文（2026-11-05 实测正文就是 4 字节 "OK"，
			// 带 X-GitHub-Edge-Region）。它不是错误码，只看状态码会把它
			// 当成"这条路能干活"，进而立成粘性——用户看到的现象是页面
			// 一片空白、也不报错。
			if n, soft := sniffSoftBlock(req, resp); soft {
				timer.Stop()
				resp.Body.Close()
				cancel()
				err = fmt.Errorf("上游返回软拦截空壳（%d 字节 text/plain），不算可用地址", n)
			}
		}
		if err == nil {
			// 头已到，撤销单次尝试的封顶；cancel 挂到 bodyWithCancel，
			// 等响应体读完（或客户端断开）才触发。
			timer.Stop()
			t.noteOK(host)
			// 响应头到手 = 这条路是真的能干活（不只是能握手），把 IP 交给
			// onOK 记成粘性：下一批并发请求直接走它，不再重新竞速去撞那些
			// "TLS 通、不吐数据"的地址。
			//
			// 但风控拦截页不算数：GitHub 对我们的探测/压测回过 400
			// "Whoa there!"、403 "Access to this site has been restricted"。
			// 这些响应只能证明"这条链路连得上"，证明不了这个地址对浏览有用，
			// 把它立成粘性只会让后续请求继续撞同一堵墙。
			if t.onOK != nil && !blockedStatus(resp.StatusCode) {
				if ip, ok := rec.Get(); ok {
					t.onOK(ip)
				}
			}
			resp.Body = &bodyWithCancel{ReadCloser: resp.Body, cancel: cancel}
			return resp, nil
		}
		timer.Stop()
		cancel()
		lastErr = err
		if req.Context().Err() != nil {
			// 客户端自己放弃（关标签页、Ctrl-C），重试没有意义。
			return nil, err
		}
		// 每次失败都计入链路健康，不依赖 Recorder 里有没有 IP：TCP 层整段
		// 丢 SYN 时拨号竞速全灭，rec.Get() 为空，但那正是最典型的链路故障。
		degradedNow := t.noteAttemptFailure(host)
		if degradedNow && t.onDegraded != nil {
			t.onDegraded(host, attemptFailThreshold)
		}
		if ip, ok := rec.Get(); ok && t.onFail != nil {
			t.onFail(ip, err)
		}
		// 降级一旦确立，连这条正在飞的请求也不必跑完剩余重试：整段上游都
		// 哑着，再换几个地址也只是把 12s 拖满。立刻返回 502，把等待时间
		// 还给浏览器（外部封锁过去后下一条请求会自己恢复）。
		// 这里要重新查一次 degraded，而不只看本次尝试开始时缓存的 isDegraded：
		// 首波并发请求里，往往是最先失败的那几条把计数推过阈值、替所有请求
		// 确立了降级；其余请求当时已经带着 attempts=4 在飞，若不重新判断，
		// 它们会各自再拖 3~4 次尝试（实测故障首波仍有整整齐齐的 12s 502）。
		if isDegraded || degradedNow || t.degraded(host) {
			break
		}
		// 剩余预算不足以再等一次完整响应头时，停止重试。
		if i < attempts && time.Now().Before(deadline.Add(-minRetryWindow)) {
			if t.onRetry != nil {
				t.onRetry("upstream retry %d/%d host=%s: %v", i, attempts, req.Host, err)
			}
			select {
			case <-time.After(100 * time.Millisecond):
			case <-req.Context().Done():
				return nil, lastErr
			}
		}
	}
	return nil, lastErr
}

type bodyWithCancel struct {
	io.ReadCloser
	cancel context.CancelFunc
}

// blockedStatus 判断状态码是不是上游的风控/限流拒绝页，而不是正常业务响应。
//
// 400/403/429 都可能来自 GitHub 边缘层对"这个客户端/IP 不顺眼"的拒绝：
// 400 是 "Whoa there! You have sent an invalid request"，
// 403 是 "Access to this site has been restricted"。它们同样有响应头，
// 所以不能拿"收到响应头"当成"这个上游地址好用"。
func blockedStatus(code int) bool {
	switch code {
	case http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests:
		return true
	}
	return false
}

// softBlockMaxBody 是"软拦截空壳"允许的最大正文长度。真页面的正文都以
// 十 KB 计，而 GitHub 的空壳只有几个字节，留 64 字节的余量足够。
const softBlockMaxBody = 64

// wantsHTML 判断这条请求是不是浏览器在导航（要一个页面）。
//
// 只对这类请求做软拦截嗅探：只有它们"拿到 200 却几乎没有正文"才是异常。
// fetch/XHR 的 Accept 是 */*，raw 上的小 .txt 也可能是 text/plain 的短正文，
// 那些不该被误判。
func wantsHTML(req *http.Request) bool {
	return strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/html")
}

// sniffSoftBlock 判断响应是不是 GitHub 的软拦截空壳：200 + text/plain +
// 正文短到不可能是页面（实测 4 字节 "OK"）。
//
// 返回正文长度与判定结果；如果不是空壳，会把已经读出来的字节接回 resp.Body，
// 调用方拿到的响应内容与未嗅探时完全一致。
func sniffSoftBlock(req *http.Request, resp *http.Response) (int, bool) {
	if resp.StatusCode != http.StatusOK || !wantsHTML(req) {
		return 0, false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, "text/plain") {
		return 0, false
	}
	buf := make([]byte, softBlockMaxBody+1)
	n, err := io.ReadFull(resp.Body, buf)
	if n <= softBlockMaxBody {
		if err == nil {
			// 理论上不会发生（读满 len(buf) 才算 nil），保守起见按"不是空壳"处理。
			resp.Body = io.NopCloser(bytes.NewReader(buf[:n]))
			return n, false
		}
		body := strings.TrimSpace(strings.ToLower(string(buf[:n])))
		// 只认 GitHub 实际用的两种空壳形态：空正文，或字面的 "ok"。
		if body == "" || body == "ok" {
			return n, true
		}
		resp.Body = io.NopCloser(bytes.NewReader(buf[:n]))
		return n, false
	}
	// 正文比阈值长，说明不是空壳：把读到的字节接回去。
	resp.Body = &restoredBody{
		Reader: io.MultiReader(bytes.NewReader(buf[:n]), resp.Body),
		Closer: resp.Body,
	}
	return n, false
}

// restoredBody 把嗅探时读出来的前导字节接回原始 body，Close 仍然关底层连接。
type restoredBody struct {
	io.Reader
	io.Closer
}

func (b *bodyWithCancel) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
