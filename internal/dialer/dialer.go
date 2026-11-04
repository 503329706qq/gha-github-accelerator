// Package dialer 负责在多个候选 IP 之间竞速，并记录每个 IP 的质量。
//
// GitHub 的可达 IP 经常是「能连上」和「连上后只有几十 KB/s」混杂，所以打分
// 不只看到握手延迟，也看到已观测吞吐（0.6 延迟 + 0.4 吞吐）。候选按分数排序，
// 逐个错开 150ms 起跑，谁先握手成功就用谁，其余立刻取消。
package dialer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/upstream"
)

// Resolver 是解析器的最小接口（由 resolver.Resolver 满足）。
type Resolver interface {
	Lookup(ctx context.Context, host string) ([]netip.Addr, error)
}

// Options 配置拨号器。
type Options struct {
	Resolver      Resolver
	Timeout       time.Duration // 单次 TCP 尝试的超时，默认 5s（纯 TCP 竞速用）
	Stagger       time.Duration // 候选间错开的时间，默认 150ms
	MaxCandidates int           // 每批并发竞速的候选数，默认 12（GitHub 的可用 IP 会整段漂移，多试才稳）
	Base          *net.Dialer   // 底层 dialer（测试可注入）
	// TLSTimeout 是"TCP + TLS 握手"整条路的单次超时，默认 2.5s。
	// 比 Timeout 紧是故意的：本机好地址走完握手只要 300-600ms，2.5s 还握手
	// 不完的地址基本就是黑洞；而它必须短到"一批全死 + 再来一批"仍装得进
	// retry 层的 8s 预算。
	TLSTimeout time.Duration
	// TLSConfig 只被 DialTLSContext 自建握手用；生产留空即用系统根证书。
	TLSConfig *tls.Config
}

type stat struct {
	lat   time.Duration // EWMA 握手延迟
	thr   float64       // EWMA 吞吐（字节/秒）
	dials int
	fails int
	// probed/ok 记录"最近一次探测的真实结果"：探测会发一个真的 HTTP HEAD，
	// 能读到响应首字节才算 ok。没有这两个字段的话，一个实际可达但 RTT 800ms
	// 的地址（分数约 0.1）会输给一个从没探测过的黑洞地址（分数 0.61）。
	probed bool
	ok     bool
	at     time.Time // 最后一次观测时间，用来让"一次抖动"的惩罚随时间淡化
}

// statDecay：超过这个时间没有再观测到问题，就把延迟惩罚往中性值拉回去。
// 没有它的话，一次瞬时失败会把某个 IP 永久压在候选队尾。
const statDecay = 5 * time.Minute

// Dialer 实现 net.Dialer 的 DialContext 形状，可直接塞进 http.Transport。
type Dialer struct {
	o     Options
	mu    sync.Mutex
	stats map[netip.Addr]*stat
	// good 记住每个域名"上一次真正拨通"的 IP。并发来了几十个请求时，每个
	// 请求都去竞速 12 个候选 = 几百个 SYN 同时打出去，本机会被自己的竞速
	// 淹掉：连本该 0.1s 建连的好地址也会因为握手队列太长而超时，然后所有
	// 请求一起在 8s 预算上撞 502（线上实测 20 并发 70% 失败，而同一条链路
	// 用 curl 直连 20 并发 20/20 全过）。先试最近确证过的那一个，只在它
	// 失败时才退回竞速，就把"每请求一次竞速"变成了"每域名偶尔一次竞速"。
	good map[string]goodIP
	// avoid 是"刚刚确认不吐数据"的地址黑名单：上游在响应头阶段超时（TCP 通、
	// TLS 也通，就是没有字节回来）时由 Penalize 写入。粘性快路必须先绕开它们，
	// 否则重试的每一次都会重新拨同一个哑地址——实测 502 全是 8000ms 就是这么来的：
	// 3 次尝试 × 3s 响应头超时 = 9s，预算 8s 先到。
	avoid map[netip.Addr]time.Time
	// extra 是种子表/DoH 之外、实测发现能通的地址。本机实测同一 /24 内经常是
	// "一个号段全黑、隔壁几号还通"（种子只有 140.82.112-116.3/.4 时它们全黑，
	// 而 140.82.112.5 仍通），只靠解析结果永远覆盖不到这些地址。
	extra map[string]map[netip.Addr]time.Time
	// hosts 记录"这个 IP 是给哪个域名拨出去的"，让 Praise 能在只拿到 IP 的
	// 情况下（响应成功时只有 IP，没有 host）把粘性记录写回正确的键。
	hosts map[netip.Addr]string
}

// avoidTTL 是失败地址的回避窗口。太短等于没记（下一次重试又拨回去），太长
// 会把一段正在恢复的地址也挡在外面；一分钟覆盖"重试 + 页面连续几个请求"足够。
const avoidTTL = 60 * time.Second

// extraTTL 是实测发现地址的有效期。GitHub 边缘地址会整段漂移，十分钟后
// 重新以探测结果为准。
const extraTTL = 10 * time.Minute

// goodIPTTL 是粘性 IP 的有效期。GitHub 的边缘地址会在几分钟内漂移，留太长
// 会把流量钉在一个已经死掉的地址上（每个请求先白等一次握手超时）。
const goodIPTTL = 30 * time.Second

// stickyTimeout 是"先试最近可用 IP"这条快路的超时。比 TLSTimeout 更紧：
// 它的职责是"确认老路还通"，不通用就赶紧去竞速，别把预算耗在这一条上。
const stickyTimeout = 1200 * time.Millisecond

type goodIP struct {
	ip netip.Addr
	at time.Time
}

// New 构造拨号器并补默认值。
func New(o Options) *Dialer {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Stagger <= 0 {
		o.Stagger = 100 * time.Millisecond
	}
	if o.MaxCandidates <= 0 {
		o.MaxCandidates = 12
	}
	if o.TLSTimeout <= 0 {
		o.TLSTimeout = 2500 * time.Millisecond
	}
	if o.Base == nil {
		o.Base = &net.Dialer{Timeout: o.Timeout, KeepAlive: 30 * time.Second}
	}
	return &Dialer{
		o:     o,
		stats: make(map[netip.Addr]*stat),
		good:  make(map[string]goodIP),
		avoid: make(map[netip.Addr]time.Time),
		extra: make(map[string]map[netip.Addr]time.Time),
		hosts: make(map[netip.Addr]string),
	}
}

// bindHost 记住"这个 IP 是为哪个域名拨的"，供 Praise 归位粘性记录。
func (d *Dialer) bindHost(host string, ip netip.Addr) {
	if host == "" || !ip.IsValid() {
		return
	}
	d.mu.Lock()
	d.hosts[ip] = host
	d.mu.Unlock()
}

// AddCandidate 登记一个"实测能用、但解析结果里没有"的地址（目前用于同 /24
// 邻居发现）。它和解析结果一起参与竞速，过期后自动失效。
func (d *Dialer) AddCandidate(host string, ip netip.Addr) {
	if host == "" || !ip.IsValid() {
		return
	}
	d.mu.Lock()
	m := d.extra[host]
	if m == nil {
		m = make(map[netip.Addr]time.Time)
		d.extra[host] = m
	}
	m[ip] = time.Now()
	d.mu.Unlock()
}

// extraFor 取出该域名仍新鲜的额外候选。调用方持锁与否都行（内部加锁）。
func (d *Dialer) extraFor(host string) []netip.Addr {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.extra[host]
	if len(m) == 0 {
		return nil
	}
	now := time.Now()
	out := make([]netip.Addr, 0, len(m))
	for ip, at := range m {
		if now.Sub(at) > extraTTL {
			delete(m, ip)
			continue
		}
		out = append(out, ip)
	}
	return out
}

// avoided 判断某个地址是否还在回避窗口内。
func (d *Dialer) avoided(ip netip.Addr) bool {
	d.mu.Lock()
	at, ok := d.avoid[ip]
	d.mu.Unlock()
	return ok && time.Since(at) < avoidTTL
}

// markGood 记住某个域名刚被确证可用的 IP。
func (d *Dialer) markGood(host string, ip netip.Addr) {
	if host == "" {
		return
	}
	d.mu.Lock()
	d.good[host] = goodIP{ip: ip, at: time.Now()}
	d.mu.Unlock()
}

// goodFor 取该域名最近确证可用的 IP；过期、没记录、或者刚被惩罚过就返回 false。
func (d *Dialer) goodFor(host string) (netip.Addr, bool) {
	d.mu.Lock()
	g, ok := d.good[host]
	if ok {
		if at, bad := d.avoid[g.ip]; bad && time.Since(at) < avoidTTL {
			ok = false
		}
	}
	d.mu.Unlock()
	if !ok || time.Since(g.at) > goodIPTTL {
		return netip.Addr{}, false
	}
	return g.ip, true
}

// Score 把（延迟，吞吐）折算成一个越大越好的分数。
// 未记录的候选按中性延迟计分，保证它们仍然会被尝试。
func Score(lat time.Duration, thr float64) float64 {
	if lat <= 0 {
		lat = 300 * time.Millisecond
	}
	if thr < 0 {
		thr = 0
	}
	latScore := 1.0 / (1.0 + float64(lat)/float64(100*time.Millisecond))
	thrScore := math.Min(thr/float64(5<<20), 1.0)
	return 0.6*latScore + 0.4*thrScore + 0.01
}

// rankFor 把候选分成三档，供排序使用：0=最近探测确实能拿到数据，
// 1=没探测过（未知），2=最近探测失败（或拨号失败）。
func (d *Dialer) rankFor(ip netip.Addr) int {
	d.mu.Lock()
	s := d.stats[ip]
	d.mu.Unlock()
	if s == nil || !s.probed {
		return 1
	}
	if s.ok {
		return 0
	}
	if time.Since(s.at) > statDecay {
		// 失败记录放久了就不再当回事，让它重新排进未知档
		return 1
	}
	return 2
}

// ScoreFor 返回某个 IP 当前的分数。
func (d *Dialer) ScoreFor(ip netip.Addr) float64 {
	// 必须在锁内把值拷出来：recordDial / RecordThroughput 会在别的 goroutine 里
	// 改同一份 stat，锁外读字段是数据竞争（-race 能报出来）。
	d.mu.Lock()
	s := d.stats[ip]
	var lat time.Duration
	var thr float64
	var stale time.Duration
	if s != nil {
		lat, thr = s.lat, s.thr
		stale = time.Since(s.at)
		if s.dials == 0 {
			lat = 0
		}
	}
	d.mu.Unlock()
	const neutral = 300 * time.Millisecond
	if lat > neutral && stale > statDecay {
		// 指数衰减回中性延迟：stale 越大，惩罚越接近 0。
		f := math.Exp(-float64(stale-statDecay) / float64(statDecay))
		lat = time.Duration(float64(neutral) + float64(lat-neutral)*f)
	}
	return Score(lat, thr)
}

// Stats 返回已记录过状态的 IP 数量（测试/状态接口用）。
func (d *Dialer) Stats() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.stats)
}

// RecordThroughput 把一次完成请求的吞吐并入该 IP 的 EWMA（α=0.3）。
func (d *Dialer) RecordThroughput(ip netip.Addr, bytes int64, dur time.Duration) {
	if bytes <= 0 || dur <= 0 {
		return
	}
	rate := float64(bytes) / dur.Seconds()
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.stats[ip]
	if s == nil {
		s = &stat{}
		d.stats[ip] = s
	}
	s.at = time.Now()
	if s.thr == 0 {
		s.thr = rate
	} else {
		s.thr = 0.7*s.thr + 0.3*rate
	}
}

// recordDial 记录一次 TCP 拨号结果：只更新延迟 EWMA 与失败计数，不碰
// probed/ok。为什么：黑洞地址的 TCP 握手照样成功（还更快——本机实测 0.25s，
// 真正能用的地址反而要 3s）。若把"TCP 拨号成功"当成"应用层可用"，探测
// （recordProbe）识别出的失败结论会被下一次竞速覆盖，黑洞 IP 又凭假快的
// 握手抢回第一位，请求再次白等 3s 才 502。
func (d *Dialer) recordDial(ip netip.Addr, lat time.Duration, ok bool) {
	d.recordLocked(ip, lat, ok, false)
}

// recordProbe 记录一次应用层探测结论：ProbeTLS 的 HEAD 读首字节结果，或一次
// 请求以"响应头超时 / 零字节搬运"收场。这是"这个 IP 到底能不能拿到数据"的
// 权威信号，是唯一会写 probed/ok 的地方；rankFor 据此分档。
func (d *Dialer) recordProbe(ip netip.Addr, lat time.Duration, ok bool) {
	d.recordLocked(ip, lat, ok, true)
}

func (d *Dialer) recordLocked(ip netip.Addr, lat time.Duration, ok, probe bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.stats[ip]
	if s == nil {
		s = &stat{lat: lat}
		d.stats[ip] = s
	}
	s.dials++
	s.at = time.Now()
	if probe {
		s.probed = true
		s.ok = ok
	}
	if !ok {
		s.fails++
		// 失败是强负信号：把延迟 EWMA 往"很慢"推
		s.lat = time.Duration(0.7*float64(s.lat) + 0.3*float64(3*time.Second))
		if s.lat <= 0 {
			s.lat = 3 * time.Second
		}
		return
	}
	if s.fails > 0 {
		s.fails-- // 成功一次就冲掉一次历史失败
	}
	if s.lat == 0 {
		s.lat = lat
	} else {
		s.lat = time.Duration(0.7*float64(s.lat) + 0.3*float64(lat))
	}
}

// Praise 记录"这条路上真的传出过数据"。给重试层用：一次尝试拿到了响应头，
// 就说明这个 IP 不只是能握手，而是真能干活。
//
// 为什么必须靠"响应成功"而不是"拨号成功"来定粘性：本机实测存在大量
// "TCP 通、TLS 通、一个字节不吐"的地址（探测日志里是
// `握手成功但读不到响应: i/o timeout`）。拨号层看得见握手，看不见数据，
// 所以按拨号成功选出来的粘性地址可能恰恰是最哑的那个——实测新实例并发
// 60 请求撞出 45 个 502，就是因为粘性落在了一个只完成握手的地址上。
func (d *Dialer) Praise(ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	d.mu.Lock()
	delete(d.avoid, ip)
	if host := d.hosts[ip]; host != "" {
		d.good[host] = goodIP{ip: ip, at: time.Now()}
	}
	d.mu.Unlock()
	d.recordProbe(ip, 0, true)
}

// Penalize 把某个 IP 记成"拨通了但没拿到数据"。给重试层用：一次尝试以
// 响应头超时收场时，惩罚这次真正拨到的 IP（Recorder 里取），让下一次竞速
// 把它排进"已验证失败"档（rank 2），statDecay（5 分钟）后退回未知档。
//
// 除了降档，这里还必须做两件事，否则重试只是把同一个哑地址再拨三次：
//  1. 摘掉指向它的粘性记录——粘性快路不走 candidates()，档位对它无效；
//  2. 进回避名单一段短窗口——竞速的"失败档兜底"仍可能在下一轮把它捞回来。
func (d *Dialer) Penalize(ip netip.Addr) {
	d.recordProbe(ip, 0, false)
	d.mu.Lock()
	for host, g := range d.good {
		if g.ip == ip {
			delete(d.good, host)
		}
	}
	d.avoid[ip] = time.Now()
	d.mu.Unlock()
}

type result struct {
	conn net.Conn
	ip   netip.Addr
	err  error
}

// ProbeTLS 探测一个候选 IP 能不能真的走完 TLS 握手，并把结果记进评分。
//
// 只测 TCP 不够：本机实测存在"三次握手成功、之后一个字节都不回"的黑洞地址
// （2026-11-03 的 20.205.243.166 / 140.82.112.4 就是这样），这种地址会让一次
// 请求白等到超时才 502。TLS 能握手，才说明这条路上真的有流量。
func (d *Dialer) ProbeTLS(ctx context.Context, host string, ip netip.Addr, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	base := d.o.Base
	if base == nil {
		base = &net.Dialer{Timeout: timeout}
	}
	start := time.Now()
	conn, err := base.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), "443"))
	if err != nil {
		d.recordProbe(ip, 0, false)
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		d.recordProbe(ip, 0, false)
		return err
	}
	// 握手成功还不够：本机实测存在"TLS 握手完成、之后一个字节都不回"的地址
	// （2026-11-03 的 20.205.243.166 就是这样），只测握手会把它们标成好地址。
	// 所以再发一个最小的 HTTP 请求，读到响应首字节才算真的通。
	if _, err := io.WriteString(tc, "HEAD / HTTP/1.1\r\nHost: "+host+"\r\nUser-Agent: gha-probe\r\nConnection: close\r\n\r\n"); err != nil {
		d.recordProbe(ip, 0, false)
		return err
	}
	_ = tc.SetReadDeadline(time.Now().Add(timeout))
	var b [1]byte
	if _, err := io.ReadFull(tc, b[:]); err != nil {
		d.recordProbe(ip, 0, false)
		return fmt.Errorf("probe %s: 握手成功但读不到响应: %w", ip, err)
	}
	d.recordProbe(ip, time.Since(start), true)
	return nil
}

// DialContext 是纯 TCP 竞速，给"不终结 TLS 的原样透传"用。
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr, false)
}

// DialTLSContext 把竞速的终点从"TCP 握手完成"推到"TLS 握手完成"。
//
// 为什么必须到 TLS：本机实测存在一类地址——TCP 三次握手 0.2s 就成功，之后
// 一个字节都不回。只按 TCP 竞速时它们永远跑第一，赢了竞速之后请求就卡在
// TLS 握手/等响应头上，把 retry 层的 8s 总预算整个吃光，最后 502
// （日志里正是 "context canceled" + 8000ms）。把 TLS 放进竞速之后，这类
// 地址 2.5s 内自己出局，好地址（实测 300ms 走完握手）直接赢。
func (d *Dialer) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr, true)
}

// dial 解析候选、分档排序，然后分批竞速：一批 MaxCandidates 个，全失败就
// 接着赌下一批——否则好地址排在第 13 位之后（种子表有 24 个，当前只有 5 个
// 活着）就永远轮不到。
func (d *Dialer) dial(ctx context.Context, network, addr string, withTLS bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// 快路：这个域名上一次确证可用的 IP 还新鲜，就先单独试它一次。
	// 命中时一个请求只花一次握手的钱，不会为了一个已经在用的地址再拉起十几
	// 个 SYN；没命中（老路死了）才落到下面的竞速。
	if _, perr := netip.ParseAddr(host); perr != nil {
		if ip, ok := d.goodFor(host); ok {
			conn, serr := d.single(ctx, network, host, port, ip, withTLS, stickyTimeout)
			if serr == nil {
				if rec := upstream.From(ctx); rec != nil {
					rec.Set(ip)
				}
				d.bindHost(host, ip)
				return &countingConn{Conn: conn, d: d, ip: ip, start: time.Now()}, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// 老路这次没拨通：立刻摘掉粘性记录并进回避窗口，别让紧跟着的
			// 兄弟请求（浏览器一页几十个并发）继续往这条死路上撞。
			d.Penalize(ip)
		}
	}

	usable, failed, err := d.candidates(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(usable)+len(failed) == 0 {
		return nil, fmt.Errorf("dialer: no addresses for %q", host)
	}

	batch := d.o.MaxCandidates
	if batch <= 0 {
		batch = 12
	}
	var errs []error
	// 先把"可用/未知"的分批跑完；一组都没成，再回头赌"已验证失败"的那批。
	// 这一步不能省：档位是竞速自己写出来的，一旦唯一的"可用"候选其实在
	// 抖动（能握手、拿不到响应头），只跑它就会一直 502；而真正健康的地址
	// 因为一次超时被打成 rank 2，就再也轮不到上场。
	for _, group := range [][]netip.Addr{usable, failed} {
		for i := 0; i < len(group); i += batch {
			end := i + batch
			if end > len(group) {
				end = len(group)
			}
			conn, err := d.raceBatch(ctx, network, host, port, group[i:end], withTLS)
			if err == nil {
				return conn, nil
			}
			errs = append(errs, err)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
	}
	return nil, fmt.Errorf("dialer: all candidates failed for %s: %w", addr, errors.Join(errs...))
}

// candidates 解析出候选地址，按"探测结论分档（已验证可用 > 未知 > 已验证
// 失败）"排序，档内再比分数。
//
// 两个切片分开返回是有意的：只按分数排会把黑洞地址排在最前面（它们的分数
// 是初始中性值，反而比一个实测 800ms 的好地址更高），所以"已验证失败"的那
// 批不进第一轮竞速——黑洞的 TCP 握手反而更快，让它们一起跑只会抢走好地址的
// 机会。但它们也不能被永久放逐：档位是竞速自己写的，一次超时就会把一个其实
// 健康的地址打成 rank 2，所以调用方跑完 usable 后必须回头再赌一批 failed。
func (d *Dialer) candidates(ctx context.Context, host string) (usable, failed []netip.Addr, err error) {
	if ip, perr := netip.ParseAddr(host); perr == nil {
		return []netip.Addr{ip}, nil, nil
	}
	if d.o.Resolver == nil {
		return nil, nil, fmt.Errorf("dialer: no resolver for %q", host)
	}
	addrs, err := d.o.Resolver.Lookup(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	// 解析结果 + 实测发现的额外地址（同 /24 邻居等）一起去重。
	addrs = d.unionExtra(host, addrs)
	sort.SliceStable(addrs, func(i, j int) bool {
		ri, rj := d.rankFor(addrs[i]), d.rankFor(addrs[j])
		if ri != rj {
			return ri < rj
		}
		return d.ScoreFor(addrs[i]) > d.ScoreFor(addrs[j])
	})
	// 刚失败过的地址（回避窗口内）一律压进 failed 组：正常路径不该再去拨它，
	// 但"usable 全跑完仍失败"时它还能作为最后的赌注——手里只有它一个候选时
	// 直接放弃，比赌一次更糟。
	for _, a := range addrs {
		if d.rankFor(a) <= 1 && !d.avoided(a) {
			usable = append(usable, a)
		} else {
			failed = append(failed, a)
		}
	}
	return usable, failed, nil
}

// unionExtra 把"实测发现的额外地址"并进解析结果，去重后保持解析结果在前。
func (d *Dialer) unionExtra(host string, addrs []netip.Addr) []netip.Addr {
	ext := d.extraFor(host)
	if len(ext) == 0 {
		return addrs
	}
	seen := make(map[netip.Addr]bool, len(addrs))
	for _, a := range addrs {
		seen[a] = true
	}
	out := addrs
	for _, a := range ext {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// raceBatch 让这一批候选错峰起跑，谁先完成（TCP，或 TCP+TLS）就用谁，其余
// 立刻取消。
func (d *Dialer) raceBatch(ctx context.Context, network, host, port string, addrs []netip.Addr, withTLS bool) (net.Conn, error) {
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ch := make(chan result, len(addrs))
	for i, ip := range addrs {
		go d.attempt(raceCtx, ch, network, host, port, ip, i, withTLS)
	}

	var errs []error
	// 不能假设"每个候选都会回一条结果"：输在错峰等待里的 goroutine 直接返回，
	// 根本不会发送。所以这里要同时盯着 ctx，别把调用方的取消变成死等。
	for received := 0; received < len(addrs); {
		select {
		case r := <-ch:
			received++
			if r.err == nil {
				cancel() // 赢家已连上，其余尝试立即放弃
				// 落选者可能已经抢在 cancel 之前把连接塞进了缓冲 channel，收尸。
				go reap(ch, len(addrs))
				// 把"这次请求实际拨到的 IP"记进请求 ctx（h1 下 transport 会把
				// 请求 ctx 原样传给 DialContext），重试层失败时据此精确惩罚
				// 这个 IP，而不是盲目惩罚整个域名。见 internal/upstream。
				if rec := upstream.From(ctx); rec != nil {
					rec.Set(r.ip)
				}
				// 记成该域名的粘性地址：后续并发请求先走这一条，不再各自拉起
				// 一整轮竞速——那正是负载越高越连不上的根因。
				// 注意这只是"拨通"级粘性，会被响应成功的 Praise 覆盖；真正
				// 该粘的是那条真的传出过数据的路。
				d.bindHost(host, r.ip)
				d.markGood(host, r.ip)
				return &countingConn{Conn: r.conn, d: d, ip: r.ip, start: time.Now()}, nil
			}
			errs = append(errs, fmt.Errorf("%s: %w", r.ip, r.err))
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("dialer: batch of %d candidates failed: %w", len(addrs), errors.Join(errs...))
}

// attempt 是单个候选的一次尝试。withTLS 时一路做到 TLS 握手完成——这是
// "这条路上真的有流量"的最短证明，也是把黑洞挡在竞速之外的关键。
func (d *Dialer) attempt(raceCtx context.Context, ch chan<- result, network, host, port string, ip netip.Addr, idx int, withTLS bool) {
	if idx > 0 {
		select {
		case <-time.After(time.Duration(idx) * d.o.Stagger):
		case <-raceCtx.Done():
			return
		}
	}
	timeout := d.o.Timeout
	if withTLS {
		timeout = d.o.TLSTimeout
	}
	conn, err := d.single(raceCtx, network, host, port, ip, withTLS, timeout)
	if err != nil {
		d.sendResult(raceCtx, ch, result{ip: ip, err: err})
		return
	}
	d.sendResult(raceCtx, ch, result{conn: conn, ip: ip})
}

// single 对单个候选做一次完整尝试（withTLS 时一路做到握手续完），并把结果
// 写进评分。竞速和"先试最近可用 IP"的快路共用这一段逻辑。
func (d *Dialer) single(ctx context.Context, network, host, port string, ip netip.Addr, withTLS bool, timeout time.Duration) (net.Conn, error) {
	start := time.Now()
	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := d.o.Base.DialContext(attemptCtx, network, net.JoinHostPort(ip.String(), port))
	if err != nil {
		// 连不上就是连不上，直接写进"已验证失败"档，下一批竞速不再往它身上
		// 浪费 2.5s。statDecay（5 分钟）到点会自动退回未知档；全部候选都失败
		// 时竞速也会兜底再赌一次，所以不会把一个"只是抖了一下"的地址永久拉黑。
		if ctx.Err() == nil {
			d.recordProbe(ip, 0, false)
		}
		return nil, err
	}
	if withTLS {
		tc := tls.Client(conn, d.tlsConfig(host))
		if herr := tc.HandshakeContext(attemptCtx); herr != nil {
			_ = conn.Close()
			// TCP 通了、TLS 一个字节都不回：黑洞地址的典型签名。必须记成
			// 应用层失败，否则它凭漂亮的握手延迟一直排在最前面。
			if ctx.Err() == nil {
				d.recordProbe(ip, 0, false)
			}
			return nil, herr
		}
		conn = tc
	}

	if withTLS {
		// TCP+TLS 都过了才算"这条路真的有流量"，是比 ProbeTLS 的 HEAD 探测
		// 更直接的一手证据，所以直接写探测档。
		d.recordProbe(ip, time.Since(start), true)
	} else {
		// 纯 TCP 成功不能当"可用"：黑洞地址的 TCP 握手照样成功（还更快）。
		// 只更新延迟，不碰探测档——见 recordDial 的说明。
		d.recordDial(ip, time.Since(start), true)
	}
	return conn, nil
}

// sendResult 把结果交回竞速。输掉竞速时不能把已经建好的 socket 丢在
// channel 里不管：没人会再读它，GC 也不会关它，句柄会一路涨上去。
func (d *Dialer) sendResult(raceCtx context.Context, ch chan<- result, r result) {
	select {
	case ch <- r:
	case <-raceCtx.Done():
		if r.conn != nil {
			_ = r.conn.Close()
		}
	}
}

// tlsConfig 造一次握手用的配置：SNI 用主机名，ALPN 只留 http/1.1
// （上游强制 h1，见 proxy.go 的 ForceAttemptHTTP2=false）。
func (d *Dialer) tlsConfig(host string) *tls.Config {
	var cfg *tls.Config
	if d.o.TLSConfig != nil {
		cfg = d.o.TLSConfig.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.ServerName = host
	cfg.NextProtos = []string{"http/1.1"}
	return cfg
}

// reap 把竞速结束后还躺在 channel 里的连接关掉。有些 goroutine 已经在
// raceCtx.Done() 分支里自己关了连接、不会再发送，所以这里必须有时间上限。
func reap(ch chan result, n int) {
	deadline := time.After(2 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case r := <-ch:
			if r.conn != nil {
				_ = r.conn.Close()
			}
		case <-deadline:
			return
		}
	}
}

// countingConn 在连接关闭时把搬运过的字节数折算成吞吐回写给 dialer。
// 没有这一层，Score 里的 0.4 吞吐权重永远是个常数——而国际链路最常见的
// 失败模式恰恰是"TCP 三秒连上、下载只有 50KB/s"。
type countingConn struct {
	net.Conn
	d     *Dialer
	ip    netip.Addr
	start time.Time
	n     atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingConn) Close() error {
	err := c.Conn.Close()
	n := c.n.Load()
	if n == 0 && time.Since(c.start) > 2*time.Second {
		// "连上了、撑了几秒、一个字节都没搬运"是最典型的黑洞地址特征：
		// TCP 与 TLS 都能过，真正的流量被吞。必须记成应用层失败，否则它会凭
		// 漂亮的握手延迟一直排在最前面，让每个请求都白等十几秒。
		c.d.recordProbe(c.ip, 0, false)
	}
	if n > 0 {
		// 用连接存活时间做分母：长连接上的空闲会稀释吞吐，
		// 但同一 IP 的多次连接会按 α=0.3 的 EWMA 抹平。
		c.d.RecordThroughput(c.ip, n, time.Since(c.start))
	}
	return err
}

// CloseWrite 透传半关闭能力：proxy 的 passthrough 依赖它避免截断响应。
func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
