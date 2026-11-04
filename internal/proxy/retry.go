package proxy

import (
	"context"
	"io"
	"net/http"
	"net/netip"
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
		// 大文件下载不会被掐断。
		remaining := time.Until(deadline)
		if remaining <= 0 {
			cancel()
			break
		}
		timer := time.AfterFunc(remaining, cancel)
		resp, err := t.base.RoundTrip(req.Clone(ctx))
		if err == nil {
			// 头已到，撤销单次尝试的封顶；cancel 挂到 bodyWithCancel，
			// 等响应体读完（或客户端断开）才触发。
			timer.Stop()
			// 响应头到手 = 这条路是真的能干活（不只是能握手），把 IP 交给
			// onOK 记成粘性：下一批并发请求直接走它，不再重新竞速去撞那些
			// "TLS 通、不吐数据"的地址。
			if t.onOK != nil {
				if ip, ok := rec.Get(); ok {
					t.onOK(ip)
				}
			}
			resp.Body = &bodyWithCancel{ReadCloser: resp.Body, cancel: cancel}
			return resp, nil
		}
		timer.Stop()
		cancel()
		if t.onFail != nil {
			if ip, ok := rec.Get(); ok {
				t.onFail(ip, err)
			}
		}
		lastErr = err
		if req.Context().Err() != nil {
			// 客户端自己放弃（关标签页、Ctrl-C），重试没有意义。
			return nil, err
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

func (b *bodyWithCancel) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
