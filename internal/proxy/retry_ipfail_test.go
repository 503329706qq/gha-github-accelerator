package proxy

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/upstream"
)

// recordingDialer 把"拨到哪个 IP"写进请求 ctx 的 Recorder，模拟真实拨号层。
type recordingDialer struct {
	ip netip.Addr
}

func (r recordingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if rec := upstream.From(ctx); rec != nil {
		rec.Set(r.ip)
	}
	// 给一个真正能连的本地地址，让 Transport 能完成请求。
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		c, err := l.Accept()
		if err == nil {
			_ = c.Close() // 立刻挂断：模拟"连得上但帮不了你"
		}
	}()
	conn, err := net.Dial(l.Addr().Network(), l.Addr().String())
	if err != nil {
		l.Close()
		return nil, err
	}
	return &closerConn{Conn: conn, onClose: l.Close}, nil
}

type closerConn struct {
	net.Conn
	onClose func() error
}

func (c *closerConn) Close() error {
	err := c.Conn.Close()
	if c.onClose != nil {
		_ = c.onClose()
	}
	return err
}

// 一次尝试失败后，onFail 必须拿到该次真正拨到的 IP（Recorder 里来的）。
func TestRetryTransportReportsDialedIPOnFailure(t *testing.T) {
	want := netip.MustParseAddr("203.0.113.7")
	base := &http.Transport{
		DialContext:           recordingDialer{ip: want}.DialContext,
		ResponseHeaderTimeout: 200 * time.Millisecond,
		DisableKeepAlives:     true,
	}
	var got []netip.Addr
	rt := &retryTransport{
		base:     base,
		attempts: 2,
		onFail: func(ip netip.Addr, err error) {
			got = append(got, ip)
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "http://blackhole.test/", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("上游立刻挂断时应当报错")
	}
	if len(got) != 2 {
		t.Fatalf("onFail 触发次数 = %d，期望 2（每次失败都报）", len(got))
	}
	for i, ip := range got {
		if ip != want {
			t.Fatalf("onFail[%d] = %s，期望该次真正拨到的 %s", i, ip, want)
		}
	}
}

// onFail 只该在真正失败时触发；成功路径不应有。
func TestRetryTransportNoIPFailOnSuccess(t *testing.T) {
	rt := &retryTransport{
		base:     &flakyTransport{fails: 1, body: "ok"},
		attempts: 3,
		onFail: func(ip netip.Addr, err error) {
			t.Errorf("成功路径不应触发 onFail，却收到 %s: %v", ip, err)
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "https://github.com/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	resp.Body.Close()
}

// 预算修正后：剩余预算不足 minRetryWindow 时不再发起下一次尝试。
// 用真实 Transport + 立刻挂断的上游让每次尝试真正消耗时间
// （ResponseHeaderTimeout 200ms × 若干次 + 间隔），整个调用必须在
// maxBudget（8s）内返回，而不是 attempts 数 × 超时地无限拖。
func TestRetryTransportStopsWithinBudget(t *testing.T) {
	base := &http.Transport{
		DialContext:           recordingDialer{}.DialContext,
		ResponseHeaderTimeout: 200 * time.Millisecond,
		DisableKeepAlives:     true,
	}
	rt := &retryTransport{base: base, attempts: 99} // 想试多少次都行，预算说了算
	req, _ := http.NewRequest(http.MethodGet, "http://blackhole.test/", nil)
	start := time.Now()
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("全部失败时应当返回错误")
	}
	if d := time.Since(start); d > maxBudget+2*time.Second {
		t.Fatalf("重试耗时 %v，超出预算 %v 太多", d, maxBudget)
	}
}

// 非幂等方法携带的 ctx 不应带 Recorder（它们不重试，也不需要惩罚）。
func TestNonIdempotentBypassesRecorder(t *testing.T) {
	rt := &retryTransport{base: &flakyTransport{fails: 0, body: "ok"}, attempts: 3}
	req, _ := http.NewRequest(http.MethodPost, "https://api.github.com/gists", strings.NewReader("{}"))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
}
