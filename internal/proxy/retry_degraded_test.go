package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/upstream"
)

// silentTransport 模拟"上游整段假死"的尝试：每次尝试都拿不到响应头。
// ips 非空时把 IP 写进 Recorder（模拟"拨号成功、TLS 握上了但不吐数据"）；
// ips 为空时 Recorder 保持空（模拟"TCP SYN 被整段丢弃、竞速全灭"）。
type silentTransport struct {
	ips   []string
	next  atomic.Int32
	calls atomic.Int32
	// succeed 为 true 时下一次尝试返回 200，用来模拟链路恢复。
	succeed atomic.Bool
	// sleep 非零时每次尝试先睡这么久（或被 ctx 取消），用于测降级封顶。
	sleep time.Duration
}

func (s *silentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.calls.Add(1)
	if rec := upstream.From(req.Context()); rec != nil && len(s.ips) > 0 {
		i := int(s.next.Add(1)-1) % len(s.ips)
		rec.Set(netip.MustParseAddr(s.ips[i]))
	}
	if s.succeed.Load() {
		s.succeed.Store(false)
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	}
	if s.sleep > 0 {
		select {
		case <-time.After(s.sleep):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	return nil, errors.New("timeout awaiting response headers")
}

// alternateTransport 模拟健康时段的常态：每个请求的第 1 次尝试撞上一个坏
// IP，第 2 次换到好地址就成功。重试内部消化掉失败，不该被判成链路故障。
type alternateTransport struct {
	calls atomic.Int32
}

func (a *alternateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if a.calls.Add(1)%2 == 1 {
		return nil, errors.New("single bad ip")
	}
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

// inflightDegradeTransport 模拟"并发首波里别的请求先撞够失败、确立了降级"：
// 被测试的请求起飞时还没降级（attempts=4），但它的第一次尝试返回时，共享的
// 降级状态已经被别的 goroutine 置上了。
type inflightDegradeTransport struct {
	calls   atomic.Int32
	onFirst func()
}

func (s *inflightDegradeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if s.calls.Add(1) == 1 && s.onFirst != nil {
		s.onFirst()
	}
	return nil, errors.New("timeout awaiting response headers")
}

func newDegradedTestTransport(base http.RoundTripper, attempts int) (*retryTransport, *atomic.Int32) {
	var degraded atomic.Int32
	rt := &retryTransport{
		base:     base,
		attempts: attempts,
		onDegraded: func(host string, failures int) {
			degraded.Add(1)
		},
	}
	return rt, &degraded
}

func doGet(t *testing.T, rt *retryTransport) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://github.com/", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	return rt.RoundTrip(req)
}

// 短时间内连续失败达到阈值就降级，并且连正在飞的那条请求也不再跑完剩余
// 重试；降级窗口内的新请求只赌一次。
func TestDegradedAfterRepeatedAttemptFailures(t *testing.T) {
	base := &silentTransport{ips: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}}
	rt, degraded := newDegradedTestTransport(base, 8)

	if _, err := doGet(t, rt); err == nil {
		t.Fatal("第 1 条请求应当失败")
	}
	if got := base.calls.Load(); got != attemptFailThreshold {
		t.Fatalf("第 1 条请求尝试次数 = %d，期望 %d（触发降级后立刻截断剩余重试）",
			got, attemptFailThreshold)
	}
	if got := degraded.Load(); got != 1 {
		t.Fatalf("降级回调次数 = %d，期望 1", got)
	}
	if !rt.degraded("github.com") {
		t.Fatal("应当已进入降级窗口")
	}

	base.calls.Store(0)
	if _, err := doGet(t, rt); err == nil {
		t.Fatal("第 2 条请求应当失败")
	}
	if got := base.calls.Load(); got != degradedAttempts {
		t.Fatalf("降级窗口内尝试次数 = %d，期望 %d（快速失败）", got, degradedAttempts)
	}
}

// 本轮修复的核心回归：TCP 全黑时拨号竞速整个失败，Recorder 里没有 IP，
// 也必须能识别出链路级故障。第一版按"3 个不同 IP"计数时漏掉了这种波形。
func TestDegradedWithoutDialedIP(t *testing.T) {
	base := &silentTransport{} // 不写 Recorder，模拟 SYN 被整段丢弃
	rt, degraded := newDegradedTestTransport(base, 8)

	if _, err := doGet(t, rt); err == nil {
		t.Fatal("请求应当失败")
	}
	if got := degraded.Load(); got != 1 {
		t.Fatalf("没有拨到任何 IP 也应当触发降级，回调次数 = %d", got)
	}
	if got := base.calls.Load(); got != attemptFailThreshold {
		t.Fatalf("尝试次数 = %d，期望 %d", got, attemptFailThreshold)
	}

	base.calls.Store(0)
	if _, err := doGet(t, rt); err == nil {
		t.Fatal("第 2 条请求应当失败")
	}
	if got := base.calls.Load(); got != degradedAttempts {
		t.Fatalf("降级窗口内尝试次数 = %d，期望 %d", got, degradedAttempts)
	}
}

// 健康时段单个坏 IP 由重试内部消化（第 2 次就成功），成功会清空累计，
// 因此连续多条请求都不该被误判成整段故障。
func TestNoDegradedWhenRetrySucceeds(t *testing.T) {
	base := &alternateTransport{}
	rt, degraded := newDegradedTestTransport(base, 3)

	for i := 0; i < 5; i++ {
		resp, err := doGet(t, rt)
		if err != nil {
			t.Fatalf("第 %d 条请求应当成功: %v", i+1, err)
		}
		resp.Body.Close()
	}
	if got := degraded.Load(); got != 0 {
		t.Fatalf("单 IP 抖动不应触发降级，回调次数 = %d", got)
	}
	if rt.degraded("github.com") {
		t.Fatal("健康时段不应进入降级窗口")
	}
}

// 一条成功就立刻解除降级，且失败累计从零开始重新算。
func TestSuccessClearsDegraded(t *testing.T) {
	base := &silentTransport{ips: []string{"192.0.2.1"}}
	rt, _ := newDegradedTestTransport(base, attemptFailThreshold)

	if _, err := doGet(t, rt); err == nil {
		t.Fatal("第 1 条请求应当失败")
	}
	if !rt.degraded("github.com") {
		t.Fatal("连续失败后应当处于降级窗口")
	}

	base.succeed.Store(true)
	// 降级窗口内只赌一次，这一次让它成功。
	resp, err := doGet(t, rt)
	if err != nil {
		t.Fatalf("链路恢复后应当成功: %v", err)
	}
	resp.Body.Close()
	if rt.degraded("github.com") {
		t.Fatal("成功的请求必须解除降级")
	}

	base.calls.Store(0)
	if _, err := doGet(t, rt); err == nil {
		t.Fatal("请求应当失败")
	}
	if got := base.calls.Load(); got != attemptFailThreshold {
		t.Fatalf("解除降级后尝试次数 = %d，期望 %d（累计已清零，不是只试 1 次）",
			got, attemptFailThreshold)
	}
}

// 降级/统计窗口过期后，上一波攒下的失败不能算进新的一波：链路恢复后只抖
// 一次，不该被再次判成整段故障。
func TestExpiredWindowDoesNotReuseStaleFailures(t *testing.T) {
	base := &silentTransport{ips: []string{"192.0.2.1"}}
	rt, degraded := newDegradedTestTransport(base, 1)

	// 手工摆成"上一波降级窗口已过期，攒了阈值-1 次旧失败"。
	rt.mu.Lock()
	rt.health = map[string]*hostHealth{
		"github.com": {
			fails: attemptFailThreshold - 1,
			first: time.Now().Add(-attemptFailWindow - time.Second),
			until: time.Now().Add(-time.Second),
		},
	}
	rt.mu.Unlock()

	if _, err := doGet(t, rt); err == nil {
		t.Fatal("请求应当失败")
	}
	if got := degraded.Load(); got != 0 {
		t.Fatalf("过期的旧失败不应参与新一波判定，降级回调次数 = %d", got)
	}
	if rt.degraded("github.com") {
		t.Fatal("只抖 1 次不应重新进入降级窗口")
	}
}

// 客户端自己放弃（关标签页）不该被算成链路故障。
func TestClientCancelNotCountedAsSilent(t *testing.T) {
	base := &silentTransport{ips: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}}
	rt, degraded := newDegradedTestTransport(base, 4)

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://github.com/", nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // 请求一进来就已经取消
		req = req.WithContext(ctx)
		if _, err := rt.RoundTrip(req); err == nil {
			t.Fatal("请求应当失败")
		}
	}
	if got := degraded.Load(); got != 0 {
		t.Fatalf("客户端取消不应触发降级，回调次数 = %d", got)
	}
}

// 降级由并发首波里的其它请求确立时，这条"已经在飞"的请求也必须立刻截断，
// 不能因为自己起飞时还没降级就硬跑完 4 次尝试（那是 12s 的 502）。
// 2026-11-04 故障波形实测：首波有 10 个请求整齐钉在 12s，就是这个缺口。
func TestInFlightRequestStopsWhenPeerEntersDegraded(t *testing.T) {
	rt, _ := newDegradedTestTransport(nil, 4)
	base := &inflightDegradeTransport{}
	base.onFirst = func() {
		rt.mu.Lock()
		rt.health = map[string]*hostHealth{
			"github.com": {until: time.Now().Add(degradedWindow)},
		}
		rt.mu.Unlock()
	}
	rt.base = base

	if _, err := doGet(t, rt); err == nil {
		t.Fatal("请求应当失败")
	}
	if got := base.calls.Load(); got != 1 {
		t.Fatalf("同伴确立降级后本请求尝试次数 = %d，期望 1（立刻截断）", got)
	}
}

// 降级窗口内单次尝试被 degradedCap 封顶：故障期间的请求应当秒级返回，
// 而不是陪着一条毫无希望的连接挂到响应头超时（甚至跑满 12s 预算）。
func TestDegradedCapsSingleAttempt(t *testing.T) {
	base := &silentTransport{sleep: 5 * time.Second}
	rt, _ := newDegradedTestTransport(base, 4)

	rt.mu.Lock()
	rt.health = map[string]*hostHealth{
		"github.com": {until: time.Now().Add(degradedWindow)},
	}
	rt.mu.Unlock()

	start := time.Now()
	if _, err := doGet(t, rt); err == nil {
		t.Fatal("请求应当失败")
	}
	if d := time.Since(start); d > degradedCap+time.Second {
		t.Fatalf("降级窗口内请求耗时 %v，超过单次封顶 %v 太多", d, degradedCap)
	}
	if got := base.calls.Load(); got != degradedAttempts {
		t.Fatalf("尝试次数 = %d，期望 %d", got, degradedAttempts)
	}
}
