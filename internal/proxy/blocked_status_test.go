package proxy

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/upstream"
)

// statusTransport 固定回某个状态码，并把一条 IP 写进 Recorder（模拟拨号成功）。
type statusTransport struct {
	code int
	ip   string
}

func (s *statusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if s.ip != "" {
		if rec := upstream.From(req.Context()); rec != nil {
			rec.Set(netip.MustParseAddr(s.ip))
		}
	}
	return &http.Response{
		StatusCode: s.code,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("x")),
		Request:    req,
	}, nil
}

func praiseCount(t *testing.T, code int) int32 {
	t.Helper()
	var praised atomic.Int32
	rt := &retryTransport{
		base:     &statusTransport{code: code, ip: "20.0.0.1"},
		attempts: 1,
		onOK:     func(netip.Addr) { praised.Add(1) },
	}
	req, err := http.NewRequest("GET", "https://github.com/", nil)
	if err != nil {
		t.Fatalf("构造请求：%v", err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip：%v", err)
	}
	_ = resp.Body.Close()
	return praised.Load()
}

// TestNoPraiseOnBlockedStatus 是 2026-11-04 GitHub 风控事件的回归。
//
// 400 "Whoa there!" / 403 "Access to this site has been restricted" /
// 429 同样有响应头，但那只证明"连得上"，不证明这个地址对浏览有用。
// 旧实现把它们也立成粘性，于是后续几十个并发请求全部照着撞同一堵墙。
func TestNoPraiseOnBlockedStatus(t *testing.T) {
	for _, code := range []int{400, 403, 429} {
		if n := praiseCount(t, code); n != 0 {
			t.Fatalf("状态码 %d 不应当把 IP 立成粘性（实际立了 %d 次）", code, n)
		}
	}
}

func TestPraiseOnNormalStatus(t *testing.T) {
	for _, code := range []int{200, 301, 304, 404} {
		if n := praiseCount(t, code); n != 1 {
			t.Fatalf("状态码 %d 应当把 IP 立成粘性（实际 %d 次）", code, n)
		}
	}
}
