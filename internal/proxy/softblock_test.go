package proxy

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/upstream"
)

func newHTMLRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://github.com/", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	return req
}

func fakeResp(contentType, body string) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: 200,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// 2026-11-05 实测形态：github.com 的导航请求拿到 200 + text/plain + 4 字节 "OK"，
// 响应头带着 X-GitHub-Edge-Region，是 GitHub 的软拦截空壳。
func TestSniffSoftBlockDetectsTarpit(t *testing.T) {
	cases := []string{"OK\n", "OK", "ok", "", "  OK  \n"}
	for _, body := range cases {
		req := newHTMLRequest(t)
		resp := fakeResp("text/plain", body)
		n, soft := sniffSoftBlock(req, resp)
		if !soft {
			t.Fatalf("正文 %q 应判为软拦截空壳", body)
		}
		if n != len(body) {
			t.Fatalf("正文 %q 读到的长度 = %d，期望 %d", body, n, len(body))
		}
	}
}

// 真页面是 text/html，绝不能因为"正文短"被误判。
func TestSniffSoftBlockKeepsRealHTML(t *testing.T) {
	req := newHTMLRequest(t)
	const page = "<!DOCTYPE html><html lang=\"en\"><head><title>GitHub</title></head></html>"
	resp := fakeResp("text/html; charset=utf-8", page)
	if _, soft := sniffSoftBlock(req, resp); soft {
		t.Fatal("text/html 的页面不该被判成软拦截")
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取正文失败: %v", err)
	}
	if string(got) != page {
		t.Fatalf("正文被改动: %q", string(got))
	}
}

// text/plain 但正文超过阈值 → 不是空壳，而且已经读出来的字节要原样接回去。
func TestSniffSoftBlockRestoresLongBody(t *testing.T) {
	req := newHTMLRequest(t)
	long := strings.Repeat("x", 4096)
	resp := fakeResp("text/plain", long)
	if _, soft := sniffSoftBlock(req, resp); soft {
		t.Fatal("超过阈值的正文不该被判成软拦截")
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取正文失败: %v", err)
	}
	if len(got) != len(long) {
		t.Fatalf("接回的正文长度 = %d，期望 %d", len(got), len(long))
	}
	if string(got) != long {
		t.Fatal("接回的正文内容与原始不一致")
	}
}

// fetch/XHR 的 Accept 是 */*，raw 上的小 .txt 也可能是 text/plain 短正文，
// 这些不该被当成风控空壳。
func TestSniffSoftBlockIgnoresNonNavigation(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/a/b/main/x.txt", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Accept", "*/*")
	resp := fakeResp("text/plain", "OK")
	if _, soft := sniffSoftBlock(req, resp); soft {
		t.Fatal("非导航请求不该做软拦截判定")
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "OK" {
		t.Fatalf("正文被改动: %q", string(got))
	}
}

// text/plain 但正文既不是空也不是 "ok"（比如一个真实的小文件），不算空壳。
func TestSniffSoftBlockIgnoresOtherShortText(t *testing.T) {
	req := newHTMLRequest(t)
	resp := fakeResp("text/plain", "hello")
	if _, soft := sniffSoftBlock(req, resp); soft {
		t.Fatal("内容不是空壳形态时不该误判")
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != "hello" {
		t.Fatalf("正文被改动: %q", string(got))
	}
}

// tarpitTransport 第一次尝试返回软拦截空壳，之后返回真页面；每次都把
// 尝试用到的 IP 写进 Recorder，用于验证 onFail/onOK 收到了哪个地址。
type tarpitTransport struct {
	calls atomic.Int32
	ips   []string
	// alwaysTarpit 为 true 时每次尝试都回空壳（模拟整段上游都在软拦截）。
	alwaysTarpit bool
}

func (tt *tarpitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	i := int(tt.calls.Add(1)) - 1
	if rec := upstream.From(req.Context()); rec != nil && len(tt.ips) > 0 {
		rec.Set(netip.MustParseAddr(tt.ips[i%len(tt.ips)]))
	}
	if i == 0 || tt.alwaysTarpit {
		h := http.Header{}
		h.Set("Content-Type", "text/plain")
		return &http.Response{
			StatusCode: 200,
			Header:     h,
			Body:       io.NopCloser(strings.NewReader("OK\n")),
			Request:    req,
		}, nil
	}
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	return &http.Response{
		StatusCode: 200,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader("<!DOCTYPE html><html><body>real</body></html>")),
		Request:    req,
	}, nil
}

// 端到端回归：软拦截空壳要被当成一次失败——惩罚那个 IP、换地址重试，
// 而不是把空壳交给浏览器并把它立成粘性。
func TestTarpitResponseIsRetriedAndPenalized(t *testing.T) {
	base := &tarpitTransport{ips: []string{"192.0.2.9", "192.0.2.10"}}

	var (
		mu     sync.Mutex
		failed []netip.Addr
		okIPs  []netip.Addr
	)
	rt := &retryTransport{
		base:     base,
		attempts: 4,
		onFail: func(ip netip.Addr, err error) {
			mu.Lock()
			failed = append(failed, ip)
			mu.Unlock()
		},
		onOK: func(ip netip.Addr) {
			mu.Lock()
			okIPs = append(okIPs, ip)
			mu.Unlock()
		},
	}

	resp, err := rt.RoundTrip(newHTMLRequest(t))
	if err != nil {
		t.Fatalf("换到好地址后应当成功: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "real") {
		t.Fatalf("最终正文应当是页面，拿到 %q", string(body))
	}
	if got := base.calls.Load(); got != 2 {
		t.Fatalf("尝试次数 = %d，期望 2（空壳算失败，换地址重试一次）", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(failed) != 1 || failed[0] != netip.MustParseAddr("192.0.2.9") {
		t.Fatalf("onFail 应当收到空壳地址 192.0.2.9，实际 %v", failed)
	}
	if len(okIPs) != 1 || okIPs[0] != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("onOK 应当收到 192.0.2.10，实际 %v", okIPs)
	}
}

// 全部地址都回空壳时，请求必须以错误收场（交给上层回 502），
// 而不是把 4 字节的 "OK" 当页面发出去。
func TestTarpitEverywhereFails(t *testing.T) {
	base := &tarpitTransport{ips: []string{"192.0.2.9", "192.0.2.10"}, alwaysTarpit: true}
	rt := &retryTransport{base: base, attempts: 3}

	resp, err := rt.RoundTrip(newHTMLRequest(t))
	if err == nil {
		resp.Body.Close()
		t.Fatal("所有地址都回空壳时应当报错")
	}
	if !strings.Contains(err.Error(), "软拦截空壳") {
		t.Fatalf("错误信息应当说明是软拦截空壳，实际 %v", err)
	}
}
