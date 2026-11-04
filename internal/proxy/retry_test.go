package proxy

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type flakyTransport struct {
	fails int
	calls atomic.Int32
	body  string
}

func (f *flakyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	n := f.calls.Add(1)
	if int(n) <= f.fails {
		return nil, errors.New("simulated blackhole")
	}
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Request:    req,
	}, nil
}

func TestRetryTransportRetriesIdempotentGet(t *testing.T) {
	base := &flakyTransport{fails: 2, body: "ok"}
	rt := &retryTransport{base: base, attempts: 3}

	req, _ := http.NewRequest(http.MethodGet, "https://github.com/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("第三次应当成功，得到错误: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}
	if got := base.calls.Load(); got != 3 {
		t.Fatalf("调用次数 = %d，期望 3（两次失败一次成功）", got)
	}
}

func TestRetryTransportDoesNotRetryPost(t *testing.T) {
	base := &flakyTransport{fails: 1, body: "ok"}
	rt := &retryTransport{base: base, attempts: 3}

	req, _ := http.NewRequest(http.MethodPost, "https://api.github.com/gists", strings.NewReader("{}"))
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("POST 失败必须直接返回错误，不能重发")
	}
	if got := base.calls.Load(); got != 1 {
		t.Fatalf("POST 调用次数 = %d，期望 1", got)
	}
}

// 响应体必须在读完并 Close 之后才取消 context，否则正常响应会被截断。
func TestRetryTransportKeepsBodyReadable(t *testing.T) {
	base := &flakyTransport{fails: 0, body: strings.Repeat("x", 1024)}
	rt := &retryTransport{base: base, attempts: 1}

	req, _ := http.NewRequest(http.MethodGet, "https://github.com/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应体失败: %v", err)
	}
	if len(b) != 1024 {
		t.Fatalf("响应体长度 = %d，期望 1024", len(b))
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
