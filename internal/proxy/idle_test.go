package proxy_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/proxy"
)

// accept 循环是串行的：一条只连不发数据的连接（浏览器空闲预连接、端口扫描、
// 半开 socket）如果让 inspect 无限等下去，整个 443 面就冻住了。inspect 现在有
// 3 秒读超时，所以这里断言"正常请求仍能完成"，而不是挂死到测试超时。
func TestIdleConnectionDoesNotFreezeHTTPS(t *testing.T) {
	upstreamAddr, pool := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}), "github.com")

	localCA := newCA(t)
	addr, shutdown := startProxy(t, proxy.Options{
		CA:    localCA,
		Allow: func(h string) bool { return h == "github.com" },
		Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		UpstreamRootCAs: pool,
	})
	defer shutdown()

	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	start := time.Now()
	resp, err := clientFor(t, localCA.CertPEM(), addr, "github.com").Get("https://github.com/")
	if err != nil {
		t.Fatalf("request while an idle connection is parked: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("request took %v — an idle connection blocked the accept loop", d)
	}
}
