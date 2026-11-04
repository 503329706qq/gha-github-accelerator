package dialer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// serveStatus 起一个 TLS 服务端：握手成功后，对每个请求回一行固定的状态行。
// 用来模拟"链路是通的，但上游在拒绝我们"（GitHub 的 400/403 拦截页）。
func serveStatus(t *testing.T, addr string, cert tls.Certificate, statusLine string) string {
	t.Helper()
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("监听 %s：%v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				// 把请求读掉再回，避免客户端还在写的时候我们就把连接关了。
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(statusLine))
			}(c)
		}
	}()
	return ln.Addr().String()
}

func probeDialerWithRoots(pool *x509.CertPool) *Dialer {
	return New(Options{
		Resolver:  staticResolver(nil),
		TLSConfig: &tls.Config{RootCAs: pool},
	})
}

// TestProbeTLSRejectsBlockPage 是 2026-11-04 GitHub 风控事件的回归。
//
// 旧实现只读响应首字节就判"可用"，而 GitHub 的 403
// "Access to this site has been restricted" 和 400 "Whoa there!"
// 都是正常回字节的，于是被当成好地址记成 rank 0：评分表里一片假地址，
// gha 还会继续往这排地址上打探测流量，反过来延长封禁。
func TestProbeTLSRejectsBlockPage(t *testing.T) {
	const host = "github.com"
	cert, pool := selfSigned(t, host)
	tcpAddr := serveStatus(t, "127.0.0.1:0", cert, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
	_, portStr, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		t.Fatalf("解析监听地址：%v", err)
	}
	port, _ := strconv.Atoi(portStr)

	ip := netip.MustParseAddr("127.0.0.1")
	d := probeDialerWithRoots(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := d.probeTLSPort(ctx, host, ip, port, 2*time.Second); err == nil {
		t.Fatalf("403 拦截页应当判为失败")
	}
	if got := d.rankFor(ip); got != 2 {
		t.Fatalf("403 之后 rankFor = %d，期望 2（已验证失败）", got)
	}
}

// TestProbeTLSAcceptsNormalResponse 保证收紧判活后没有误杀正常响应。
func TestProbeTLSAcceptsNormalResponse(t *testing.T) {
	const host = "github.com"
	cert, pool := selfSigned(t, host)
	tcpAddr := serveStatus(t, "127.0.0.1:0", cert, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	_, portStr, _ := net.SplitHostPort(tcpAddr)
	port, _ := strconv.Atoi(portStr)

	ip := netip.MustParseAddr("127.0.0.1")
	d := probeDialerWithRoots(pool)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := d.probeTLSPort(ctx, host, ip, port, 2*time.Second); err != nil {
		t.Fatalf("200 应当通过：%v", err)
	}
	if got := d.rankFor(ip); got != 0 {
		t.Fatalf("200 之后 rankFor = %d，期望 0（已验证可用）", got)
	}
}

func TestCheckStatusLine(t *testing.T) {
	ok := []string{
		"HTTP/1.1 200 OK\r\n",
		"HTTP/1.1 301 Moved Permanently\r\n",
		"HTTP/1.1 304 Not Modified\r\n",
		"HTTP/1.1 404 Not Found\r\n",
		"garbage\r\n",
		"\r\n",
	}
	for _, line := range ok {
		if err := checkStatusLine(line); err != nil {
			t.Fatalf("%q 不应被判失败：%v", line, err)
		}
	}
	for _, line := range []string{
		"HTTP/1.1 400 Bad Request\r\n",
		"HTTP/1.1 403 Forbidden\r\n",
		"HTTP/1.1 429 Too Many Requests\r\n",
	} {
		if err := checkStatusLine(line); err == nil {
			t.Fatalf("%q 应当被判失败", line)
		}
	}
}
