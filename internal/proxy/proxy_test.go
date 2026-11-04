package proxy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/ca"
	"github.com/503329706qq/gha-github-accelerator/internal/proxy"
)

func poolWith(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// startUpstream 起一个自签名 TLS 上游，证书覆盖 names 指定的域名。
// 不用 httptest.NewTLSServer：它的证书只覆盖 example.com/127.0.0.1，
// 而反代把 URL.Host 设成 github.com，会撞上主机名不匹配。
func startUpstream(t *testing.T, h http.Handler, names ...string) (addr string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              names,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	srv := &http.Server{Handler: h}
	go srv.Serve(tlsLn)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), poolWith(parsed)
}

func newCA(t *testing.T) *ca.CA {
	t.Helper()
	dir := t.TempDir()
	c, err := ca.LoadOrCreate(ca.Options{
		CertPath: filepath.Join(dir, "root.crt"),
		KeyPath:  filepath.Join(dir, "root.key.pem"),
		CRLURL:   "http://127.0.0.1:12080/ca.crl",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func startProxy(t *testing.T, opts proxy.Options) (addr string, shutdown func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := proxy.New(opts)
	go srv.ServeTLS(ln)
	return ln.Addr().String(), func() { srv.Close() }
}

// clientFor 造一个"信本地 CA、但把连接打到 proxyAddr"的客户端。
func clientFor(t *testing.T, caCertPEM []byte, proxyAddr, sni string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("bad CA PEM")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, proxyAddr)
			},
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: sni},
		},
	}
}

func TestProxiesAllowlistedHost(t *testing.T) {
	upstreamAddr, upstreamPool := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "upstream saw host=%s path=%s", r.Host, r.URL.Path)
	}), "github.com")

	localCA := newCA(t)
	var dialedTo atomic.Value

	addr, shutdown := startProxy(t, proxy.Options{
		CA:    localCA,
		Allow: func(h string) bool { return h == "github.com" },
		Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
			dialedTo.Store(a)
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		UpstreamRootCAs: upstreamPool,
	})
	defer shutdown()

	client := clientFor(t, localCA.CertPEM(), addr, "github.com")
	resp, err := client.Get("https://github.com/octocat/Hello-World")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "upstream saw host=github.com") {
		t.Fatalf("body=%s", body)
	}
	if got, _ := dialedTo.Load().(string); got != "github.com:443" {
		t.Fatalf("dialed %q, want github.com:443", got)
	}
	if len(resp.TLS.PeerCertificates) == 0 || resp.TLS.PeerCertificates[0].Issuer.CommonName != localCA.Certificate().Subject.CommonName {
		t.Fatalf("peer cert not issued by local CA: %v", resp.TLS.PeerCertificates)
	}
}

func TestPassthroughForForeignSNI(t *testing.T) {
	upstreamAddr, upstreamPool := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "raw upstream")
	}), "example.com")

	localCA := newCA(t)
	var passthroughUsed atomic.Bool

	addr, shutdown := startProxy(t, proxy.Options{
		CA:    localCA,
		Allow: func(h string) bool { return strings.HasSuffix(h, ".github.com") },
		Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
			t.Errorf("dial must not be used for passthrough, got %s", a)
			return nil, fmt.Errorf("unexpected")
		},
		Passthrough: func(ctx context.Context, host string) (net.Conn, error) {
			passthroughUsed.Store(true)
			if host != "example.com" {
				t.Errorf("passthrough host=%q", host)
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", upstreamAddr)
		},
	})
	defer shutdown()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
			TLSClientConfig: &tls.Config{RootCAs: upstreamPool, ServerName: "example.com"},
		},
	}
	resp, err := client.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "raw upstream" {
		t.Fatalf("body=%s", body)
	}
	if !passthroughUsed.Load() {
		t.Fatal("passthrough path not taken")
	}
}

func TestHTTPRedirectsToHTTPS(t *testing.T) {
	localCA := newCA(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := proxy.New(proxy.Options{CA: localCA, Allow: func(string) bool { return true }})
	go srv.ServeHTTP(ln)
	defer srv.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + ln.Addr().String() + "/octocat?tab=repos")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://") || !strings.Contains(loc, "/octocat?tab=repos") {
		t.Fatalf("Location=%q", loc)
	}
}

func TestReportsTransferSize(t *testing.T) {
	payload := strings.Repeat("x", 8192)
	upstreamAddr, upstreamPool := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, payload)
	}), "github.com")

	localCA := newCA(t)
	type sample struct {
		host  string
		bytes int64
		dur   time.Duration
	}
	got := make(chan sample, 4)

	addr, shutdown := startProxy(t, proxy.Options{
		CA:              localCA,
		Allow:           func(h string) bool { return true },
		UpstreamRootCAs: upstreamPool,
		Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		OnRequest: func(host string, n int64, dur time.Duration, status int) {
			got <- sample{host, n, dur}
		},
	})
	defer shutdown()

	client := clientFor(t, localCA.CertPEM(), addr, "github.com")
	resp, err := client.Get("https://github.com/big")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	select {
	case s := <-got:
		if s.bytes < int64(len(payload)) {
			t.Fatalf("reported bytes=%d, want >= %d", s.bytes, len(payload))
		}
		if s.host != "github.com" {
			t.Fatalf("reported host=%q", s.host)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnRequest never called")
	}
}

func TestRejectsHostOutsideAllowlistAtHTTPLayer(t *testing.T) {
	localCA := newCA(t)
	addr, shutdown := startProxy(t, proxy.Options{
		CA: localCA,
		// SNI 放行，但 HTTP 层再拦一次（防御纵深：hosts 可能被人改）
		Allow: func(h string) bool { return h != "evil.example" },
		Dial: func(ctx context.Context, network, a string) (net.Conn, error) {
			return nil, fmt.Errorf("must not dial")
		},
	})
	defer shutdown()

	client := clientFor(t, localCA.CertPEM(), addr, "github.com")
	req, _ := http.NewRequest("GET", "https://github.com/", nil)
	req.Host = "evil.example"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want 421/403", resp.StatusCode)
	}
}
