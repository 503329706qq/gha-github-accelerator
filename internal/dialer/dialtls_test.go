package dialer

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
	"net/netip"
	"sync"
	"testing"
	"time"
)

// staticResolver 按固定顺序给出候选，模拟"种子表里好地址排在后面"的情况。
type staticResolver []netip.Addr

func (s staticResolver) Lookup(context.Context, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), s...), nil
}

// selfSigned 造一张 host 的自签证书，并返回信任它的池子。
func selfSigned(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥：%v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书：%v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书：%v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// serveTLS 起一个只握手不聊天的 TLS 服务端：握手能成功，之后就一直挂着。
func serveTLS(t *testing.T, addr string, cert tls.Certificate) net.Listener {
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
				if tc, ok := c.(*tls.Conn); ok {
					if err := tc.Handshake(); err != nil {
						return
					}
				}
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return ln
}

// stallTCP 起一个"只 accept 不说话"的服务端：TCP 三次握手立刻成功，TLS 的
// ClientHello 石沉大海——这正是本机那些黑洞地址的签名。
func stallTCP(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("监听 %s：%v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c) // 一个字节都不读
		}
	}()
	return ln
}

// 竞速必须跑到 TLS 握手完成：只测 TCP 的话，"握手 0.2s 成功、之后一个字节
// 都不回"的黑洞地址会赢下竞速，然后把请求卡到 8s 预算耗尽（线上表现为
// 8000ms 的 502 + context canceled）。这个用例把黑洞放在第 0 位，好地址放
// 第 1 位，胜者必须是后者，且黑洞要被写进"已验证失败"档。
func TestDialTLSBeatsStalledCandidate(t *testing.T) {
	cert, pool := selfSigned(t, "github.com")
	good := serveTLS(t, "127.0.0.2:0", cert)
	port := good.Addr().(*net.TCPAddr).Port
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	stallTCP(t, addr)

	stalled := netip.MustParseAddr("127.0.0.1")
	healthy := netip.MustParseAddr("127.0.0.2")

	d := New(Options{
		Resolver:   staticResolver{stalled, healthy},
		TLSTimeout: 800 * time.Millisecond,
		Stagger:    20 * time.Millisecond,
		TLSConfig:  &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	})

	start := time.Now()
	conn, err := d.DialTLSContext(context.Background(), "tcp", fmt.Sprintf("github.com:%d", port))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("拨号失败：%v（耗时 %v）", err, elapsed)
	}
	defer conn.Close()

	if elapsed > time.Second {
		t.Fatalf("竞速没有甩开黑洞候选，耗时 %v", elapsed)
	}
	if got, want := conn.RemoteAddr().(*net.TCPAddr).IP.String(), "127.0.0.2"; got != want {
		t.Fatalf("赢家应该是好地址，实际 %s", got)
	}
	if got := d.rankFor(healthy); got != 0 {
		t.Fatalf("握手成功的候选应记为验证可用（rank 0），实际 %d", got)
	}
	// 输在竞速里被 cancel 的候选不能判死刑：它只是没跑完，没证据说明它不能用。
	if got := d.rankFor(stalled); got == 2 {
		t.Fatalf("被竞速取消的候选不该记成验证失败，实际 rank %d", got)
	}
}

// 只有黑洞候选时，失败必须立刻落到"已验证失败"档——否则下一次竞速还会
// 优先派它上场，每个请求都要白等一次握手超时。
func TestDialTLSMarksStalledCandidateFailed(t *testing.T) {
	ln := stallTCP(t, "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	stalled := netip.MustParseAddr("127.0.0.1")

	d := New(Options{
		Resolver:   staticResolver{stalled},
		TLSTimeout: 300 * time.Millisecond,
	})
	start := time.Now()
	conn, err := d.DialTLSContext(context.Background(), "tcp", fmt.Sprintf("github.com:%d", port))
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatalf("黑洞候选不该拨号成功")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("失败得太慢：%v（TLSTimeout 300ms 应该兜住）", elapsed)
	}
	if got := d.rankFor(stalled); got != 2 {
		t.Fatalf("TLS 卡死的候选应被记为验证失败（rank 2），实际 %d", got)
	}
}

// 好地址排在 MaxCandidates 之后（种子表 24 个、前面一批全死）时不能直接
// 放弃——必须接着赌下一批，否则整个域名永久 502。
func TestDialFallsBackToNextBatch(t *testing.T) {
	const n = 13
	target := fmt.Sprintf("127.0.0.%d", n)
	ln, err := net.Listen("tcp", target+":0")
	if err != nil {
		t.Fatalf("监听 %s：%v", target, err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	var addrs []netip.Addr
	for i := 1; i <= n; i++ {
		addrs = append(addrs, netip.MustParseAddr(fmt.Sprintf("127.0.0.%d", i)))
	}
	d := New(Options{
		Resolver:      staticResolver(addrs),
		MaxCandidates: 12, // 第 13 个（唯一活着的）落在第二批
		Timeout:       300 * time.Millisecond,
		Stagger:       time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("github.com:%d", port))
	if err != nil {
		t.Fatalf("第二批没被尝试：%v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().(*net.TCPAddr).IP.String(); got != target {
		t.Fatalf("应该连到 %s，实际 %s", target, got)
	}
}

// "已验证失败"档不能是永久放逐。档位是竞速自己写出来的，一次响应头超时就会
// 把一个其实健康的地址打成 rank 2；如果此后只跑"可用"那批，而唯一"可用"的
// 候选恰好在抖动，整个域名就一直是 502。这里把唯一健康地址先打成 rank 2，
// 只留一个卡死的"可用"候选：拨号必须跑完 usable 之后回头赌 failed。
func TestDialFallsBackToFailedCandidates(t *testing.T) {
	cert, pool := selfSigned(t, "github.com")
	good := serveTLS(t, "127.0.0.2:0", cert)
	port := good.Addr().(*net.TCPAddr).Port
	stallTCP(t, fmt.Sprintf("127.0.0.1:%d", port))

	stalled := netip.MustParseAddr("127.0.0.1")
	healthy := netip.MustParseAddr("127.0.0.2")

	d := New(Options{
		Resolver:   staticResolver{stalled, healthy},
		TLSTimeout: 300 * time.Millisecond,
		Stagger:    20 * time.Millisecond,
		TLSConfig:  &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	})
	d.Penalize(healthy) // 健康地址先被打成"已验证失败"
	if got := d.rankFor(healthy); got != 2 {
		t.Fatalf("前置条件不成立：healthy 应该是 rank 2，实际 %d", got)
	}

	conn, err := d.DialTLSContext(context.Background(), "tcp", fmt.Sprintf("github.com:%d", port))
	if err != nil {
		t.Fatalf("失败的档位把唯一健康地址永久放逐了：%v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.2" {
		t.Fatalf("应该回落到 127.0.0.2，实际 %s", got)
	}
	if got := d.rankFor(healthy); got != 0 {
		t.Fatalf("重新握手成功应把档位洗回 rank 0，实际 %d", got)
	}
}

// 一次竞速成功后，同域名后续拨号必须优先直连那个 IP，而不是每次都重新
// 拉起一整轮竞速：浏览器一个页面几十个连接，每个连接再打 12 个 SYN，本机
// 会被自己的竞速淹掉，连本来 0.1s 能连上的地址也会超时（线上 20 并发
// 70% 502 的形态）。这里用 accept 计数证明第二次根本没去碰别的候选。
func TestDialReusesStickyIP(t *testing.T) {
	cert, pool := selfSigned(t, "github.com")
	good := serveTLS(t, "127.0.0.2:0", cert)
	port := good.Addr().(*net.TCPAddr).Port

	var mu sync.Mutex
	accepts := 0
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("监听：%v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			mu.Lock()
			accepts++
			mu.Unlock()
			held = append(held, c) // 只 accept 不回话，模拟黑洞
		}
	}()

	d := New(Options{
		Resolver:   staticResolver{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")},
		TLSTimeout: 400 * time.Millisecond,
		Stagger:    20 * time.Millisecond,
		TLSConfig:  &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	})
	target := fmt.Sprintf("github.com:%d", port)

	first, err := d.DialTLSContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("第一次拨号失败：%v", err)
	}
	_ = first.Close()

	mu.Lock()
	before := accepts
	mu.Unlock()

	second, err := d.DialTLSContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatalf("第二次拨号失败：%v", err)
	}
	defer second.Close()

	mu.Lock()
	after := accepts
	mu.Unlock()
	if after != before {
		t.Fatalf("第二次拨号又去摸了别的候选（accept %d -> %d），粘性快路没生效", before, after)
	}
	if got := second.RemoteAddr().(*net.TCPAddr).IP.String(); got != "127.0.0.2" {
		t.Fatalf("第二次应该直连 127.0.0.2，实际 %s", got)
	}
}
