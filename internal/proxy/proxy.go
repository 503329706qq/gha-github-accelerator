// Package proxy 是加速器的核心：在 127.0.0.1:443 上接住 GitHub 的 TLS 连接，
// 用自己的叶证书终结 TLS，再把请求转发到真正的 GitHub。
//
// 为什么值得这样做：直连时每个连接都要跨境握手（本机实测 TLS 1.34s），而
// 终结在本机之后，浏览器与本机之间只有一次本地握手；到 GitHub 的连接则由
// Transport 池化复用。实测同一个 codeload 包从 340KB/s 提到 782KB/s。
//
// 白名单之外的 SNI 一律原样透传（不终结 TLS、不解密），这样即使 hosts 里
// 混进了别的站点（商店、镜像、包管理器之类）不该接管的域名，也不会把它们弄坏。
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/ca"
	"github.com/503329706qq/gha-github-accelerator/internal/log"
	"github.com/503329706qq/gha-github-accelerator/internal/sni"
)

// Options 配置代理。
type Options struct {
	CA    *ca.CA
	Allow func(host string) bool
	Dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	// DialTLS 负责"拨号 + TLS 握手"整条路（可为 nil：nil 时退回 Dial + 标准库
	// 自带的握手，测试替身用得上）。生产接 dialer.DialTLSContext：只有把 TLS
	// 也放进竞速，才能让"TCP 立刻连上、之后一个字节不回"的黑洞地址在 2.5s
	// 内自己出局，而不是让整个请求卡到 8s 预算耗尽再 502。
	DialTLS     func(ctx context.Context, network, addr string) (net.Conn, error)
	Passthrough func(ctx context.Context, host string) (net.Conn, error)
	Logger      *log.Logger
	OnRequest   func(host string, bytes int64, dur time.Duration, status int)
	// OnUpstreamError 在一次上游请求最终失败（重试耗尽、即将 502）时回调，
	// host 是目标域名。run 层用它对失败域名做去抖的按需探测，把长尾域名
	// （avatars 之类从不预热的主机）补进拨号评分。
	OnUpstreamError func(host string, err error)
	// OnUpstreamIPFail 在一次上游尝试失败时收到该次真正拨到的 IP；
	// run 层把它接到 dialer.Penalize，让下一次竞速避开这个地址。
	OnUpstreamIPFail func(ip netip.Addr, err error)
	// OnUpstreamIPOK 在一次上游尝试拿到响应头时收到真正拨到的 IP；run 层把它
	// 接到 dialer.Praise，把"这条路真的能干活"的地址记成粘性。
	OnUpstreamIPOK func(ip netip.Addr)
	// UpstreamRootCAs 只用于测试替身上游；生产留空即用系统根证书。
	UpstreamRootCAs *x509.CertPool
}

// Server 是一个已经在跑的本地反向代理。
type Server struct {
	o       Options
	tr      *http.Transport
	rp      *httputil.ReverseProxy
	https   *http.Server
	plain   *http.Server
	once    sync.Once
	mu      sync.Mutex
	closers []io.Closer
}

// New 构造代理（还没开始监听）。
func New(o Options) *Server {
	if o.Passthrough == nil {
		o.Passthrough = func(ctx context.Context, host string) (net.Conn, error) {
			if o.Dial == nil {
				return nil, errors.New("proxy: no dialer")
			}
			return o.Dial(ctx, "tcp", net.JoinHostPort(host, "443"))
		}
	}
	if o.Allow == nil {
		o.Allow = func(string) bool { return false }
	}

	s := &Server{o: o}
	s.tr = &http.Transport{
		DialContext: o.Dial,
		// DialTLS 非 nil 时由它一把做完"拨号 + TLS"，Transport 不再自己握手
		// （TLSClientConfig 也就不再生效）。这是把黑洞地址挡在请求之外的关键：
		// 见 dialer.DialTLSContext 的说明。
		DialTLSContext: o.DialTLS,
		// 上游强制 HTTP/1.1。2026-11-03 实测：h2 的连接多路复用会把一条
		// 被黑洞的上游连接放大成同一 host 的全部并发请求一起超时
		// （"http2: timeout awaiting response headers"成批出现），而且逐请求
		// 重试逃不出被复用的那条连接。h1 下每个请求独立连接，重试才能真正
		// 换连接换 IP。代价是每条新连接一次 TLS 握手，连接池（64/host）仍在。
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        300,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     120 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// 3 秒拿不到响应头就当这个上游 IP 是黑洞，交给 retryTransport 换一个。
		ResponseHeaderTimeout: 3 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.UpstreamRootCAs},
	}
	s.rp = &httputil.ReverseProxy{
		Rewrite: s.rewrite,
		// 单次尝试受 ResponseHeaderTimeout（3s）约束、最多 4 次、总预算 12s：
		// GitHub 正常首字节在 1 秒内，3 秒还没动静基本就是黑洞地址，
		// 立刻换下一个重试（见 retry.go 的说明）。
		Transport: &retryTransport{
			base:     s.tr,
			attempts: 4,
			onRetry: func(format string, args ...any) {
				if o.Logger != nil {
					o.Logger.Debug(format, args...)
				}
			},
			onFail: func(ip netip.Addr, err error) {
				if o.OnUpstreamIPFail != nil {
					o.OnUpstreamIPFail(ip, err)
				}
			},
			onOK: func(ip netip.Addr) {
				if o.OnUpstreamIPOK != nil {
					o.OnUpstreamIPOK(ip)
				}
			},
			onDegraded: func(host string, failures int) {
				if o.Logger != nil {
					o.Logger.Error("upstream 链路级故障 host=%s：短时间内 %d 次尝试都拿不到响应，%s 内改为单次尝试快速失败",
						host, failures, degradedWindow)
				}
			},
		},
		FlushInterval: 100 * time.Millisecond,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if o.Logger != nil {
				o.Logger.Error("upstream error host=%s path=%s: %v", r.Host, r.URL.Path, err)
			}
			if o.OnUpstreamError != nil {
				o.OnUpstreamError(r.Host, err)
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	s.https = &http.Server{
		Handler: http.HandlerFunc(s.handle),
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
			GetCertificate: s.getCertificate,
		},
		ReadHeaderTimeout: 15 * time.Second,
	}
	s.plain = &http.Server{
		Handler:           http.HandlerFunc(s.redirect),
		ReadHeaderTimeout: 15 * time.Second,
	}
	return s
}

// rewrite 把请求改写成发往真实 GitHub 的请求，但保留客户端带来的 Host。
func (s *Server) rewrite(pr *httputil.ProxyRequest) {
	host := hostOnly(pr.In.Host)
	pr.Out.URL.Scheme = "https"
	pr.Out.URL.Host = host
	// Host 头统一用主机名、不带端口：生产上端口就是 443，但自测会跑在 18443，
	// 把 ":18443" 透给 GitHub 会让它回 301 到无端口地址（浏览器再走一次握手，白费一个 RTT）。
	pr.Out.Host = host
}

// getCertificate 在握手中按 SNI 现签一张叶证书。
func (s *Server) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(hello.ServerName)
	if name == "" || !s.o.Allow(name) {
		return nil, fmt.Errorf("proxy: refuse certificate for SNI %q", hello.ServerName)
	}
	return s.o.CA.LeafFor(name)
}

// handle 处理已经解密的 HTTPS 请求。
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if host == "" || !s.o.Allow(host) {
		http.Error(w, "gha: host not accelerated", http.StatusMisdirectedRequest)
		return
	}
	start := time.Now()
	cw := &countingWriter{ResponseWriter: w, status: http.StatusOK}
	s.rp.ServeHTTP(cw, r)
	d := time.Since(start)
	if s.o.Logger != nil {
		// 每个请求一行，便于事后算吞吐、定位是哪个资源慢；query 里的敏感项由 logger 脱敏。
		s.o.Logger.Request(host, r.Method, r.URL.Path, r.URL.RawQuery, cw.status, cw.n, d, clientIP(r))
	}
	if s.o.OnRequest != nil {
		s.o.OnRequest(host, cw.n, d, cw.status)
	}
}

// clientIP 从 RemoteAddr 里取客户端地址（去掉端口）。
func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// redirect 把 80 端口的明文请求重定向到 HTTPS——GitHub 自己也是这么做的，
// 但 hosts 指过来之后必须由我们补上这一步。
func (s *Server) redirect(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if host == "" || !s.o.Allow(host) {
		http.Error(w, "gha: host not accelerated", http.StatusNotFound)
		return
	}
	target := "https://" + host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// ServeTLS 在 ln 上跑 443 端的服务：允许的 SNI 走终结，其余原样透传。
func (s *Server) ServeTLS(ln net.Listener) error {
	s.addCloser(ln)
	err := s.https.ServeTLS(&decisionListener{ln: ln, s: s}, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeHTTP 在 ln 上跑 80 端的重定向服务。
func (s *Server) ServeHTTP(ln net.Listener) error {
	s.addCloser(ln)
	err := s.plain.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) addCloser(c io.Closer) {
	s.mu.Lock()
	s.closers = append(s.closers, c)
	s.mu.Unlock()
}

// Close 关掉两个监听与所有上游空闲连接。
func (s *Server) Close() error {
	var first error
	s.once.Do(func() {
		if err := s.https.Close(); err != nil {
			first = err
		}
		_ = s.plain.Close()
		s.tr.CloseIdleConnections()
		s.mu.Lock()
		for _, c := range s.closers {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	return first
}

// decisionListener 在 Accept 里就做完"终结还是透传"的判断。
// 透传的连接不交给 http.Server，直接自己转发了。
type decisionListener struct {
	ln net.Listener
	s  *Server
}

func (l *decisionListener) Accept() (net.Conn, error) {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return nil, err
		}
		pc, name, err := inspect(c)
		if err != nil {
			// 静默关连接会让"某些客户端 TLS 老是被重置"变成玄学问题，至少留一条 debug。
			if l.s.o.Logger != nil {
				l.s.o.Logger.Debug("inspect %s: %v", c.RemoteAddr(), err)
			}
			c.Close()
			continue
		}
		if name != "" && l.s.o.Allow(name) {
			return pc, nil
		}
		go l.s.passthrough(pc, name)
	}
}

func (l *decisionListener) Close() error   { return l.ln.Close() }
func (l *decisionListener) Addr() net.Addr { return l.ln.Addr() }

// passthrough 把白名单外的连接原样搬到真实服务器：不终结 TLS、不解密。
func (s *Server) passthrough(c net.Conn, name string) {
	defer c.Close()
	if name == "" {
		return // 没有 SNI 就没有目标，只能放弃
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	up, err := s.o.Passthrough(ctx, name)
	if err != nil {
		if s.o.Logger != nil {
			s.o.Logger.Debug("passthrough %s failed: %v", name, err)
		}
		return
	}
	defer up.Close()

	// 两个方向各自半关闭：客户端写完请求就 shutdown(SHUT_WR) 是合法行为，
	// 这时不能立刻把两端都关掉，否则上行的响应会被截断。
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, c)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, up)
		closeWrite(c)
		done <- struct{}{}
	}()
	<-done
	// 另一方向通常马上就结束；给个上限，别让慢连接把 goroutine 挂死。
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

// closeWrite 尽力做半关闭；不支持的类型就什么都不做（由 defer Close 兜底）。
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// prefixConn 把已经 peek 过的字节接回 Read。
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// inspect 读够一个 TLS 记录并解析出 SNI。
func inspect(c net.Conn) (*prefixConn, string, error) {
	// 这里在 Accept 的串行路径上：一条"连上但不发数据"的连接（浏览器空闲预连接、
	// 端口扫描、半开 socket）如果无限等下去，整个 443 面就冻住了。必须有读超时。
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	// 缓冲要能装下整个 record（上限 16KB）+ 头；浏览器带 PQ key_share 的
	// ClientHello 已经能到 2–3KB，4096 的老值连 ErrBufferFull 都来不及报。
	pc := &prefixConn{Conn: c, r: bufio.NewReaderSize(c, 32*1024)}
	hdr, err := pc.r.Peek(5)
	if err != nil {
		return nil, "", err
	}
	if hdr[0] != 0x16 {
		return nil, "", errors.New("proxy: not a TLS handshake")
	}
	total := 5 + int(hdr[3])<<8 + int(hdr[4])
	if total > 16384+5 {
		return nil, "", errors.New("proxy: TLS record too large")
	}
	buf, err := pc.r.Peek(total)
	if err != nil {
		return nil, "", err
	}
	name, need, err := sni.ParseClientHello(buf)
	if err != nil {
		return nil, "", err
	}
	if need > 0 {
		return nil, "", fmt.Errorf("proxy: incomplete ClientHello (need %d more bytes)", need)
	}
	// 交出去之前清掉截止时间，否则握手/传输会带着这个 3 秒的期限。
	_ = c.SetReadDeadline(time.Time{})
	return pc, strings.ToLower(name), nil
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// countingWriter 记录回给客户端的字节数与状态码，用来喂吞吐评分。
type countingWriter struct {
	http.ResponseWriter
	n      int64
	status int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.n += int64(n)
	return n, err
}

func (w *countingWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Flush 让 ReverseProxy 的流式刷新（FlushInterval）继续生效。
func (w *countingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

var _ = url.URL{}
