package dialer_test

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/dialer"
)

// fakeResolver 返回固定地址列表。
type fakeResolver struct {
	addrs []netip.Addr
	err   error
}

func (f *fakeResolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return f.addrs, f.err
}

// listen 起一个本地 TCP 监听，返回端口。
func listen(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln, ln.Addr().String()
}

func TestDialUsesResolverAndRecords(t *testing.T) {
	_, addr := listen(t)
	port := addr[len("127.0.0.1:"):]

	d := dialer.New(dialer.Options{
		Resolver: &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		Timeout:  time.Second,
		Stagger:  10 * time.Millisecond,
	})
	conn, err := d.DialContext(context.Background(), "tcp", "github.com:"+port)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	if n := d.Stats(); n == 0 {
		t.Fatal("expected at least one recorded dial stat")
	}
}

func TestDialFailsOverToLiveCandidate(t *testing.T) {
	_, addr := listen(t)
	port := addr[len("127.0.0.1:"):]

	// 127.0.0.2 上没有监听 → 立刻被拒；应当自动落到 127.0.0.1。
	d := dialer.New(dialer.Options{
		Resolver: &fakeResolver{addrs: []netip.Addr{
			netip.MustParseAddr("127.0.0.2"),
			netip.MustParseAddr("127.0.0.1"),
		}},
		Timeout: time.Second,
		Stagger: 10 * time.Millisecond,
	})
	conn, err := d.DialContext(context.Background(), "tcp", "github.com:"+port)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDialStaggersInsteadOfWaitingForTimeout(t *testing.T) {
	_, addr := listen(t)
	port := addr[len("127.0.0.1:"):]

	// 192.0.2.1 是 TEST-NET，握手会一直等到超时；第二个候选在 50ms 后加入竞速。
	d := dialer.New(dialer.Options{
		Resolver: &fakeResolver{addrs: []netip.Addr{
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("127.0.0.1"),
		}},
		Timeout: 3 * time.Second,
		Stagger: 50 * time.Millisecond,
	})
	start := time.Now()
	conn, err := d.DialContext(context.Background(), "tcp", "github.com:"+port)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dial failed after %v: %v", elapsed, err)
	}
	conn.Close()
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("staggering did not help: waited %v", elapsed)
	}
}

func TestDialHonoursContextCancel(t *testing.T) {
	d := dialer.New(dialer.Options{
		Resolver: &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
		Timeout:  5 * time.Second,
		Stagger:  time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := d.DialContext(ctx, "tcp", "github.com:443"); err == nil {
		t.Fatal("expected error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("context cancel ignored, waited %v", elapsed)
	}
}

func TestScorePrefersFastAndFat(t *testing.T) {
	fast := dialer.Score(50*time.Millisecond, 3<<20)
	slow := dialer.Score(400*time.Millisecond, 3<<20)
	thin := dialer.Score(400*time.Millisecond, 50<<10)

	if !(fast > slow) {
		t.Fatalf("latency not weighted: fast=%v slow=%v", fast, slow)
	}
	if !(slow > thin) {
		t.Fatalf("throughput not weighted: slow=%v thin=%v", slow, thin)
	}
	if dialer.Score(0, 0) <= 0 {
		t.Fatal("unrecorded candidate should still get a positive neutral score")
	}
}

func TestRecordThroughputMovesScore(t *testing.T) {
	d := dialer.New(dialer.Options{Resolver: &fakeResolver{}, Timeout: time.Second, Stagger: time.Millisecond})
	ip := netip.MustParseAddr("185.199.108.133")
	before := d.ScoreFor(ip)
	d.RecordThroughput(ip, 4<<20, 500*time.Millisecond) // 8MB/s
	after := d.ScoreFor(ip)
	if !(after > before) {
		t.Fatalf("throughput did not improve score: before=%v after=%v", before, after)
	}
}

// TestDialExcludesFailedCandidates 验证核心修复：黑洞地址（TCP 能连、应用层死）
// 被 Penalize 标成 rank 2 后，竞速应跳过它、直连好地址，而不是让它凭假快的
// TCP 握手抢走竞速。两个 loopback 监听同一端口、不同 IP 来模拟"黑洞 vs 好地址"。
func TestDialExcludesFailedCandidates(t *testing.T) {
	// 先监听 127.0.0.2 拿到一个端口，再用同一端口监听 127.0.0.1。
	ln2, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("127.0.0.2 not available: %v", err)
	}
	port := ln2.Addr().(*net.TCPAddr).Port
	ln1, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln1.Close(); ln2.Close() })
	acceptAll := func(ln net.Listener) {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	acceptAll(ln1)
	acceptAll(ln2)

	d := dialer.New(dialer.Options{
		Resolver: &fakeResolver{addrs: []netip.Addr{
			netip.MustParseAddr("127.0.0.2"), // 黑洞，rank 2
			netip.MustParseAddr("127.0.0.1"), // 好地址，rank 1
		}},
		Timeout: time.Second,
		Stagger: 10 * time.Millisecond,
	})
	d.Penalize(netip.MustParseAddr("127.0.0.2"))

	conn, err := d.DialContext(context.Background(), "tcp", "github.com:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected remote addr type %T", conn.RemoteAddr())
	}
	if got := remote.IP.String(); got != "127.0.0.1" {
		t.Fatalf("expected to dial good IP 127.0.0.1 (blackhole excluded), got %s", got)
	}
}
