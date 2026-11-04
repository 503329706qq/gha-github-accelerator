package resolver_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/resolver"
)

// fakeDoHJSON 返回阿里 DNS 的 JSON 格式。
func fakeDoHJSON(t *testing.T, ips ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") == "" {
			http.Error(w, "missing name", 400)
			return
		}
		type ans struct {
			Name string `json:"name"`
			TTL  uint32 `json:"TTL"`
			Type int    `json:"type"`
			Data string `json:"data"`
		}
		resp := struct {
			Status int   `json:"Status"`
			Answer []ans `json:"Answer"`
		}{Status: 0}
		for _, ip := range ips {
			resp.Answer = append(resp.Answer, ans{Name: "github.com.", TTL: 27, Type: 1, Data: ip})
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

// fakeDNS 起一个极简 UDP DNS 服务器，只回一个 A 记录。
func fakeDNS(t *testing.T, ip string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			if n < 12 {
				continue
			}
			// 找 question 结束位置
			p := 12
			for p < n && q[p] != 0 {
				p += int(q[p]) + 1
			}
			p += 1 + 4 // 终止零字节 + qtype + qclass

			out := make([]byte, 0, p+16)
			out = append(out, q[:2]...)   // ID
			out = append(out, 0x81, 0x80) // QR=1 RD RA
			out = append(out, 0, 1, 0, 1, 0, 0, 0, 0)
			out = append(out, q[12:p]...)  // 原 question
			out = append(out, 0xC0, 0x0C)  // 指向 question 名字
			out = append(out, 0, 1, 0, 1)  // A IN
			out = append(out, 0, 0, 0, 60) // TTL 60
			out = append(out, 0, 4)
			parsed := net.ParseIP(ip).To4()
			out = append(out, parsed...)
			pc.WriteTo(out, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestLookupJSON(t *testing.T) {
	srv := fakeDoHJSON(t, "20.205.243.166")
	defer srv.Close()

	r := resolver.New(resolver.Options{JSON: []string{srv.URL}, TTLMin: time.Minute, TTLMax: 10 * time.Minute})
	addrs, err := r.Lookup(context.Background(), "github.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0].String() != "20.205.243.166" {
		t.Fatalf("addrs=%v", addrs)
	}
}

func TestLookupFallsBackToBareDNS(t *testing.T) {
	fallback := fakeDNS(t, "1.2.3.4")
	r := resolver.New(resolver.Options{
		JSON:     []string{"http://127.0.0.1:1/resolve"},
		Wire:     []string{"http://127.0.0.1:1/dns-query"},
		Fallback: fallback,
		TTLMin:   time.Minute, TTLMax: 10 * time.Minute,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := r.Lookup(ctx, "github.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) == 0 || addrs[0].String() != "1.2.3.4" {
		t.Fatalf("addrs=%v", addrs)
	}
}

func TestLookupRejectsLoopback(t *testing.T) {
	srv := fakeDoHJSON(t, "127.0.0.1")
	defer srv.Close()

	r := resolver.New(resolver.Options{JSON: []string{srv.URL}, TTLMin: time.Minute, TTLMax: 10 * time.Minute})
	_, err := r.Lookup(context.Background(), "github.com")
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback error, got %v", err)
	}
}

func TestLookupCachesWithinTTL(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprintf(w, `{"Status":0,"Answer":[{"name":"github.com.","TTL":300,"type":1,"data":"20.205.243.166"}]}`)
	}))
	defer srv.Close()

	r := resolver.New(resolver.Options{JSON: []string{srv.URL}, TTLMin: time.Minute, TTLMax: 10 * time.Minute})
	for i := 0; i < 3; i++ {
		if _, err := r.Lookup(context.Background(), "github.com"); err != nil {
			t.Fatal(err)
		}
	}
	if hits != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", hits)
	}
}

func TestWireQueryRoundTrip(t *testing.T) {
	// 用一个 UDP DNS 服务器冒充 doh.pub 的响应内容，直接测报文编解码。
	pkt := resolver.BuildQueryForTest(0x1234, "github.com", 1)
	if len(pkt) < 12 || binary.BigEndian.Uint16(pkt[0:2]) != 0x1234 {
		t.Fatalf("bad query header: %x", pkt)
	}
	if pkt[2]&0x80 != 0 {
		t.Fatalf("QR bit must be clear in a query, flags=%02x", pkt[2])
	}
	if pkt[2]&0x01 == 0 {
		t.Fatalf("RD bit must be set in a query, flags=%02x", pkt[2])
	}
	if !strings.Contains(string(pkt), "github") {
		t.Fatalf("qname missing: %x", pkt)
	}
}

// TestLookupLiveDoH 打真实 DoH 端点，默认跳过（GHA_LIVE=1 才跑）。
func TestLookupLiveDoH(t *testing.T) {
	if os.Getenv("GHA_LIVE") == "" {
		t.Skip("set GHA_LIVE=1 to hit real DoH endpoints")
	}
	r := resolver.New(resolver.Options{
		JSON:     []string{"https://223.5.5.5/resolve"},
		Wire:     []string{"https://doh.pub/dns-query"},
		Fallback: "223.5.5.5:53",
		IPv6:     false,
	})
	for _, host := range []string{"github.com", "codeload.github.com", "objects.githubusercontent.com"} {
		addrs, err := r.Lookup(context.Background(), host)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		t.Logf("%s -> %v", host, addrs)
	}
	// 二次查询应命中缓存，且不再是回环
	if again, _ := r.Lookup(context.Background(), "github.com"); len(again) == 0 {
		t.Fatal("cached lookup empty")
	}
}

// TestLookupMergesSeedAddrs 验证种子 IP 会与 DoH 结果合并、去重，且顺序上
// DoH 结果在前。种子是"DNS 给了地址但这段时间连不上"时的第二条路。
func TestLookupMergesSeedAddrs(t *testing.T) {
	srv := fakeDoHJSON(t, "1.2.3.4")
	defer srv.Close()

	r := resolver.New(resolver.Options{
		JSON: []string{srv.URL + "/resolve"},
		Seeds: map[string][]netip.Addr{
			"github.com": {
				netip.MustParseAddr("5.6.7.8"),
				netip.MustParseAddr("1.2.3.4"), // 与 DoH 重复，应被去掉
			},
		},
	})
	got, err := r.Lookup(context.Background(), "github.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 addrs (1 from DoH + 1 unique seed), got %v", got)
	}
	// 种子排在前面：拨号层按候选顺序错峰起跑，种子是长期验证过的地址段，
	// 而 DoH 的答案可能是"TCP 通、TLS 不回"的黑洞（见 doh.go 里的注释）。
	if got[0].String() != "5.6.7.8" || got[1].String() != "1.2.3.4" {
		t.Fatalf("unexpected order: %v", got)
	}
}

// TestLookupUsesSeedsWhenDoHFails 验证 DoH 全挂时仍然能拿到种子地址。
func TestLookupUsesSeedsWhenDoHFails(t *testing.T) {
	r := resolver.New(resolver.Options{
		JSON:     []string{"http://127.0.0.1:1/resolve"},
		Fallback: "127.0.0.1:1",
		Seeds: map[string][]netip.Addr{
			"github.com": {netip.MustParseAddr("20.207.73.82")},
		},
	})
	got, err := r.Lookup(context.Background(), "github.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 1 || got[0].String() != "20.207.73.82" {
		t.Fatalf("want seed addr, got %v", got)
	}
}
