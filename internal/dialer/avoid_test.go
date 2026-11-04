package dialer

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// 粘性记录必须能被上游失败摘掉：否则"TCP 通、TLS 通、就是不吐响应头"的地址
// 会被每个请求先试一次、重试再试三次，8 秒预算就这么烧成 502。
func TestPenalizeDropsSticky(t *testing.T) {
	ip := netip.MustParseAddr("20.27.177.113")
	d := New(Options{Resolver: staticResolver{ip}})
	d.markGood("github.com", ip)

	if got, ok := d.goodFor("github.com"); !ok || got != ip {
		t.Fatalf("markGood 之后 goodFor 应命中 %s，实际 %s ok=%v", ip, got, ok)
	}

	d.Penalize(ip)

	if got, ok := d.goodFor("github.com"); ok {
		t.Fatalf("Penalize 之后 goodFor 不应再命中，实际拿到 %s", got)
	}
	if !d.avoided(ip) {
		t.Fatal("Penalize 之后该地址应进入回避窗口")
	}
}

// 刚失败过的地址不能再出现在"可用"组里——这是"重试换一个 IP"的前提；
// 但它要留在 failed 组当最后的赌注（见 TestDialFallsBackToFailedCandidates）。
func TestCandidatesSkipRecentFailure(t *testing.T) {
	bad := netip.MustParseAddr("20.27.177.113")
	good := netip.MustParseAddr("20.200.245.247")
	d := New(Options{Resolver: staticResolver{bad, good}})
	d.Penalize(bad)

	usable, failed, err := d.candidates(context.Background(), "github.com")
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	for _, a := range usable {
		if a == bad {
			t.Fatalf("回避窗口内的 %s 不该出现在 usable 组（usable=%v）", bad, usable)
		}
	}
	if len(usable) != 1 || usable[0] != good {
		t.Fatalf("usable 组应只剩好地址 %s，实际 %v", good, usable)
	}
	inFailed := false
	for _, a := range failed {
		if a == bad {
			inFailed = true
		}
	}
	if !inFailed {
		t.Fatalf("被惩罚的 %s 应留在 failed 组做兜底，实际 failed=%v", bad, failed)
	}
}

// 全部候选都在回避窗口时，不能用"没有可用候选"直接失败——把整批当兜底。
func TestCandidatesKeepAllWhenAllAvoided(t *testing.T) {
	a := netip.MustParseAddr("20.27.177.113")
	b := netip.MustParseAddr("20.200.245.247")
	d := New(Options{Resolver: staticResolver{a, b}})
	d.Penalize(a)
	d.Penalize(b)

	usable, failed, err := d.candidates(context.Background(), "github.com")
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(usable) != 0 {
		t.Fatalf("全部回避时 usable 应为空，实际 %v", usable)
	}
	if len(failed) != 2 {
		t.Fatalf("全部回避时应整批落进 failed 组，实际 %v", failed)
	}
}

// 实测发现的额外地址（同 /24 邻居）要能和解析结果一起进候选池。
func TestCandidatesIncludeExtra(t *testing.T) {
	known := netip.MustParseAddr("140.82.112.3")
	extra := netip.MustParseAddr("140.82.112.5")
	d := New(Options{Resolver: staticResolver{known}})
	d.AddCandidate("github.com", extra)

	usable, failed, err := d.candidates(context.Background(), "github.com")
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	found := false
	for _, a := range append(append([]netip.Addr{}, usable...), failed...) {
		if a == extra {
			found = true
		}
	}
	if !found {
		t.Fatalf("额外候选 %s 应出现在候选池里（usable=%v failed=%v）", extra, usable, failed)
	}
}

// 响应成功才立粘性：Praise 要把地址立成该域名的粘性地址、清掉回避标记、
// 并把档位洗回"已验证可用"。
func TestPraiseSetsStickyAndClearsAvoid(t *testing.T) {
	ip := netip.MustParseAddr("20.27.177.113")
	d := New(Options{Resolver: staticResolver{ip}})
	d.bindHost("github.com", ip)
	d.Penalize(ip)

	if _, ok := d.goodFor("github.com"); ok {
		t.Fatal("前置条件：Penalize 之后不该有粘性记录")
	}

	d.Praise(ip)

	got, ok := d.goodFor("github.com")
	if !ok || got != ip {
		t.Fatalf("Praise 之后应立粘性 %s，实际 %s ok=%v", ip, got, ok)
	}
	if d.avoided(ip) {
		t.Fatal("Praise 应清掉回避窗口")
	}
	if r := d.rankFor(ip); r != 0 {
		t.Fatalf("Praise 之后档位应为 0（已验证可用），实际 %d", r)
	}
}

// 额外地址会被登记、进候选池，并在超时后过期。
func TestExtraCandidateExpires(t *testing.T) {
	d := New(Options{Resolver: staticResolver{}})
	ip := netip.MustParseAddr("20.205.243.161")
	d.AddCandidate("github.com", ip)

	d.mu.Lock()
	d.extra["github.com"][ip] = time.Now().Add(-extraTTL - time.Minute)
	d.mu.Unlock()

	if got := d.extraFor("github.com"); len(got) != 0 {
		t.Fatalf("过期的额外候选应被剔除，实际 %v", got)
	}
}
