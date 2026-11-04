package dialer

import (
	"net/netip"
	"testing"
	"time"
)

// 一次瞬时失败会把延迟 EWMA 推到 3 秒。如果这个惩罚永远不淡化，
// 一个只是当时抖了一下的 IP 会被永久排在候选队尾。5 分钟后应明显回血。
func TestScoreForDecaysStalePenalty(t *testing.T) {
	d := New(Options{})
	ip := netip.MustParseAddr("192.0.2.9")

	d.mu.Lock()
	d.stats[ip] = &stat{lat: 3 * time.Second, dials: 3, at: time.Now()}
	d.mu.Unlock()
	fresh := d.ScoreFor(ip)

	d.mu.Lock()
	d.stats[ip].at = time.Now().Add(-30 * time.Minute)
	d.mu.Unlock()
	aged := d.ScoreFor(ip)

	if aged <= fresh {
		t.Fatalf("stale penalty did not decay: fresh=%v aged=%v", fresh, aged)
	}
	// 快速 IP（延迟低于中性值）不该被"衰减"逻辑拖慢。
	d.mu.Lock()
	d.stats[ip] = &stat{lat: 20 * time.Millisecond, dials: 3, at: time.Now().Add(-time.Hour)}
	d.mu.Unlock()
	if got, want := d.ScoreFor(ip), Score(20*time.Millisecond, 0); got != want {
		t.Fatalf("fast IP altered by decay: got=%v want=%v", got, want)
	}
}

// 黑洞地址的 TCP 握手照样成功（还更快），但应用层一个字节都读不到。修复目标：
// TCP 拨号成功只能更新延迟，不能写 probed/ok——否则下一次竞速会把探测识别出的
// "应用层失败"结论覆盖掉，黑洞 IP 又凭假快的握手抢回第一位。
func TestRecordDialDoesNotSetProbeRank(t *testing.T) {
	d := New(Options{})
	ip := netip.MustParseAddr("192.0.2.1")
	d.recordDial(ip, 100*time.Millisecond, true)
	if got := d.rankFor(ip); got != 1 {
		t.Fatalf("TCP dial success must stay rank 1 (unknown), got %d", got)
	}
}

func TestRecordProbeSetsRank(t *testing.T) {
	d := New(Options{})
	ip := netip.MustParseAddr("192.0.2.1")
	d.recordProbe(ip, 100*time.Millisecond, true)
	if got := d.rankFor(ip); got != 0 {
		t.Fatalf("probe ok should give rank 0, got %d", got)
	}
	d.recordProbe(ip, 0, false)
	if got := d.rankFor(ip); got != 2 {
		t.Fatalf("probe fail should give rank 2, got %d", got)
	}
}

func TestPenalizeSetsRank2(t *testing.T) {
	d := New(Options{})
	ip := netip.MustParseAddr("192.0.2.1")
	d.Penalize(ip)
	if got := d.rankFor(ip); got != 2 {
		t.Fatalf("Penalize should give rank 2, got %d", got)
	}
}
