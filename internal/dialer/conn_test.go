package dialer

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// 黑洞地址的特征是"连上了、撑几秒、一个字节都不搬运"。如果这种连接不记失败，
// 它会凭漂亮的握手延迟一直排在最前面，让每个请求都白等十几秒。
func TestZeroByteSlowConnIsPenalised(t *testing.T) {
	d := New(Options{})
	ip := netip.MustParseAddr("192.0.2.9")
	before := d.ScoreFor(ip)

	client, server := net.Pipe()
	defer server.Close()
	c := &countingConn{Conn: client, d: d, ip: ip, start: time.Now().Add(-5 * time.Second)}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	after := d.ScoreFor(ip)
	if after >= before/2 {
		t.Fatalf("零字节慢连接没有被惩罚：before=%.3f after=%.3f", before, after)
	}
}

// 刚建立就关掉的空连接（客户端立刻断开）不该被当成黑洞，否则正常浏览会被误伤。
func TestFastZeroByteConnIsNotPenalised(t *testing.T) {
	d := New(Options{})
	ip := netip.MustParseAddr("192.0.2.10")
	before := d.ScoreFor(ip)

	client, server := net.Pipe()
	defer server.Close()
	c := &countingConn{Conn: client, d: d, ip: ip, start: time.Now()}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if after := d.ScoreFor(ip); after != before {
		t.Fatalf("瞬断连接不应改变评分：before=%.3f after=%.3f", before, after)
	}
}
