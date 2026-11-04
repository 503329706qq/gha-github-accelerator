package upstream

import (
	"context"
	"net/netip"
	"testing"
)

func TestRecorderRoundTrip(t *testing.T) {
	rec := NewRecorder()

	if ip, ok := rec.Get(); ok {
		t.Fatalf("空 Recorder 不应返回数据，却得到 %v", ip)
	}

	ctx := With(context.Background(), rec)
	if got := From(ctx); got != rec {
		t.Fatalf("From(ctx) 应返回挂进去的 Recorder，得到 %v", got)
	}

	want := netip.MustParseAddr("140.82.112.3")
	rec.Set(want)
	got, ok := rec.Get()
	if !ok || got != want {
		t.Fatalf("Get() = (%v, %v)，想要 (%v, true)", got, ok, want)
	}
}

func TestFromWithoutRecorder(t *testing.T) {
	if rec := From(context.Background()); rec != nil {
		t.Fatalf("无 Recorder 的 ctx 应返回 nil，得到 %v", rec)
	}
}

func TestConcurrentSetGet(t *testing.T) {
	rec := NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			rec.Set(netip.MustParseAddr("20.205.243.166"))
			if _, ok := rec.Get(); !ok {
				t.Error("并发读取时不应丢失记录")
				return
			}
		}
	}()
	<-done
}
