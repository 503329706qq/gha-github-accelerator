package app

import (
	"sync/atomic"
	"testing"
	"time"
)

// Fire 第一次必须立即触发。
func TestProbeDebouncerFiresImmediately(t *testing.T) {
	d := newProbeDebouncer(20 * time.Second)
	var fired atomic.Int32
	done := make(chan struct{})
	d.Fire("avatars.githubusercontent.com", func() {
		fired.Add(1)
		close(done)
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("第一次 Fire 没有触发回调")
	}
}

// 窗口内的同 host 请求被丢弃；不同 host 不受影响。
func TestProbeDebouncerMergesWithinWindow(t *testing.T) {
	d := newProbeDebouncer(20 * time.Second)
	var fired atomic.Int32
	d.Fire("a.test", func() { fired.Add(1) })
	// 等第一次真正跑起来
	deadline := time.Now().Add(time.Second)
	for fired.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	d.Fire("a.test", func() { fired.Add(1) })
	d.Fire("a.test", func() { fired.Add(1) })
	if got := fired.Load(); got != 1 {
		t.Fatalf("窗口内重复 Fire 应被合并，实际触发 %d 次", got)
	}
	d.Fire("b.test", func() { fired.Add(1) })
	deadline = time.Now().Add(time.Second)
	for fired.Load() == 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := fired.Load(); got != 2 {
		t.Fatalf("不同 host 不应被合并，实际触发 %d 次", got)
	}
}

// 窗口过后同一 host 可以再次触发。
func TestProbeDebouncerAllowsAfterWindow(t *testing.T) {
	d := newProbeDebouncer(30 * time.Millisecond)
	var fired atomic.Int32
	d.Fire("a.test", func() { fired.Add(1) })
	time.Sleep(60 * time.Millisecond) // 超过窗口
	d.Fire("a.test", func() { fired.Add(1) })
	deadline := time.Now().Add(time.Second)
	for fired.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := fired.Load(); got != 2 {
		t.Fatalf("窗口过后应再次触发，实际触发 %d 次", got)
	}
}
