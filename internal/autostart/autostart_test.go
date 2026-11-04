package autostart_test

import (
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/autostart"
)

// 路径带空格时必须整体加引号，否则 Windows 会把 "C:\Program" 当成可执行文件。
func TestValueQuotesPathWithSpaces(t *testing.T) {
	got := autostart.Value(`C:\Program Files\gha\gha.exe`)
	want := `"C:\Program Files\gha\gha.exe" run --autostart`
	if got != want {
		t.Fatalf("Value=%q want %q", got, want)
	}
}

// 用一次性子键验证写入/读回/删除的完整闭环，顺带验证"删两次"是幂等的。
func TestInstallRemoveRoundTrip(t *testing.T) {
	old := autostart.SubKey
	autostart.SubKey = `Software\gha-test-autostart`
	t.Cleanup(func() {
		_ = autostart.Remove()
		autostart.SubKey = old
	})

	if err := autostart.Remove(); err != nil { // 起点可能残留上次跑挂的值
		t.Fatalf("cleanup before install: %v", err)
	}
	if err := autostart.Install(`C:\Tools\gha.exe`); err != nil {
		t.Fatalf("Install: %v", err)
	}
	got, ok, err := autostart.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if !ok {
		t.Fatal("Current: 自启项没写进去")
	}
	if want := autostart.Value(`C:\Tools\gha.exe`); got != want {
		t.Fatalf("Current=%q want %q", got, want)
	}

	if err := autostart.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok, err := autostart.Current(); err != nil || ok {
		t.Fatalf("Remove 之后仍在（ok=%v err=%v）", ok, err)
	}
	if err := autostart.Remove(); err != nil {
		t.Fatalf("重复 Remove 应当成功: %v", err)
	}
}
