package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallSelfCopiesExecutable(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "dist", "gha.exe")
	dst := filepath.Join(dir, "data", "bin", "gha.exe")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte("fake-exe-bytes-\x00\x01\x02")
	if err := os.WriteFile(src, payload, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := installSelf(src, dst)
	if err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	if got != dst {
		t.Fatalf("返回路径 = %q，期望 %q", got, dst)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("读取目标: %v", err)
	}
	if string(b) != string(payload) {
		t.Fatalf("复制内容不一致：%d 字节 vs %d 字节", len(b), len(payload))
	}
	if _, err := os.Stat(dst + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("临时文件应当已被改名，留下的是 %v", err)
	}
}

// 目标已存在（升级场景）时要能覆盖，而不是报错。
func TestInstallSelfOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "gha.exe")
	dst := filepath.Join(dir, "bin", "gha.exe")
	if err := os.WriteFile(src, []byte("v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("v1-older-and-longer"), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := installSelf(src, dst); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	b, _ := os.ReadFile(dst)
	if string(b) != "v2" {
		t.Fatalf("目标内容 = %q，期望 v2", b)
	}
}

// 已经是从 bin 里运行时不该自我复制（否则会把自己覆盖掉）。
func TestInstallSelfSamePathIsNoop(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gha.exe")
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := installSelf(p, p); err != nil {
		t.Fatalf("installSelf: %v", err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("同一路径时不应产生临时文件")
	}
}

func TestEqualFoldPathIgnoresCase(t *testing.T) {
	if !equalFoldPath(`C:\App\GHA.exe`, `C:\App\gha.EXE`) {
		t.Fatal("Windows 路径大小写不敏感，应当判定为同一路径")
	}
	if equalFoldPath(`C:\App\a.exe`, `C:\App\b.exe`) {
		t.Fatal("不同文件名不应相等")
	}
}
