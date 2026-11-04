package ca_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/ca"
)

// 私钥必须加密落盘：根证书进了 LocalMachine\Root 之后，拿到这把私钥就等于
// 能给任意域名签一张本机信任的证书。0o600 在 Windows 上不起作用。
func TestKeyFileIsEncryptedAtRest(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI 只在 Windows 上存在")
	}
	dir := t.TempDir()
	o := ca.Options{
		CertPath: filepath.Join(dir, "root.crt"),
		KeyPath:  filepath.Join(dir, "root.key.pem"),
	}
	if _, err := ca.LoadOrCreate(o); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(o.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("private key is stored as plaintext PEM")
	}
	// 同一份文件必须还能被自己解开（否则重启就是一台没有 CA 的机器）。
	if _, err := ca.LoadOrCreate(o); err != nil {
		t.Fatalf("cannot reload encrypted key: %v", err)
	}
}
