package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/config"
)

// 命令行覆盖只作用于本次进程。写回配置会导致 README 里那条自测命令
// （--https 127.0.0.1:18443）把正式端口永久改掉：下一次正常 `gha run`
// 只绑 18443，而 hosts 仍指向 443 —— GitHub 全断，现象还特别迷惑。
func TestLoadConfigDoesNotPersistOverrides(t *testing.T) {
	dir := t.TempDir()
	a := Args{
		Cmd:     "run",
		DataDir: dir,
		HTTPS:   "127.0.0.1:18443",
		HTTP:    "127.0.0.1:18080",
		Verbose: true,
	}
	cfg, path, err := loadConfig(a)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen.HTTPS != "127.0.0.1:18443" {
		t.Fatalf("in-memory override lost: %s", cfg.Listen.HTTPS)
	}
	if path != filepath.Join(dir, "config.json") {
		t.Fatalf("unexpected config path: %s", path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk config.Config
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.Listen.HTTPS != "127.0.0.1:443" || onDisk.Listen.HTTP != "127.0.0.1:80" {
		t.Fatalf("CLI override persisted: %s", raw)
	}
	if onDisk.LogLevel == "debug" {
		t.Fatalf("-v persisted into log_level: %s", raw)
	}
	if onDisk.Token == "" {
		t.Fatal("token must be persisted so `gha status` can authenticate")
	}
}
