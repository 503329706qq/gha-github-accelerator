package hosts_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/hosts"
)

// 这条用例覆盖评审里那个阻塞项的根因："hosts 里已经有一模一样的块"
// （上一次进程被强杀/断电留下的痕迹）时 Apply 返回 changed=false。
// 退出路径如果拿 changed 当"要不要还原"的开关，这个残留块就永远没人摘。
func TestRestoreAfterIdempotentApplyStillRemovesBlock(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hosts")
	backupDir := filepath.Join(dir, "backup")
	if err := os.WriteFile(p, fixture, 0o644); err != nil {
		t.Fatal(err)
	}

	domains := []string{"github.com", "api.github.com"}
	if changed, err := hosts.ApplyTo(p, domains, backupDir); err != nil || !changed {
		t.Fatalf("first apply: changed=%v err=%v", changed, err)
	}
	changed, err := hosts.ApplyTo(p, domains, backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("second apply should be a no-op (this is the crash-residue state)")
	}

	if _, err := hosts.RestoreTo(p, backupDir); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fixture) {
		t.Fatalf("hosts still differs from fixture after restore:\n%q", got)
	}

	// 备份必须落在数据目录，不能堆进 etc。
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "hosts.backup-") {
			t.Fatalf("backup written next to hosts: %s", e.Name())
		}
	}
	if entries, err := os.ReadDir(backupDir); err != nil || len(entries) == 0 {
		t.Fatalf("no backups in %s (err=%v)", backupDir, err)
	}
}
