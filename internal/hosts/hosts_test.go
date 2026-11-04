package hosts_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/hosts"
)

// fixture 复刻真实 hosts 的常见特征：UTF-8 BOM、CRLF、两个第三方块
// （一个指向公网地址，一个把若干域名指到 127.0.0.1）。地址用文档保留段
// 203.0.113.0/24 与 .test 顶级域，不涉及任何真实主机。
var fixture = []byte("\xef\xbb\xbf\r\n" +
	"# ACME-AGENT-BEGIN\r\n" +
	"203.0.113.10 agent.example.test\r\n" +
	"# ACME-AGENT-END\r\n" +
	"# LocalProxy Start\r\n" +
	"127.0.0.1 example.test\r\n" +
	"127.0.0.1 www.example.test\r\n" +
	"# LocalProxy End\r\n")

func TestUpsertPreservesBOMAndForeignBlocks(t *testing.T) {
	got := hosts.Upsert(fixture, hosts.Render([]string{"github.com"}))
	if !bytes.HasPrefix(got, []byte("\xef\xbb\xbf")) {
		t.Fatal("BOM lost")
	}
	if !bytes.Contains(got, []byte("203.0.113.10 agent.example.test\r\n")) {
		t.Fatal("foreign block damaged")
	}
	if !bytes.Contains(got, []byte("# LocalProxy Start\r\n127.0.0.1 example.test\r\n127.0.0.1 www.example.test\r\n# LocalProxy End\r\n")) {
		t.Fatal("foreign block damaged")
	}
	if bytes.Count(got, []byte(hosts.BeginMarker)) != 1 {
		t.Fatalf("marker count: %d", bytes.Count(got, []byte(hosts.BeginMarker)))
	}
	if !bytes.Contains(got, []byte("127.0.0.1 github.com\r\n")) {
		t.Fatal("entry missing")
	}
	if !bytes.HasSuffix(got, []byte(hosts.EndMarker+"\r\n")) {
		t.Fatalf("block not at end: %q", got)
	}
}

func TestUpsertTwiceIsIdempotent(t *testing.T) {
	once := hosts.Upsert(fixture, hosts.Render([]string{"github.com"}))
	twice := hosts.Upsert(once, hosts.Render([]string{"github.com", "api.github.com"}))
	if bytes.Count(twice, []byte(hosts.BeginMarker)) != 1 {
		t.Fatal("duplicated block")
	}
	if !bytes.Contains(twice, []byte("127.0.0.1 api.github.com\r\n")) {
		t.Fatal("new entry missing")
	}
	if bytes.Count(twice, []byte("127.0.0.1 github.com\r\n")) != 1 {
		t.Fatal("old entry duplicated")
	}
}

func TestRemoveRestoresFixtureExactly(t *testing.T) {
	got := hosts.Remove(hosts.Upsert(fixture, hosts.Render([]string{"github.com"})))
	if !bytes.Equal(got, fixture) {
		t.Fatalf("got %q", got)
	}
}

func TestRemoveNoopWhenNoBlock(t *testing.T) {
	if got := hosts.Remove(fixture); !bytes.Equal(got, fixture) {
		t.Fatalf("got %q", got)
	}
}

func TestApplyWritesAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hosts")
	if err := os.WriteFile(p, fixture, 0644); err != nil {
		t.Fatal(err)
	}
	changed, err := hosts.Apply(p, []string{"github.com"})
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Contains(got, []byte("127.0.0.1 github.com\r\n")) {
		t.Fatal("not written")
	}
	// 第二次内容相同 -> changed=false，且不再新增备份
	changed, err = hosts.Apply(p, []string{"github.com"})
	if err != nil || changed {
		t.Fatalf("second apply changed=%v err=%v", changed, err)
	}
	backups, _ := filepath.Glob(filepath.Join(dir, "hosts.backup-*"))
	if len(backups) != 1 {
		t.Fatalf("backups=%v", backups)
	}
	// 还原
	if _, err := hosts.Restore(p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(after, fixture) {
		t.Fatalf("restore mismatch: %q", after)
	}
	if present, _, _ := hosts.Status(p); present {
		t.Fatal("still present after restore")
	}
}
