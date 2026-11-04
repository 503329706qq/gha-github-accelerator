package gitcfg_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/gitcfg"
)

func TestGitRewritesAndRemove(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cfgPath := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(cfgPath, []byte("[user]\n\tname = test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfgPath)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Env = os.Environ()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}

	git("config", "--global", "url.https://gh-proxy.org/https://github.com/.insteadOf", "https://github.com/")
	git("config", "--global", "http.postBuffer", "524288000") // 无关配置，必须原样保留

	rs, err := gitcfg.Rewrites()
	if err != nil {
		t.Fatalf("Rewrites: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("Rewrites=%v", rs)
	}
	want := gitcfg.Entry{
		Key:       "url.https://gh-proxy.org/https://github.com/.insteadOf",
		Base:      "https://gh-proxy.org/https://github.com/",
		InsteadOf: "https://github.com/",
	}
	if rs[0] != want {
		t.Fatalf("got %+v want %+v", rs[0], want)
	}

	if err := gitcfg.Remove(rs[0]); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if rs, _ := gitcfg.Rewrites(); len(rs) != 0 {
		t.Fatalf("after Remove: %v", rs)
	}
	// 无关配置必须还在
	if out, err := exec.Command("git", "config", "--global", "--get", "http.postBuffer").Output(); err != nil {
		t.Fatalf("postBuffer lost: %v", err)
	} else if strings.TrimSpace(string(out)) != "524288000" {
		t.Fatalf("postBuffer=%q", out)
	}

	if err := gitcfg.Add(want); err != nil {
		t.Fatalf("Add: %v", err)
	}
	rs, err = gitcfg.Rewrites()
	if err != nil || len(rs) != 1 || rs[0] != want {
		t.Fatalf("after Add: %v %v", rs, err)
	}
}
