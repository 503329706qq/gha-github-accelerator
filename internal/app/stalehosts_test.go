package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/hosts"
)

func writeHostsFixture(t *testing.T, extra string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hosts")
	content := "127.0.0.1 localhost\r\n" + extra
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadHostsStateDetectsOurBlock(t *testing.T) {
	block := string(hosts.Render([]string{"github.com", "api.github.com", "codeload.github.com"}))
	p := writeHostsFixture(t, block)

	st := readHostsState(p)
	if !st.Present {
		t.Fatal("应当检测到 gha 的块")
	}
	if st.Lines != 3 {
		t.Fatalf("条目数 = %d，期望 3", st.Lines)
	}
	hint := staleHostsHint(st)
	if hint == "" {
		t.Fatal("有残留时必须给出提示")
	}
	if !strings.Contains(hint, "gha stop") || !strings.Contains(hint, "127.0.0.1") {
		t.Fatalf("提示里应包含还原方式与后果，实际：%s", hint)
	}
}

func TestReadHostsStateWithoutBlock(t *testing.T) {
	p := writeHostsFixture(t, "127.0.0.1 localhost\r\n")
	st := readHostsState(p)
	if st.Present {
		t.Fatal("没有块时不应报告 present")
	}
	if staleHostsHint(st) != "" {
		t.Fatal("没有残留时不应给出提示")
	}
}
