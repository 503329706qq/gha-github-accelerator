package log_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/log"
)

func TestRedactQuery(t *testing.T) {
	got := log.RedactQuery("a=1&token=abc&access_token=xyz&password=p&key=k&secret=s&n=2")
	want := "a=1&token=***&access_token=***&password=***&key=***&secret=***&n=2"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRedactQueryKeepsOrderAndEmpty(t *testing.T) {
	if log.RedactQuery("") != "" {
		t.Fatal("empty query should stay empty")
	}
	if got := log.RedactQuery("Token=ABC"); got != "Token=***" {
		t.Fatalf("case-insensitive key match failed: %q", got)
	}
	if got := log.RedactQuery("code=ok"); got != "code=ok" {
		t.Fatalf("non-secret changed: %q", got)
	}
}

func TestRequestLineRedacts(t *testing.T) {
	var buf bytes.Buffer
	l := log.New(&buf, log.LevelInfo)
	l.Request("github.com", "GET", "/x", "token=abc&a=1", 200, 1234, 12*time.Millisecond, "1.2.3.4")

	line := buf.String()
	if !strings.Contains(line, "github.com GET /x?token=***&a=1 200") {
		t.Fatalf("line=%q", line)
	}
	if strings.Contains(line, "abc") {
		t.Fatalf("secret leaked: %q", line)
	}
	if !strings.Contains(line, "1234B") || !strings.Contains(line, "1.2.3.4") {
		t.Fatalf("missing bytes/ip: %q", line)
	}
}

func TestDebugSuppressedAtInfo(t *testing.T) {
	var buf bytes.Buffer
	l := log.New(&buf, log.LevelInfo)
	l.Debug("noise %d", 1)
	if buf.Len() != 0 {
		t.Fatalf("debug leaked at info level: %q", buf.String())
	}
}
