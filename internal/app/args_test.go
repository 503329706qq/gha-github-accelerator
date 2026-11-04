package app

import (
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	a, err := ParseArgs([]string{"run", "--https", "127.0.0.1:18443", "--no-hosts"})
	if err != nil {
		t.Fatal(err)
	}
	if a.Cmd != "run" || a.HTTPS != "127.0.0.1:18443" || !a.NoHosts {
		t.Fatalf("got %+v", a)
	}
	if a.HTTP != "" || a.Verbose {
		t.Fatalf("unexpected defaults: %+v", a)
	}
}

func TestParseArgsEqualsForm(t *testing.T) {
	a, err := ParseArgs([]string{"run", "--http=127.0.0.1:18080", "--control=127.0.0.1:12081", "-v"})
	if err != nil {
		t.Fatal(err)
	}
	if a.HTTP != "127.0.0.1:18080" || a.Control != "127.0.0.1:12081" || !a.Verbose {
		t.Fatalf("got %+v", a)
	}
}

func TestUnknownCommand(t *testing.T) {
	_, err := ParseArgs([]string{"bogus"})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"install", "run", "status"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q should mention %q", err, want)
		}
	}
	if _, err := ParseArgs(nil); err == nil {
		t.Fatal("empty argv should error")
	}
	if _, err := ParseArgs([]string{"run", "--nope"}); err == nil {
		t.Fatal("unknown flag should error")
	}
	if _, err := ParseArgs([]string{"run", "--https"}); err == nil {
		t.Fatal("missing flag value should error")
	}
}
