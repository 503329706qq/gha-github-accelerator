package config_test

import (
	"path/filepath"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/config"
)

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	c, err := config.Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen.HTTPS != "127.0.0.1:443" {
		t.Fatalf("https=%s", c.Listen.HTTPS)
	}
	if c.Listen.HTTP != "127.0.0.1:80" {
		t.Fatalf("http=%s", c.Listen.HTTP)
	}
	if c.Listen.Control != "127.0.0.1:12080" {
		t.Fatalf("control=%s", c.Listen.Control)
	}
	if c.FallbackDNS != "223.5.5.5:53" {
		t.Fatalf("fallback=%s", c.FallbackDNS)
	}
	if !c.IPv6 {
		t.Fatal("ipv6 default should be true")
	}
	if len(c.DoHJSON) == 0 || len(c.DoHWire) == 0 {
		t.Fatal("doh defaults missing")
	}
}

func TestAllDomainsAppendsExtraAndDedups(t *testing.T) {
	c := config.Default()
	c.ExtraDomains = []string{"github.com", "example.github.com"}
	got := c.AllDomains()
	if count(got, "github.com") != 1 {
		t.Fatalf("dup github.com: %v", got)
	}
	if !contains(got, "example.github.com") {
		t.Fatal("extra missing")
	}
	if !contains(got, "codeload.github.com") {
		t.Fatal("builtin missing")
	}
}

func TestAllDomainsOrderIsStable(t *testing.T) {
	c := config.Default()
	first := c.AllDomains()
	second := c.AllDomains()
	if len(first) != len(second) {
		t.Fatal("length changed")
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("order changed at %d", i)
		}
	}
	if first[0] != "github.com" {
		t.Fatalf("first=%s", first[0])
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func count(ss []string, s string) int {
	n := 0
	for _, v := range ss {
		if v == s {
			n++
		}
	}
	return n
}
