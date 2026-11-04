package sni_test

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/sni"
)

// captureClientHello 借 crypto/tls 造一个真实 ClientHello：net.Pipe 一端跑
// tls.Client 握手，另一端把字节读出来。比自己手搓报文更可信。
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() {
		_ = tls.Client(c2, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
		c2.Close()
	}()

	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 512)
	for len(buf) < 5 {
		n, err := c1.Read(tmp)
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		buf = append(buf, tmp[:n]...)
	}
	total := 5 + int(binary.BigEndian.Uint16(buf[3:5]))
	for len(buf) < total {
		n, err := c1.Read(tmp)
		if err != nil && err != io.EOF {
			t.Fatalf("read body: %v", err)
		}
		if n == 0 {
			break
		}
		buf = append(buf, tmp[:n]...)
	}
	if len(buf) < total {
		t.Fatalf("short clienthello: %d < %d", len(buf), total)
	}
	return buf[:total]
}

func TestParseClientHelloSNI(t *testing.T) {
	raw := captureClientHello(t, "github.com")

	if _, need, err := sni.ParseClientHello(raw[:20]); err != nil || need <= 0 {
		t.Fatalf("partial: need=%d err=%v", need, err)
	}
	name, need, err := sni.ParseClientHello(raw)
	if err != nil || need != 0 || name != "github.com" {
		t.Fatalf("name=%q need=%d err=%v", name, need, err)
	}
}

func TestParseClientHelloWithoutSNI(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() {
		// ServerName 为空时 crypto/tls 不发 SNI 扩展。
		_ = tls.Client(c2, &tls.Config{InsecureSkipVerify: true}).Handshake()
		c2.Close()
	}()
	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 512)
	for len(buf) < 5 {
		n, err := c1.Read(tmp)
		if err != nil {
			t.Fatal(err)
		}
		buf = append(buf, tmp[:n]...)
	}
	total := 5 + int(binary.BigEndian.Uint16(buf[3:5]))
	for len(buf) < total {
		n, _ := c1.Read(tmp)
		if n == 0 {
			break
		}
		buf = append(buf, tmp[:n]...)
	}
	name, _, err := sni.ParseClientHello(buf)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if name != "" {
		t.Fatalf("expected empty SNI, got %q", name)
	}
}

func TestParseNotTLS(t *testing.T) {
	if _, _, err := sni.ParseClientHello([]byte("GET / HTTP/1.1\r\n")); err == nil {
		t.Fatal("expected error for non-TLS bytes")
	}
}

func TestInAllowlist(t *testing.T) {
	for _, ok := range []string{
		"github.com", "api.github.com", "raw.githubusercontent.com",
		"avatars3.githubusercontent.com", "github.githubassets.com",
		"github.io", "www.github.io", "github.dev", "codeload.github.com",
	} {
		if !sni.InAllowlist(ok) {
			t.Fatalf("%s should match", ok)
		}
	}
	if !sni.InAllowlist("API.GitHub.com") {
		t.Fatal("case-insensitive match expected")
	}
	for _, bad := range []string{
		"evilgithub.com", "github.com.evil.io", "example.com",
		"huggingface.co", "greasyfork.org", "", "github",
	} {
		if sni.InAllowlist(bad) {
			t.Fatalf("%q should not match", bad)
		}
	}
}
