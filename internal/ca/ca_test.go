package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/503329706qq/gha-github-accelerator/internal/ca"
)

const testCRLURL = "http://127.0.0.1:12080/ca.crl"

func newCA(t *testing.T, dir string) *ca.CA {
	t.Helper()
	c, err := ca.LoadOrCreate(ca.Options{
		CertPath: filepath.Join(dir, "root.crt"),
		KeyPath:  filepath.Join(dir, "root.key.pem"),
		CRLURL:   testCRLURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadOrCreatePersists(t *testing.T) {
	dir := t.TempDir()
	first := newCA(t, dir)

	for _, f := range []string{"root.crt", "root.key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s not written: %v", f, err)
		}
	}
	// 私钥必须只有本用户可读。Windows 上 os.Stat 的权限位恒为 0666，
	// 真正的隔离来自 %LOCALAPPDATA% 的 ACL 继承，所以这里只对类 Unix 断言。
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(filepath.Join(dir, "root.key.pem")); err == nil {
			if perm := fi.Mode().Perm(); perm&0o077 != 0 {
				t.Fatalf("key file too permissive: %v", perm)
			}
		}
	}

	second := newCA(t, dir)
	if second.Certificate().SerialNumber.Cmp(first.Certificate().SerialNumber) != 0 {
		t.Fatal("second load produced a different CA")
	}
}

func TestRootProperties(t *testing.T) {
	dir := t.TempDir()
	c := newCA(t, dir)
	root := c.Certificate()

	if !root.IsCA || !root.BasicConstraintsValid {
		t.Fatal("root is not a CA")
	}
	if root.KeyUsage&x509.KeyUsageCertSign == 0 || root.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatalf("root key usage lacks CertSign/CRLSign: %v", root.KeyUsage)
	}
	if _, ok := root.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("root key is %T, want ECDSA", root.PublicKey)
	}
	if root.PublicKey.(*ecdsa.PublicKey).Curve != elliptic.P256() {
		t.Fatal("root key is not P-256")
	}
	if y := root.NotAfter.Sub(root.NotBefore); y < 9*365*24*time.Hour {
		t.Fatalf("root validity too short: %v", y)
	}
	// 根证书必须能自校验
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root is not self-signed: %v", err)
	}
}

func TestLeafForHasSANAndCRLDP(t *testing.T) {
	dir := t.TempDir()
	c := newCA(t, dir)

	leaf, err := c.LeafFor("github.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("expected leaf+root chain, got %d certs", len(leaf.Certificate))
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "github.com" {
		t.Fatalf("SAN=%v", parsed.DNSNames)
	}
	if parsed.IsCA {
		t.Fatal("leaf marked as CA")
	}
	if len(parsed.CRLDistributionPoints) != 1 || parsed.CRLDistributionPoints[0] != testCRLURL {
		t.Fatalf("CRLDP=%v", parsed.CRLDistributionPoints)
	}
	if parsed.NotAfter.Sub(parsed.NotBefore) > 100*24*time.Hour {
		t.Fatalf("leaf validity too long: %v", parsed.NotAfter.Sub(parsed.NotBefore))
	}
	if err := parsed.CheckSignatureFrom(c.Certificate()); err != nil {
		t.Fatalf("leaf not signed by root: %v", err)
	}
}

func TestLeafForCaches(t *testing.T) {
	c := newCA(t, t.TempDir())
	a, err := c.LeafFor("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.LeafFor("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Certificate[0]) != string(b.Certificate[0]) {
		t.Fatal("leaf not cached for identical SNI")
	}
}

func TestCRLIsSignedAndFresh(t *testing.T) {
	c := newCA(t, t.TempDir())
	der, err := c.CRL()
	if err != nil {
		t.Fatal(err)
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := rl.CheckSignatureFrom(c.Certificate()); err != nil {
		t.Fatalf("CRL signature invalid: %v", err)
	}
	if len(rl.RevokedCertificateEntries) != 0 {
		t.Fatal("CRL should be empty")
	}
	now := time.Now()
	if rl.ThisUpdate.After(now.Add(time.Minute)) {
		t.Fatalf("ThisUpdate in the future: %v", rl.ThisUpdate)
	}
	// 有效期必须明显长于"存储里的 CRL 多久刷一次"：schannel 手里有一份未过期的
	// CRL 就不会去问 12080，控制端口挂掉也不影响证书校验（见 crlValidFor 的注释）。
	if rl.NextUpdate.Before(now.Add(24*time.Hour)) || rl.NextUpdate.After(now.Add(8*24*time.Hour)) {
		t.Fatalf("NextUpdate out of range: %v", rl.NextUpdate)
	}
}

func TestCRLRegeneratedAfterInterval(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	c, err := ca.LoadOrCreate(ca.Options{
		CertPath: filepath.Join(dir, "root.crt"),
		KeyPath:  filepath.Join(dir, "root.key.pem"),
		CRLURL:   testCRLURL,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.CRL()
	if err != nil {
		t.Fatal(err)
	}
	// 同一时刻再取应命中缓存
	again, _ := c.CRL()
	if string(first) != string(again) {
		t.Fatal("CRL should be cached")
	}
	// 推进 8 小时，必须重签
	now = now.Add(8 * time.Hour)
	third, err := c.CRL()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) == string(third) {
		t.Fatal("CRL not regenerated after 8h")
	}
	rl, err := x509.ParseRevocationList(third)
	if err != nil {
		t.Fatal(err)
	}
	if rl.NextUpdate.Before(now) {
		t.Fatalf("regenerated CRL already expired: %v < %v", rl.NextUpdate, now)
	}
}

func TestCertPEMIsParseable(t *testing.T) {
	c := newCA(t, t.TempDir())
	block, _ := pem.Decode(c.CertPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("CertPEM is not a CERTIFICATE block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}
}
