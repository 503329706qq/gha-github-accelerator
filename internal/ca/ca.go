// Package ca 管理本地根证书、按 SNI 现签的叶证书，以及 schannel 要求的 CRL。
//
// 关键约束：Windows 的 schannel（curl、git 的默认后端）在对端证书带 CRL
// 分发点时，会真的去把它取回来，取不到就报 CRYPT_E_NO_REVOCATION_CHECK。
// 所以叶证书必须带 CRLDP，而且那个 URL 在每次校验时都必须活着——由
// control 服务在 127.0.0.1:12080 上提供 /ca.crl。
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	defaultCRLURL    = "http://127.0.0.1:12080/ca.crl"
	defaultLeafTTL   = 90 * 24 * time.Hour
	defaultRootYears = 10
	// CRL 的有效期给 7 天：schannel 只要手里有一份未过期的 CRL 就不会去问
	// 分发点，控制端口 12080 挂掉也不会让证书校验失败。内存里每 6h 重签一份，
	// 保证长时间挂机时存储里那份始终新鲜。
	crlValidFor   = 7 * 24 * time.Hour
	crlRenewEvery = 6 * time.Hour
	serialBits    = 128
)

// Options 配置 CA。
type Options struct {
	CertPath  string // 根证书 PEM 路径
	KeyPath   string // 根私钥 PEM 路径
	CRLURL    string // 叶证书里的 CRL 分发点
	Now       func() time.Time
	LeafTTL   time.Duration
	RootYears int
}

// CA 是已加载或刚生成的本地 CA，并发安全。
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	crlURL  string
	leafTTL time.Duration
	now     func() time.Time

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
	crl    []byte
	crlAt  time.Time
}

// LoadOrCreate 读取已有 CA；文件不存在则生成并落盘（私钥 0600）。
func LoadOrCreate(o Options) (*CA, error) {
	if o.CRLURL == "" {
		o.CRLURL = defaultCRLURL
	}
	if o.LeafTTL <= 0 {
		o.LeafTTL = defaultLeafTTL
	}
	if o.RootYears <= 0 {
		o.RootYears = defaultRootYears
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.CertPath == "" || o.KeyPath == "" {
		return nil, errors.New("ca: CertPath and KeyPath are required")
	}

	certExists := fileExists(o.CertPath)
	keyExists := fileExists(o.KeyPath)

	var cert *x509.Certificate
	var key *ecdsa.PrivateKey
	var certPEM []byte

	switch {
	case certExists && keyExists:
		var err error
		cert, key, certPEM, err = load(o.CertPath, o.KeyPath)
		if err != nil {
			return nil, err
		}
	case certExists != keyExists:
		return nil, fmt.Errorf("ca: incomplete keypair (cert=%v key=%v) — remove both to regenerate", certExists, keyExists)
	default:
		var err error
		cert, key, certPEM, err = create(o)
		if err != nil {
			return nil, err
		}
	}

	return &CA{
		cert:    cert,
		key:     key,
		certPEM: certPEM,
		crlURL:  o.CRLURL,
		leafTTL: o.LeafTTL,
		now:     o.Now,
		leaves:  make(map[string]*tls.Certificate),
	}, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func load(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, nil, fmt.Errorf("ca: %s is not a CERTIFICATE PEM", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	keyPEM, err := readKey(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, nil, fmt.Errorf("ca: %s is not a PEM key", keyPath)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, nil, fmt.Errorf("ca: %s holds %T, want ECDSA", keyPath, parsed)
	}
	return cert, key, certPEM, nil
}

func create(o Options) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	now := o.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "gha Local Root CA", Organization: []string{"gha"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(o.RootYears, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if dir := filepath.Dir(o.CertPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := os.WriteFile(o.CertPath, certPEM, 0o644); err != nil {
		return nil, nil, nil, err
	}
	// 私钥用 DPAPI 加密后落盘：0o600 在 Windows 上只影响只读位，同用户的
	// 任何进程（被投毒的 npm postinstall 也算）都能读到 %LOCALAPPDATA% 下的明文。
	// 这把私钥能签发任意域名证书，而根已经进了 LocalMachine\Root。
	if err := writeKey(o.KeyPath, keyPEM); err != nil {
		return nil, nil, nil, err
	}
	return cert, key, certPEM, nil
}

func keyID(pub *ecdsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(der)
	return sum[:20]
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), serialBits)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n, nil
}

// Certificate 返回根证书。
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// CertPEM 返回根证书的 PEM 编码（用于装进系统存储、给 Node/Python 合并）。
func (c *CA) CertPEM() []byte { return c.certPEM }

// LeafFor 现签（并按 SNI 缓存）一张叶证书，返回含根证书的链。
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, errors.New("ca: empty SNI")
	}
	c.mu.Lock()
	if lc, ok := c.leaves[host]; ok {
		c.mu.Unlock()
		return lc, nil
	}
	c.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := c.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(c.leafTTL),
		DNSNames:              []string{host},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		CRLDistributionPoints: []string{c.crlURL},
		AuthorityKeyId:        c.cert.SubjectKeyId,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	lc := &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        nil,
	}

	c.mu.Lock()
	c.leaves[host] = lc
	c.mu.Unlock()
	return lc, nil
}

// CRL 返回当前 CRL（DER）。每 6 小时重签一次，其余时间返回缓存。
func (c *CA) CRL() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if c.crl != nil && now.Sub(c.crlAt) < crlRenewEvery {
		return c.crl, nil
	}

	number := big.NewInt(now.Unix())
	tmpl := &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(crlValidFor),
		SignatureAlgorithm:        x509.ECDSAWithSHA256,
		RevokedCertificateEntries: nil,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.cert, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: create CRL: %w", err)
	}
	c.crl = der
	c.crlAt = now
	return der, nil
}

var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
