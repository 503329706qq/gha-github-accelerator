//go:build windows

// Package store 把根证书与 CRL 装进 Windows 证书存储。
//
// 为什么要装进存储而不是只给 curl/git 传 --cacert：Chrome/Edge 只认系统存储，
// git 的 schannel 也默认只认系统存储。装进 LocalMachine\Root 之后 hosts 指向
// 本机才有意义——否则浏览器看到的是不受信任的证书。
//
// 这里的 syscall 直调 crypt32 会换来三条 `go vet` 的 "possible misuse of
// unsafe.Pointer"：那三处都是把 CERT_CONTEXT/CRL_CONTEXT 的 uintptr 句柄还原成
// 结构体指针，生命周期由 Crypt32 自己管理，不涉及 Go 堆，属于 API 语义决定的
// 写法（x/sys/windows 内部也是同样写法，只是 vet 不检查依赖包）。之所以不用
// x/sys：它没有 CRL 相关函数（CertEnumCRLsInStore / CertAddEncodedCRLToStore），
// 混用两套反而更难读。
package store

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// Scope 决定装进哪一套存储。
type Scope int

const (
	// CurrentUser 是 HKCU，不需要管理员。
	CurrentUser Scope = iota
	// LocalMachine 是 HKLM，需要管理员，但对所有账户生效。
	LocalMachine
)

const (
	certStoreProvSystem         = 10      // CERT_STORE_PROV_SYSTEM_W
	certSystemStoreCurrentUser  = 0x10000 // CERT_SYSTEM_STORE_CURRENT_USER
	certSystemStoreLocalMachine = 0x20000 // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certStoreAddReplaceExisting = 3       // CERT_STORE_ADD_REPLACE_EXISTING
	encodingX509AndPKCS7        = 0x10001 // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
	storeRoot                   = "Root"
	storeCA                     = "CA"
	cryptENotFound              = 0x80092004 // CRYPT_E_NOT_FOUND：枚举到底的正常信号
)

var (
	crypt32 = syscall.NewLazyDLL("crypt32.dll")

	procCertOpenStore                    = crypt32.NewProc("CertOpenStore")
	procCertCloseStore                   = crypt32.NewProc("CertCloseStore")
	procCertAddEncodedCertificateToStore = crypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertAddEncodedCRLToStore         = crypt32.NewProc("CertAddEncodedCRLToStore")
	procCertEnumCertificatesInStore      = crypt32.NewProc("CertEnumCertificatesInStore")
	procCertEnumCRLsInStore              = crypt32.NewProc("CertEnumCRLsInStore")
	procCertDeleteCertificateFromStore   = crypt32.NewProc("CertDeleteCertificateFromStore")
	procCertDeleteCRLFromStore           = crypt32.NewProc("CertDeleteCRLFromStore")
	procCertFreeCertificateContext       = crypt32.NewProc("CertFreeCertificateContext")
	procCertFreeCRLContext               = crypt32.NewProc("CertFreeCRLContext")
)

type certContext struct {
	encodingType uint32
	encoded      *byte
	encodedLen   uint32
	info         unsafe.Pointer
	store        syscall.Handle
}

type crlContext struct {
	encodingType uint32
	encoded      *byte
	encodedLen   uint32
	info         unsafe.Pointer
	store        syscall.Handle
}

func openStore(sc Scope, name string) (syscall.Handle, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := uintptr(certSystemStoreCurrentUser)
	if sc == LocalMachine {
		flags = certSystemStoreLocalMachine
	}
	h, _, callErr := procCertOpenStore.Call(
		uintptr(certStoreProvSystem),
		0,
		0,
		flags,
		uintptr(unsafe.Pointer(namePtr)),
	)
	if h == 0 {
		return 0, fmt.Errorf("store: open %s: %w", name, callErr)
	}
	return syscall.Handle(h), nil
}

func closeStore(h syscall.Handle) {
	if h != 0 {
		procCertCloseStore.Call(uintptr(h), 0)
	}
}

// derFromPEM 解出第一块 CERTIFICATE 的 DER。
func derFromPEM(certPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("store: input is not a CERTIFICATE PEM block")
	}
	return block.Bytes, nil
}

// InstallCert 把证书装进 Root 存储。已存在时覆盖（幂等）。
func InstallCert(sc Scope, certPEM []byte) error {
	der, err := derFromPEM(certPEM)
	if err != nil {
		return err
	}
	h, err := openStore(sc, storeRoot)
	if err != nil {
		return err
	}
	defer closeStore(h)
	r, _, callErr := procCertAddEncodedCertificateToStore.Call(
		uintptr(h),
		encodingX509AndPKCS7,
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
		certStoreAddReplaceExisting,
		0,
	)
	if r == 0 {
		return fmt.Errorf("store: add cert: %w", callErr)
	}
	return nil
}

// DeleteCert 删除与给定 PEM 逐字节相同的证书；不存在时返回 nil。
func DeleteCert(sc Scope, certPEM []byte) error {
	der, err := derFromPEM(certPEM)
	if err != nil {
		return err
	}
	h, err := openStore(sc, storeRoot)
	if err != nil {
		return err
	}
	defer closeStore(h)

	var prev uintptr
	for {
		r, _, callErr := procCertEnumCertificatesInStore.Call(uintptr(h), prev)
		if r == 0 {
			if prev == 0 || callErr == syscall.Errno(cryptENotFound) {
				return nil // 枚举到底，没找到
			}
			return fmt.Errorf("store: enumerate certs: %w", callErr)
		}
		ctx := (*certContext)(unsafe.Pointer(r))
		cur := unsafe.Slice(ctx.encoded, ctx.encodedLen)
		if bytes.Equal(cur, der) {
			ok, _, delErr := procCertDeleteCertificateFromStore.Call(r)
			if ok == 0 {
				return fmt.Errorf("store: delete cert: %w", delErr)
			}
			return nil
		}
		prev = r
	}
}

// HasCert 报告本地存储里是否已有这张证书。
func HasCert(sc Scope, certPEM []byte) (bool, error) {
	der, err := derFromPEM(certPEM)
	if err != nil {
		return false, err
	}
	h, err := openStore(sc, storeRoot)
	if err != nil {
		return false, err
	}
	defer closeStore(h)

	var prev uintptr
	for {
		r, _, callErr := procCertEnumCertificatesInStore.Call(uintptr(h), prev)
		if r == 0 {
			if prev == 0 || callErr == syscall.Errno(cryptENotFound) {
				return false, nil
			}
			return false, fmt.Errorf("store: enumerate certs: %w", callErr)
		}
		ctx := (*certContext)(unsafe.Pointer(r))
		if bytes.Equal(unsafe.Slice(ctx.encoded, ctx.encodedLen), der) {
			procCertFreeCertificateContext.Call(r) // 只释放句柄，绝不动存储内容
			return true, nil
		}
		prev = r
	}
}

// InstallCRL 把 CRL（DER）装进 CA 存储。schannel 会优先用存储里的 CRL，
// 这样即使 12080 上的 HTTP 分发点暂时不可达也不会吊销检查失败。
func InstallCRL(sc Scope, der []byte) error {
	if len(der) == 0 {
		return errors.New("store: empty CRL")
	}
	if _, err := parseCRL(der); err != nil {
		return err
	}
	h, err := openStore(sc, storeCA)
	if err != nil {
		return err
	}
	defer closeStore(h)
	r, _, callErr := procCertAddEncodedCRLToStore.Call(
		uintptr(h),
		encodingX509AndPKCS7,
		uintptr(unsafe.Pointer(&der[0])),
		uintptr(len(der)),
		certStoreAddReplaceExisting,
		0,
	)
	if r == 0 {
		return fmt.Errorf("store: add CRL: %w", callErr)
	}
	return nil
}

// HasCRL 报告 CA 存储里是否有这张 CRL。
func HasCRL(sc Scope, der []byte) (bool, error) {
	h, err := openStore(sc, storeCA)
	if err != nil {
		return false, err
	}
	defer closeStore(h)

	var prev uintptr
	for {
		r, _, callErr := procCertEnumCRLsInStore.Call(uintptr(h), prev)
		if r == 0 {
			if prev == 0 || callErr == syscall.Errno(cryptENotFound) {
				return false, nil
			}
			return false, fmt.Errorf("store: enumerate CRLs: %w", callErr)
		}
		ctx := (*crlContext)(unsafe.Pointer(r))
		if bytes.Equal(unsafe.Slice(ctx.encoded, ctx.encodedLen), der) {
			procCertFreeCRLContext.Call(r) // 只释放句柄
			return true, nil
		}
		prev = r
	}
}

// parseCRL 只做一次结构校验，避免把垃圾塞进 CA 存储。
func parseCRL(der []byte) (*x509.RevocationList, error) {
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("store: not a valid CRL: %w", err)
	}
	return rl, nil
}

// DeleteCRLsByIssuer 删除本 CA 签发的全部 CRL（卸载时用）。
//
// 不能"按字节比对"删：CRL 的 Number/ThisUpdate 每次重签都会变，install 时装进去的
// 那份和现在手上这份未必一致。所以这里按"签名能否被本 CA 验证"来认领，
// 既不误删别人的 CRL，也不会漏掉历史版本。
func DeleteCRLsByIssuer(sc Scope, certPEM []byte) (int, error) {
	der, err := derFromPEM(certPEM)
	if err != nil {
		return 0, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, err
	}
	h, err := openStore(sc, storeCA)
	if err != nil {
		return 0, err
	}
	defer closeStore(h)

	deleted := 0
	for {
		removedThisPass := false
		var prev uintptr
		for {
			r, _, callErr := procCertEnumCRLsInStore.Call(uintptr(h), prev)
			if r == 0 {
				if prev != 0 && callErr != syscall.Errno(cryptENotFound) {
					return deleted, fmt.Errorf("store: enumerate CRLs: %w", callErr)
				}
				break
			}
			ctx := (*crlContext)(unsafe.Pointer(r))
			raw := unsafe.Slice(ctx.encoded, ctx.encodedLen)
			if owned(cert, raw) {
				// CertDeleteCRLFromStore 删除的同时释放 context
				if ok, _, delErr := procCertDeleteCRLFromStore.Call(r); ok == 0 {
					return deleted, fmt.Errorf("store: delete CRL: %w", delErr)
				}
				deleted++
				removedThisPass = true
				break
			}
			prev = r
		}
		if !removedThisPass {
			return deleted, nil
		}
	}
}

// owned 判断一张 CRL 是不是本 CA 签发的。
func owned(cert *x509.Certificate, der []byte) bool {
	rl, err := parseCRL(der)
	if err != nil {
		return false
	}
	if rl.Issuer.String() != cert.Subject.String() {
		return false
	}
	return cert.CheckSignature(rl.SignatureAlgorithm, rl.RawTBSRevocationList, rl.Signature) == nil
}
