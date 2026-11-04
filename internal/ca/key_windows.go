//go:build windows

package ca

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// 私钥落盘格式：magic 前缀 + CryptProtectData 产生的 blob。
// 只有当前 Windows 用户登录后能解开；文件被拷走或换个账户读都是密文。
// 这一层不是可选的加固：0o600 在 Windows 上只映射只读位，不加 DPAPI 的话
// %LOCALAPPDATA%\gha\ca 下的私钥对同用户的任何进程都是可读的。
const keyBlobMagic = "gha-dpapi-v1\n"

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtect   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32.NewProc("CryptUnprotectData")
	procLocalFree      = kernel32.NewProc("LocalFree")
)

// CRYPTPROTECT_UI_FORBIDDEN：服务/无界面进程不能弹任何对话框。
const cryptProtectUIForbidden = 0x1

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) dataBlob {
	if len(b) == 0 {
		return dataBlob{}
	}
	return dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func protectKey(plain []byte) ([]byte, error) {
	in := newBlob(plain)
	var out dataBlob
	r, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("ca: CryptProtectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	blob := make([]byte, 0, len(keyBlobMagic)+int(out.cbData))
	blob = append(blob, keyBlobMagic...)
	blob = append(blob, unsafe.Slice(out.pbData, int(out.cbData))...)
	return blob, nil
}

func unprotectKey(blob []byte) ([]byte, error) {
	in := newBlob(blob)
	var out dataBlob
	r, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("ca: CryptUnprotectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return append([]byte(nil), unsafe.Slice(out.pbData, int(out.cbData))...), nil
}

func writeKey(path string, pemBytes []byte) error {
	blob, err := protectKey(pemBytes)
	if err != nil {
		return err
	}
	return os.WriteFile(path, blob, 0o600)
}

// readKey 读私钥；老版本留下的明文 PEM 会顺手迁移成 DPAPI blob（迁移失败也照常用）。
func readKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(b, []byte(keyBlobMagic)) {
		return unprotectKey(b[len(keyBlobMagic):])
	}
	if block, _ := pem.Decode(b); block != nil {
		if blob, err := protectKey(b); err == nil {
			_ = os.WriteFile(path, blob, 0o600)
		}
	}
	return b, nil
}
