// Package regkey 读写当前用户（HKCU）下的注册表字符串值。
//
// 只做 HKCU：gha 的自启项属于"这个用户"，写到 HKLM 会让同一台机器上的其他账户
// 也莫名其妙多出一个加速器进程，收益不大、影响面反而更大。
//
// 为什么自己拿 advapi32 的 RegSetValueExW：Go 的 syscall 包只导出了
// RegOpenKeyEx / RegQueryValueEx / RegCloseKey 一族，写入与删除没有封装
// （envvars 包当初也是同样的原因自己取的），这里集中一处，别的包复用。
package regkey

import (
	"errors"
	"syscall"
	"unsafe"
)

// RunKey 是登录自启项所在的注册表位置（相对 HKCU）。
const RunKey = `Software\Microsoft\Windows\CurrentVersion\Run`

const (
	regSZ        = 1
	keyAllAccess = syscall.KEY_READ | syscall.KEY_WRITE
)

var advapi32 = syscall.NewLazyDLL("advapi32.dll")

var (
	procRegCreateKeyEx = advapi32.NewProc("RegCreateKeyExW")
	procRegSetValueEx  = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValue = advapi32.NewProc("RegDeleteValueW")
)

// SetString 写入（或覆盖）一个 REG_SZ 值；子键不存在时自动创建。
func SetString(subkey, name, value string) error {
	h, err := create(subkey)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(h)

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	if err := regSetValue(h, namePtr, regSZ, (*byte)(unsafe.Pointer(&data[0])), uint32(len(data)*2)); err != nil {
		return err
	}
	return nil
}

// GetString 读取一个 REG_SZ 值，第二个返回值表示"存在与否"。
// 值不存在不是错误——调用方（比如 status）只是想知道有没有配自启。
func GetString(subkey, name string) (string, bool, error) {
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, utf16Ptr(subkey), 0, syscall.KEY_READ, &h); err != nil {
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return "", false, nil
		}
		return "", false, err
	}
	defer syscall.RegCloseKey(h)

	buf := make([]uint16, 512)
	for {
		n := uint32(len(buf) * 2)
		var typ uint32
		err := syscall.RegQueryValueEx(h, utf16Ptr(name), nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n)
		if err != nil {
			if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
				return "", false, nil
			}
			if errors.Is(err, syscall.ERROR_MORE_DATA) {
				buf = make([]uint16, n/2+1)
				continue
			}
			return "", false, err
		}
		chars := n / 2
		for chars > 0 && buf[chars-1] == 0 {
			chars--
		}
		return syscall.UTF16ToString(buf[:chars]), true, nil
	}
}

// DeleteValue 删除一个值；本来就不存在时返回 nil（卸载必须可重复执行）。
func DeleteValue(subkey, name string) error {
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, utf16Ptr(subkey), 0, keyAllAccess, &h); err != nil {
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		return err
	}
	defer syscall.RegCloseKey(h)

	if err := regDeleteValue(h, utf16Ptr(name)); err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return err
	}
	return nil
}

func create(subkey string) (syscall.Handle, error) {
	var h syscall.Handle
	err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, utf16Ptr(subkey), 0, keyAllAccess, &h)
	if err == nil {
		return h, nil
	}
	if !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return 0, err
	}
	var out syscall.Handle
	var disposition uint32
	r, _, _ := procRegCreateKeyEx.Call(
		uintptr(syscall.HKEY_CURRENT_USER),
		uintptr(unsafe.Pointer(utf16Ptr(subkey))),
		0,
		0,
		0,
		uintptr(keyAllAccess),
		0,
		uintptr(unsafe.Pointer(&out)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return out, nil
}

func utf16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func regSetValue(h syscall.Handle, name *uint16, typ uint32, data *byte, size uint32) error {
	r, _, _ := procRegSetValueEx.Call(uintptr(h), uintptr(unsafe.Pointer(name)), 0,
		uintptr(typ), uintptr(unsafe.Pointer(data)), uintptr(size))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regDeleteValue(h syscall.Handle, name *uint16) error {
	r, _, _ := procRegDeleteValue.Call(uintptr(h), uintptr(unsafe.Pointer(name)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}
