// Package envvars 读写当前用户的环境变量（HKCU\Environment）。
//
// 只做"用户级"而不是"机器级"：gha 装的证书是给这个账户的程序用的，
// 机器级变量会影响所有账户，收益不大、影响面反而更大。
// 改完之后广播 WM_SETTINGCHANGE("Environment")，让资源管理器立刻刷新，
// 否则新开的终端要等重新登录才看得到。
package envvars

import (
	"errors"
	"syscall"
	"unsafe"
)

const envSubKey = `Environment`

var errNotFound = errors.New("env var not found")

func openEnvironment(access uint32) (syscall.Handle, error) {
	var h syscall.Handle
	name, err := syscall.UTF16PtrFromString(envSubKey)
	if err != nil {
		return 0, err
	}
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, name, 0, access, &h); err != nil {
		return 0, err
	}
	return h, nil
}

// SetUser 写入一个用户环境变量；value 为空等价于删除（Windows 没有"空值变量"这个概念）。
func SetUser(name, value string) error {
	h, err := openEnvironment(syscall.KEY_READ | syscall.KEY_WRITE)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(h)

	if value == "" {
		return deleteValue(h, name)
	}
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	if err := regSetValue(h, namePtr, syscall.REG_SZ, (*byte)(unsafe.Pointer(&data[0])), uint32(len(data)*2)); err != nil {
		return err
	}
	notifyEnvironmentChanged()
	return nil
}

// Broadcast 带外广播 WM_SETTINGCHANGE("Environment")：用于不是经 SetUser
// 改的环境（例如 PowerShell 的 [Environment]::SetEnvironmentVariable）之后，
// 让资源管理器立刻刷新环境表，新开的终端马上能看到新值。
func Broadcast() {
	notifyEnvironmentChanged()
}

// GetUser 读取用户环境变量，第二个返回值表示"是否存在"。
func GetUser(name string) (string, bool, error) {
	h, err := openEnvironment(syscall.KEY_READ)
	if err != nil {
		return "", false, err
	}
	defer syscall.RegCloseKey(h)

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", false, err
	}
	buf := make([]uint16, 512)
	for {
		n := uint32(len(buf) * 2)
		var typ uint32
		err := syscall.RegQueryValueEx(h, namePtr, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n)
		if err != nil {
			if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, errNotFound) {
				return "", false, nil
			}
			if errors.Is(err, syscall.ERROR_MORE_DATA) {
				// n 已经被填成需要的字节数，直接加长再来一次
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

// DeleteUser 删除用户环境变量；变量本来就不存在时返回 nil（uninstall 必须可重复执行）。
func DeleteUser(name string) error {
	h, err := openEnvironment(syscall.KEY_READ | syscall.KEY_WRITE)
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(h)
	if err := deleteValue(h, name); err != nil {
		return err
	}
	notifyEnvironmentChanged()
	return nil
}

func deleteValue(h syscall.Handle, name string) error {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	err = regDeleteValue(h, namePtr)
	if err != nil && (errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, errNotFound)) {
		return nil
	}
	return err
}

// syscall 只导出了 RegOpenKeyEx/RegQueryValueEx/RegCloseKey，
// 写入和删除得自己去 advapi32 里取。
var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procRegSetValueEx  = advapi32.NewProc("RegSetValueExW")
	procRegDeleteValue = advapi32.NewProc("RegDeleteValueW")
)

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

var (
	user32             = syscall.NewLazyDLL("user32.dll")
	sendMessageTimeout = user32.NewProc("SendMessageTimeoutW")
)

const (
	hwndBroadcast   = 0xffff
	wmSettingChange = 0x001A
	smtoAbortIfHung = 0x0002
)

// notifyEnvironmentChanged 广播环境变量变更。调不通也无所谓（广播是"尽力而为"），
// 所以这里刻意吞掉错误——真正需要立刻生效的子进程会拿到显式传入的 env。
func notifyEnvironmentChanged() {
	lparam, err := syscall.UTF16PtrFromString("Environment")
	if err != nil {
		return
	}
	var result uintptr
	_, _, _ = sendMessageTimeout.Call(
		uintptr(hwndBroadcast),
		uintptr(wmSettingChange),
		0,
		uintptr(unsafe.Pointer(lparam)),
		uintptr(smtoAbortIfHung),
		uintptr(2000),
		uintptr(unsafe.Pointer(&result)),
	)
}
