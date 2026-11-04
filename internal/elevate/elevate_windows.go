//go:build windows

// Package elevate 负责"以管理员身份重新启动自己"。
//
// gha 需要管理员的原因只有两个：写 hosts（C:\Windows\...\etc\hosts 的 ACL 只给
// Administrators 写权限）和绑 80/443（Windows 上低于 1024 的端口不需要特权，
// 但为了避免端口被别人占着时出现半启动状态，仍然要求提权后统一处理）。
//
// 如果系统的 UAC 策略是"管理员组静默提权"（ConsentPromptBehaviorAdmin=0），提权不弹窗；
// 但代码不能假设这一点，所以提权失败要给出可读的提示。
package elevate

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	advapi32  = syscall.NewLazyDLL("advapi32.dll")
	shell32   = syscall.NewLazyDLL("shell32.dll")
	kernel32  = syscall.NewLazyDLL("kernel32.dll")
	procSID   = advapi32.NewProc("ConvertStringSidToSidW")
	procCheck = advapi32.NewProc("CheckTokenMembership")
	procFree  = kernel32.NewProc("LocalFree")
	procShell = shell32.NewProc("ShellExecuteW")
)

const swShowNormal = 1

const swHide = 0

// IsAdmin 判断当前进程是否在管理员组里（等价于 `net session` 能跑通）。
func IsAdmin() bool {
	sidName, err := syscall.UTF16PtrFromString("S-1-5-32-544")
	if err != nil {
		return false
	}
	var sid uintptr
	if r, _, _ := procSID.Call(uintptr(unsafe.Pointer(sidName)), uintptr(unsafe.Pointer(&sid))); r == 0 {
		return false
	}
	defer procFree.Call(sid)

	var isMember int32
	r, _, _ := procCheck.Call(0, sid, uintptr(unsafe.Pointer(&isMember)))
	return r != 0 && isMember != 0
}

// Relaunch 用 "runas" 动词重新启动同一个可执行文件，参数原样带过去。
// 隐藏窗口给计划任务用（登录自启时不该弹黑框）。
func Relaunch(exe string, argv []string, hidden bool) error {
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return err
	}
	file, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	params, err := syscall.UTF16PtrFromString(QuoteArgs(argv))
	if err != nil {
		return err
	}
	show := uintptr(swShowNormal)
	if hidden {
		show = swHide
	}
	r, _, callErr := procShell.Call(0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		0,
		show,
	)
	// ShellExecuteW 的返回值 >32 才算成功
	if r <= 32 {
		if r == 5 || r == 1223 {
			return fmt.Errorf("提权被拒绝（UAC 取消）：code %d", r)
		}
		return fmt.Errorf("ShellExecuteW 失败：code %d (%v)", r, callErr)
	}
	return nil
}

// QuoteArgs 按 CommandLineToArgvW 的规则把参数拼成一条命令行。
func QuoteArgs(argv []string) string {
	out := make([]string, 0, len(argv))
	for _, a := range argv {
		if a == "" {
			out = append(out, `""`)
			continue
		}
		if !strings.ContainsAny(a, " \t\"") {
			out = append(out, a)
			continue
		}
		out = append(out, `"`+strings.ReplaceAll(a, `"`, `\"`)+`"`)
	}
	return strings.Join(out, " ")
}
