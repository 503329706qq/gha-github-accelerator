//go:build windows

package app

import (
	"sync/atomic"
	"syscall"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	user32                    = syscall.NewLazyDLL("user32.dll")
	procSetConsoleCtrlHandler = kernel32.NewProc("SetConsoleCtrlHandler")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
	procShowWindow            = user32.NewProc("ShowWindow")

	consoleCallback uintptr
	// 回调只能拿到 ctrlType，真正的清理逻辑用 atomic 挂进来。
	consoleHook atomic.Value // func()
)

// watchConsole 注册控制台事件回调：关闭窗口 / 注销 / 关机 / Ctrl+C 都触发退出。
// 返回的函数用于注销回调（正常退出路径上调用，避免重复触发）。
func watchConsole(onExit func()) func() {
	consoleHook.Store(onExit)
	if consoleCallback == 0 {
		consoleCallback = syscall.NewCallback(func(ctrlType uint32) uintptr {
			switch ctrlType {
			case 0, 1, 2, 5, 6: // CTRL_C / CTRL_BREAK / CTRL_CLOSE / LOGOFF / SHUTDOWN
				if fn, ok := consoleHook.Load().(func()); ok && fn != nil {
					fn()
				}
			}
			// 返回 0 表示"交给下一个处理器"，进程照常退出
			return 0
		})
	}
	procSetConsoleCtrlHandler.Call(consoleCallback, 1)
	return func() { procSetConsoleCtrlHandler.Call(consoleCallback, 0) }
}

// hideConsole 给登录自启用：自启时不要把黑框弹到用户脸上。
func hideConsole() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	const swHide = 0
	procShowWindow.Call(hwnd, swHide)
}
