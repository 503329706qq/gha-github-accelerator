// Package autostart 负责"登录时自动启动"。
//
// 用 HKCU\Software\Microsoft\Windows\CurrentVersion\Run 而不是计划任务：
// 2026-11-03 在本机实测，Task Scheduler 直接拉起的 gha 拿不到正常的用户凭据——
// 既写不进 %LOCALAPPDATA%\gha\logs（打开就失败），连 GitHub 都只能返回 502，
// 同样的二进制用 Start-Process 或由 Run 键拉起则完全正常（200 / 0.4s）。
//
// Run 键是"以登录用户身份、在用户会话里"启动的，gha 自己再走 ShellExecuteW
// "runas" 静默提权（本机 UAC ConsentPromptBehaviorAdmin=0，不弹窗）就能绑 443。
// 代价是别的机器上如果开了 UAC 弹窗提示，登录时会看到一次提权框；
// 这比"自启了但连不上网"要好得多。
package autostart

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/503329706qq/gha-github-accelerator/internal/regkey"
)

const (
	// ValueName 是 Run 键下这个自启值的名字。
	ValueName = "gha"
	// legacyTaskName 是旧版本用过的计划任务名；install/uninstall 顺手清理，
	// 免得升级后两个机制同时拉起两个实例。
	legacyTaskName = "gha"
)

// SubKey 允许测试改到一次性的子键下，生产固定为 Run 键。
var SubKey = regkey.RunKey

// Value 返回自启项的内容：带引号的绝对路径 + 自启参数。
func Value(exe string) string { return `"` + exe + `" run --autostart` }

// Install 写入登录自启项，并尽力删掉旧的计划任务。
func Install(exe string) error {
	if err := regkey.SetString(SubKey, ValueName, Value(exe)); err != nil {
		return fmt.Errorf("写自启项: %w", err)
	}
	removeLegacyTask()
	return nil
}

// Remove 删除登录自启项与遗留计划任务；都不存在时返回 nil。
func Remove() error {
	if err := regkey.DeleteValue(SubKey, ValueName); err != nil {
		return fmt.Errorf("删自启项: %w", err)
	}
	removeLegacyTask()
	return nil
}

// Current 读回自启项，供 status 展示（第二个返回值表示是否配置了）。
func Current() (string, bool, error) { return regkey.GetString(SubKey, ValueName) }

// removeLegacyTask 删除旧版计划任务。这是"尽力而为"：任务不存在、或者当前
// 不是管理员（schtasks 会拒绝访问）都直接忽略——自启项本身已经不依赖它了。
func removeLegacyTask() {
	if SubKey != regkey.RunKey {
		return // 测试环境，别动真实任务
	}
	out, err := exec.Command("schtasks", "/Delete", "/TN", legacyTaskName, "/F").CombinedOutput()
	if err == nil {
		return
	}
	msg := strings.ToLower(string(out))
	if strings.Contains(msg, "cannot find") || strings.Contains(msg, "找不到") ||
		strings.Contains(msg, "拒绝访问") || strings.Contains(msg, "access is denied") {
		return
	}
}
