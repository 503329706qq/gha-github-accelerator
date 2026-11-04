package app

import (
	"fmt"
	"os"
	"strings"

	"github.com/503329706qq/gha-github-accelerator/internal/hosts"
)

// hostsRemove 摘掉 hosts 里我方块（uninstall 用）。备份写到数据目录，不留在 etc 里。
func hostsRemove(backupDir string) (bool, error) { return hosts.RestoreTo(hostsPath(), backupDir) }

// hostsPrivilegeHint 给出"当前环境里会挡住 gha 的那件事"，没有就返回空串。
func hostsPrivilegeHint() (string, error) {
	if !isAdmin() {
		return "当前不是管理员，写 hosts 会失败（install/run 应自动提权，这里只是提醒）", nil
	}
	raw, err := os.ReadFile(hostsPath())
	if err != nil {
		return "", err
	}
	if n := foreignLoopbackLines(string(raw)); n > 0 {
		return fmt.Sprintf("hosts 里还有 %d 条别的程序写的 127.0.0.1 记录（多半是另一个加速器）："+
			"它和 gha 都要占 80/443，同一时间只能用一个（退出那个程序后它通常会自己清理）", n), nil
	}
	return "", nil
}

// foreignLoopbackLines 数一数"不是我方块、却把域名指到回环地址"的行。
// 这类行几乎总是另一个本地加速器留下的：它和 gha 抢同一个 443，
// 所以 install 结束时值得提醒一句。我自己写的块（含块内的 127.0.0.1）不算。
func foreignLoopbackLines(body string) int {
	n := 0
	inBlock := false
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if !inBlock && t == hosts.BeginMarker {
			inBlock = true
			continue
		}
		if inBlock && t == hosts.EndMarker {
			inBlock = false
			continue
		}
		if inBlock || t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) >= 2 && (f[0] == "127.0.0.1" || f[0] == "::1") {
			n++
		}
	}
	return n
}
