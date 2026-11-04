package app

import (
	"os"
	"path/filepath"
)

// hostsPath 返回系统 hosts 的路径。
func hostsPath() string {
	if sr := os.Getenv("SystemRoot"); sr != "" {
		return filepath.Join(sr, "System32", "drivers", "etc", "hosts")
	}
	return `C:\Windows\System32\drivers\etc\hosts`
}
