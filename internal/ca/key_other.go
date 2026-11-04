//go:build !windows

package ca

import "os"

// 非 Windows 上没有 DPAPI，退化为 0600 权限位（POSIX 下它是真的权限）。
func writeKey(path string, pemBytes []byte) error {
	return os.WriteFile(path, pemBytes, 0o600)
}

func readKey(path string) ([]byte, error) {
	return os.ReadFile(path)
}
