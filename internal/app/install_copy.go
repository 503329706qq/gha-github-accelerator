package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// installSelf 把当前运行的 gha.exe 复制到数据目录（%LOCALAPPDATA%\gha\bin\gha.exe），
// 返回写进登录自启项、也就是以后该被启动的那个路径。
//
// 为什么不让自启项直接指向"用户当初运行的那个 exe"：
//   - 工程目录里的 dist 会被重新编译覆盖，运行中的 exe 被占用会导致编译失败；
//   - 用户随手移动/删除工程目录，自启就断了，而 hosts 还指着 127.0.0.1，
//     GitHub 会全断——这种失败模式代价太高。
//
// 复制时先写临时文件再改名，避免中途断电留下半个 exe 还被自启项引用。
func installSelf(cfgPathExe, dst string) (string, error) {
	src := cfgPathExe
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return "", err
	}
	absDst, err := filepath.Abs(dst)
	if err != nil {
		return "", err
	}
	if equalFoldPath(absSrc, absDst) {
		return absDst, nil
	}
	if err := os.MkdirAll(filepath.Dir(absDst), 0o755); err != nil {
		return "", fmt.Errorf("创建 %s: %w", filepath.Dir(absDst), err)
	}
	tmp := absDst + ".tmp"
	if err := copyFile(absSrc, tmp); err != nil {
		return "", fmt.Errorf("复制自身: %w", err)
	}
	// 目标可能正被上一个实例占用（升级场景）：先试改名替换，失败就报错让人先 stop。
	if err := os.Rename(tmp, absDst); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("安装到 %s（该文件可能正在运行，先执行 gha stop）: %w", absDst, err)
	}
	return absDst, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// equalFoldPath 比较两个绝对路径是否指向同一个文件。Windows 路径大小写不敏感，
// 但 filepath.Clean 不做大小写折叠，所以这里显式转小写再比。
func equalFoldPath(a, b string) bool {
	if a == b {
		return true
	}
	return filepath.Clean(a) == filepath.Clean(b) ||
		filepath.Clean(lower(a)) == filepath.Clean(lower(b))
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
