// Package app 是 gha 的命令层：把 config/ca/store/proxy/control 这些零件
// 按生命周期拼起来，并处理提权、hosts、自启等"有副作用"的动作。
//
// 生命周期约定：
//
//	install   只装 CA/证书/CRL/环境变量/git 规则/登录自启，**不写 hosts**
//	run       先绑端口，成功后才写 hosts；退出时还原
//	uninstall 全部逆操作
//
// install 不写 hosts 是故意的：install 和 run 之间如果断了，hosts 指向本机
// 却没有进程监听，GitHub 会变成"连不上"，且用户不知道去哪修。
package app

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/503329706qq/gha-github-accelerator/internal/config"
)

// Version 由 -ldflags "-X gha/internal/app.Version=..." 覆盖。
var Version = "dev"

// Usage 是 `gha help` 的输出。
const Usage = `gha —— 只加速 GitHub 的本地反向代理

用法：
  gha install [--config PATH] [--data-dir DIR]     安装（CA、证书、CRL、环境变量、git 规则、自启）
  gha uninstall                                    卸载并还原上面每一项
  gha run [--no-hosts] [--https ADDR] [--http ADDR] [--control ADDR] [-v]
                                                   前台运行；默认接管 443/80 并写 hosts
  gha status                                       读取运行中的实例状态
  gha stop                                         通知运行中的实例退出
  gha ca                                           打印根证书路径与 PEM（方便手动分发）
  gha version                                      版本信息

说明：
  * install 不写 hosts，hosts 由 run 在"端口绑定成功之后"写入、退出时还原；
    这样即使 install 之后没运行，GitHub 也不会被劫持到没人监听的 127.0.0.1。
  * 80/443 是独占端口：本机任何同样接管这两个端口的程序（别的本地反代/加速器）
    与 gha 同一时间只能有一个生效。
  * 自测可以用 --no-hosts + 高位端口：
      gha run --no-hosts --https 127.0.0.1:18443 --http 127.0.0.1:18080
`

// Run 是命令入口，返回进程退出码。
func Run(argv []string) int {
	a, err := ParseArgs(argv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gha: %v\n\n%s", err, Usage)
		return 2
	}
	switch a.Cmd {
	case "help":
		fmt.Print(Usage)
		return 0
	case "version":
		fmt.Printf("gha %s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "install":
		return cmdInstall(a)
	case "uninstall":
		return cmdUninstall(a)
	case "run":
		return cmdRun(a)
	case "status":
		return cmdStatus(a)
	case "stop":
		return cmdStop(a)
	case "ca":
		return cmdCA(a)
	}
	fmt.Fprintf(os.Stderr, "gha: 未实现的命令 %q\n", a.Cmd)
	return 2
}

// requireAdmin 在需要管理员时重新以管理员身份启动自己。
// 返回 (已重启, 退出码)：已重启时调用方应当立刻返回这个退出码。
func requireAdmin(a Args, hidden bool) (bool, int) {
	// GHA_NO_ELEVATE=1 给自测/CI 用：跳过提权，让进程以当前身份继续跑。
	// 只影响"要不要重启自己"，真正的权限检查发生在写 hosts 那一刻（会直接报错）。
	if os.Getenv("GHA_NO_ELEVATE") != "" {
		return false, 0
	}
	if isAdmin() {
		return false, 0
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gha: 取可执行文件路径失败：%v\n", err)
		return true, 1
	}
	if err := relaunchAsAdmin(exe, os.Args[1:], hidden); err != nil {
		fmt.Fprintf(os.Stderr, "gha: 需要管理员权限：%v\n请以管理员身份打开终端后重试。\n", err)
		return true, 1
	}
	fmt.Println("已请求管理员权限，请在新窗口中继续操作。")
	return true, 0
}

// configPath 决定配置文件位置：--config > --data-dir/config.json > 数据目录下。
func configPath(a Args) (string, error) {
	if a.ConfigPath != "" {
		return a.ConfigPath, nil
	}
	dataDir := a.DataDir
	if dataDir == "" {
		dataDir = config.Default().DataDir
	}
	return filepath.Join(dataDir, "config.json"), nil
}

// loadConfig 读配置并补上命令行的覆盖项；token 缺失时生成并落盘。
func loadConfig(a Args) (*config.Config, string, error) {
	path, err := configPath(a)
	if err != nil {
		return nil, "", err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, "", fmt.Errorf("读取配置 %s：%w", path, err)
	}
	if a.DataDir != "" {
		cfg.DataDir = a.DataDir
	}
	// 落盘的只有"配置文件里已有的值 + 必要时新生成的 token"。
	// 命令行的端口/日志级别覆盖只作用于本次进程：否则 README 里那条自测命令
	// `gha run --no-hosts --https 127.0.0.1:18443` 会把 443 永久改成 18443，
	// 下一次不带参数的 `gha run` 只绑 18443，而 hosts 仍把 github.com 指到 443，
	// 结果是"进程在跑、hosts 正常、GitHub 全断"，排查成本极高。
	saved := *cfg
	freshToken := saved.Token == ""
	if freshToken {
		saved.Token = newToken()
	}
	cfg.Token = saved.Token

	if a.HTTPS != "" {
		cfg.Listen.HTTPS = a.HTTPS
	}
	if a.HTTP != "" {
		cfg.Listen.HTTP = a.HTTP
	}
	if a.Control != "" {
		cfg.Listen.Control = a.Control
	}
	if a.Verbose {
		cfg.LogLevel = "debug"
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, "", fmt.Errorf("创建数据目录 %s：%w", cfg.DataDir, err)
	}
	// 只在第一次生成 token 时落盘（`gha status` 靠它鉴权）。
	if freshToken {
		saved.DataDir = cfg.DataDir
		if err := saved.Save(path); err != nil {
			return nil, "", fmt.Errorf("写配置 %s：%w", path, err)
		}
	}
	return cfg, path, nil
}

func newToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败在 Windows 上几乎不可能；真失败也只能退化成时间戳
		return fmt.Sprintf("%d", os.Getpid())
	}
	return hex.EncodeToString(b)
}
