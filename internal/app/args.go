package app

import (
	"fmt"
	"strings"
)

// Args 是解析后的命令行。
type Args struct {
	Cmd        string
	HTTPS      string // 覆盖监听的 443 地址（测试时用高位端口）
	HTTP       string // 覆盖监听的 80 地址
	Control    string // 覆盖控制接口地址
	ConfigPath string // 覆盖配置文件路径
	DataDir    string // 覆盖数据目录
	NoHosts    bool   // 不写 hosts（自测/演示用）
	Autostart  bool   // 由登录自启项启动：隐藏控制台窗口
	Purge      bool   // uninstall 时连数据目录一起删掉
	Verbose    bool
}

// Commands 是全部可用子命令，帮助信息与错误提示共用这一份。
var Commands = []string{"install", "uninstall", "run", "stop", "status", "ca", "version", "help"}

// ParseArgs 解析 os.Args[1:]。刻意不引第三方 flag 库：子命令 + 少量标志，
// 手写反而更好控制错误提示（"未知命令"能直接列出可用命令）。
func ParseArgs(argv []string) (Args, error) {
	if len(argv) == 0 {
		return Args{}, fmt.Errorf("缺少子命令；可用：%s", strings.Join(Commands, ", "))
	}
	a := Args{Cmd: argv[0]}
	if !knownCommand(a.Cmd) {
		return Args{}, fmt.Errorf("未知命令 %q；可用：%s", a.Cmd, strings.Join(Commands, ", "))
	}

	rest := argv[1:]
	for i := 0; i < len(rest); i++ {
		flag := rest[i]
		name, inline, hasInline := strings.Cut(flag, "=")
		value := func() (string, error) {
			if hasInline {
				return inline, nil
			}
			if i+1 >= len(rest) {
				return "", fmt.Errorf("标志 %s 需要一个值", name)
			}
			i++
			return rest[i], nil
		}
		var err error
		switch name {
		case "--https":
			a.HTTPS, err = value()
		case "--http":
			a.HTTP, err = value()
		case "--control":
			a.Control, err = value()
		case "--config":
			a.ConfigPath, err = value()
		case "--data-dir":
			a.DataDir, err = value()
		case "--no-hosts":
			if hasInline {
				return Args{}, fmt.Errorf("--no-hosts 不接受值")
			}
			a.NoHosts = true
		case "--autostart":
			a.Autostart = true
		case "--purge":
			a.Purge = true
		case "-v", "--verbose":
			a.Verbose = true
		case "-h", "--help":
			a.Cmd = "help"
		default:
			return Args{}, fmt.Errorf("未知标志 %q", flag)
		}
		if err != nil {
			return Args{}, err
		}
	}
	return a, nil
}

func knownCommand(c string) bool {
	for _, k := range Commands {
		if k == c {
			return true
		}
	}
	return false
}
