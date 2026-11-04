// Package gitcfg 处理 git 的 url.<base>.insteadOf 重写规则。
//
// 现实背景：这台机器的全局配置里有一条
//
//	url.https://gh-proxy.org/https://github.com/.insteadOf = https://github.com/
//
// 它把 git 的所有 github 流量导到第三方代理。gha 要把流量收回本地代理，
// 所以 install 时备份并移除这类规则，uninstall 时原样加回去。
//
// 直接调 `git config` 而不是自己解析/重写 .gitconfig：git 的配置格式有 include、
// 条件 include、多值、转义等一堆边角，自己写解析器迟早出事。
package gitcfg

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Entry 是一条 url.<base>.insteadOf 重写规则。
type Entry struct {
	Key       string // 完整配置键，如 url.https://gh-proxy.org/https://github.com/.insteadOf
	Base      string // 键中间那段，如 https://gh-proxy.org/https://github.com/
	InsteadOf string // 被替换的前缀，如 https://github.com/
}

// Rewrites 列出全局配置里所有 insteadOf 规则（每条值算一条）。
func Rewrites() ([]Entry, error) {
	out, err := run("-z", "--get-regexp", `^url\..*\.insteadOf$`)
	if err != nil {
		var exitErr *exec.ExitError
		// 没有任何匹配时 git 以 1 退出，这不是错误
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("git config --get-regexp: %w (%s)", err, out)
	}

	var entries []Entry
	for _, rec := range strings.Split(string(out), "\x00") {
		if rec == "" {
			continue
		}
		// -z 模式下记录形如 "key\nvalue"
		key, value, ok := strings.Cut(rec, "\n")
		if !ok {
			continue
		}
		base := baseOf(key)
		if base == "" {
			continue
		}
		// git 会把键名统一成小写（.insteadof），这里恢复成文档里的写法，
		// 免得调用方打印出来的东西和别人习惯看到的不一样（git 本身大小写不敏感）。
		entries = append(entries, Entry{Key: "url." + base + ".insteadOf", Base: base, InsteadOf: value})
	}
	return entries, nil
}

// baseOf 从 url.<base>.insteadOf 里抠出 <base>（键名大小写不敏感）。
func baseOf(key string) string {
	lower := strings.ToLower(key)
	if !strings.HasPrefix(lower, "url.") || !strings.HasSuffix(lower, ".insteadof") {
		return ""
	}
	return key[len("url.") : len(key)-len(".insteadof")]
}

// Remove 删除一条具体规则；同键下的其它值保持不变。
func Remove(e Entry) error {
	if e.Key == "" {
		return errors.New("gitcfg: empty key")
	}
	// value-pattern 是 POSIX 扩展正则，锚定 + 转义后只命中这一条值。
	pattern := "^" + regexp.QuoteMeta(e.InsteadOf) + "$"
	if out, err := run("--unset", e.Key, pattern); err != nil {
		return fmt.Errorf("git config --unset %s: %w (%s)", e.Key, err, out)
	}
	return nil
}

// Add 追加一条规则（同键下可多值，不影响已有值）。
func Add(e Entry) error {
	if e.Key == "" {
		return errors.New("gitcfg: empty key")
	}
	if out, err := run("--add", e.Key, e.InsteadOf); err != nil {
		return fmt.Errorf("git config --add %s: %w (%s)", e.Key, err, out)
	}
	return nil
}

// run 执行 `git config --global <args...>`，返回合并后的输出。
func run(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"config", "--global"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
