package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// controlURL 拼出控制接口地址（监听地址可能是 127.0.0.1:12080 这种形式）。
func controlURL(cfgListen string) string {
	if strings.HasPrefix(cfgListen, "http://") || strings.HasPrefix(cfgListen, "https://") {
		return strings.TrimSuffix(cfgListen, "/")
	}
	return "http://" + cfgListen
}

func newControlClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second}
}

// cmdStatus 读取运行中实例的状态。不需要管理员：控制接口只绑本机回环。
//
// 连不上实例时不只是报错：还要看一眼 hosts 里是不是还留着 gha 的块。留着就意味着
// GitHub 现在全部指向 127.0.0.1、必然打不开，得把"怎么救回来"直接写出来。
func cmdStatus(a Args) int {
	cfg, _, err := loadConfig(a)
	if err != nil {
		return fail(err)
	}
	url := controlURL(cfg.Listen.Control) + "/status"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fail(err)
	}
	req.Header.Set("X-Gha-Token", cfg.Token)
	resp, err := newControlClient().Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gha: 连不上 %s（实例没在运行）：%v\n", url, err)
		if hint := staleHostsHint(readHostsState(hostsPath())); hint != "" {
			fmt.Fprintf(os.Stderr, "gha: %s\n", hint)
		} else {
			fmt.Fprintln(os.Stderr, "gha: hosts 里没有 gha 的块，GitHub 走直连，不受影响。")
		}
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "gha: %s 返回 %d：%s\n", url, resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}
	// 原样透出 JSON，但缩进一下方便肉眼读；解析失败就退回原始字节。
	var v any
	if err := json.Unmarshal(body, &v); err == nil {
		pretty, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(pretty))
		return 0
	}
	fmt.Println(string(body))
	return 0
}

// cmdStop 通知运行中的实例优雅退出；实例已经不在了就自己还原 hosts。
func cmdStop(a Args) int {
	cfg, _, err := loadConfig(a)
	if err != nil {
		return fail(err)
	}
	url := controlURL(cfg.Listen.Control) + "/quit"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return fail(err)
	}
	req.Header.Set("X-Gha-Token", cfg.Token)
	resp, err := newControlClient().Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gha: 连不上 %s（实例没在运行）：%v\n", url, err)
		// 兜底：实例已经没了，但 hosts 可能还指着 127.0.0.1。此时没人能"优雅退出"，
		// 只能就地还原——这是用户最需要的"一键救回 GitHub"。
		st := readHostsState(hostsPath())
		if !st.Present {
			fmt.Println("hosts 里没有 gha 的块，无需还原。")
			return 0
		}
		fmt.Printf("hosts 里仍有 gha 的 %d 行记录，直接还原（需要管理员）…\n", st.Lines)
		if stop, code := requireAdmin(a, false); stop {
			return code
		}
		changed, rerr := hostsRemove(cfg.P().BackupDir())
		if rerr != nil {
			return fail(rerr)
		}
		if changed {
			fmt.Println("hosts 已还原，GitHub 恢复直连。")
		} else {
			fmt.Println("hosts 本来就没有 gha 的块。")
		}
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "gha: %s 返回 %d：%s\n", url, resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}
	fmt.Println("已通知 gha 退出（它会先还原 hosts）。")
	return 0
}
