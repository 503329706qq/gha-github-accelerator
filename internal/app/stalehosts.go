package app

import (
	"fmt"

	"github.com/503329706qq/gha-github-accelerator/internal/hosts"
)

// hostsState 描述 hosts 文件里我方块的现状。
//
// 这个信息只在"连不上运行中的实例"时有用：hosts 方案最危险的失败模式就是
// 进程没了、hosts 还指着 127.0.0.1——此时 GitHub 是彻底不通的，而用户看到的
// 只是"网页打不开"，很难联想到是加速器没启动。
type hostsState struct {
	Present bool
	Lines   int
	Err     error
}

func readHostsState(path string) hostsState {
	present, lines, err := hosts.Status(path)
	if err != nil {
		return hostsState{Err: err}
	}
	return hostsState{Present: present, Lines: lines}
}

// staleHostsHint 返回一句"为什么现在打不开 GitHub"的说明；没残留就返回空串。
func staleHostsHint(st hostsState) string {
	if !st.Present {
		return ""
	}
	return fmt.Sprintf(
		"hosts 里仍留着 gha 的 %d 行记录：访问 GitHub 会连到没人监听的 127.0.0.1，等于全断。\n"+
			"     修复：gha stop（会自动提权还原 hosts），或者 gha run（重新接管）", st.Lines)
}
