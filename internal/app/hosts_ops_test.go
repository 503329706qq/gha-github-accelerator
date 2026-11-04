package app

import (
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/hosts"
)

func TestForeignLoopbackLines(t *testing.T) {
	mine := string(hosts.Render([]string{"github.com", "api.github.com"}))
	cases := []struct {
		name string
		body string
		want int
	}{
		{"只有自己的块", mine, 0},
		{"空文件", "", 0},
		{"只有注释", "# 127.0.0.1 example.com\n", 0},
		{"别人的加速器块", "# >>> other >>>\n127.0.0.1 example.com\n# <<< other <<<\n", 1},
		{"自己的块 + 别人一行", mine + "127.0.0.1 example.com\n", 1},
		{"IPv6 回环也算", "::1 example.com\n", 1},
		{"普通映射不算", "10.0.0.1 example.com\n", 0},
		{"自己的块之后又开始别人的块", mine + "127.0.0.1 a.test\n127.0.0.1 b.test\n", 2},
	}
	for _, c := range cases {
		if got := foreignLoopbackLines(c.body); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}
