// Command gha 是只加速 GitHub 的本地反向代理。
//
// 用法见 `gha help`；文档见 README。
package main

import (
	"os"

	"github.com/503329706qq/gha-github-accelerator/internal/app"
)

// version 由构建脚本用 -ldflags "-X main.version=..." 注入。
var version = "dev"

func main() {
	app.Version = version
	os.Exit(app.Run(os.Args[1:]))
}
