package app

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/503329706qq/gha-github-accelerator/internal/autostart"
	"github.com/503329706qq/gha-github-accelerator/internal/ca"
	"github.com/503329706qq/gha-github-accelerator/internal/config"
	"github.com/503329706qq/gha-github-accelerator/internal/envvars"
	"github.com/503329706qq/gha-github-accelerator/internal/gitcfg"
	"github.com/503329706qq/gha-github-accelerator/internal/store"
)

// gitHubPrefix 是要从 git 全局配置里摘掉的 insteadOf 目标。
const gitHubPrefix = "https://github.com/"

func cmdInstall(a Args) int {
	if relaunched, code := requireAdmin(a, false); relaunched {
		return code
	}
	cfg, cfgFile, err := loadConfig(a)
	if err != nil {
		return fail(err)
	}
	p := cfg.P()
	if err := os.MkdirAll(p.CA(), 0o700); err != nil {
		return fail(err)
	}

	// 安装是多步副作用操作：每一步都登记撤销动作，任何一步失败就逆序回滚。
	// 否则"证书已进 LocalMachine\Root、CRL 安装失败"这种半成品会让用户看到
	// "安装失败"，而系统信任根其实已经被改过，且没有 CRL 兜底。
	var undo []func()
	abort := func(err error) int {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		return fail(err)
	}

	fmt.Println("== 1/6 生成根证书 ==")
	c, err := ca.LoadOrCreate(ca.Options{
		CertPath: p.CertPEM(),
		KeyPath:  p.KeyPEM(),
		CRLURL:   cfg.CRLHTTPBase + "/ca.crl",
	})
	if err != nil {
		return fail(err)
	}
	fmt.Printf("   %s（CN=%s）\n", p.CertPEM(), c.Certificate().Subject.CommonName)

	fmt.Println("== 2/6 装入证书存储 ==")
	if err := store.InstallCert(store.LocalMachine, c.CertPEM()); err != nil {
		return abort(fmt.Errorf("安装根证书：%w", err))
	}
	undo = append(undo, func() { _ = store.DeleteCert(store.LocalMachine, c.CertPEM()) })
	der, err := c.CRL()
	if err != nil {
		return abort(fmt.Errorf("生成 CRL：%w", err))
	}
	if err := store.InstallCRL(store.LocalMachine, der); err != nil {
		return abort(fmt.Errorf("安装 CRL：%w", err))
	}
	undo = append(undo, func() { _, _ = store.DeleteCRLsByIssuer(store.LocalMachine, c.CertPEM()) })
	fmt.Println("   LocalMachine\\Root 与 LocalMachine\\CA 已更新（机器级，所有账户生效）")

	fmt.Println("== 3/6 配置开发工具信任链 ==")
	if bundlePath, ok := buildBundle(p, c.CertPEM()); ok {
		mustWarn(envvars.SetUser("SSL_CERT_FILE", bundlePath))
		mustWarn(envvars.SetUser("REQUESTS_CA_BUNDLE", bundlePath))
		undo = append(undo, func() {
			_ = envvars.DeleteUser("SSL_CERT_FILE")
			_ = envvars.DeleteUser("REQUESTS_CA_BUNDLE")
		})
		fmt.Printf("   Python（SSL_CERT_FILE / REQUESTS_CA_BUNDLE）= %s\n", bundlePath)
	} else {
		fmt.Println("   ! 没找到 certifi 的 cacert.pem（没装 Python？），跳过 Python 相关变量")
	}
	mustWarn(envvars.SetUser("NODE_EXTRA_CA_CERTS", p.CertPEM()))
	undo = append(undo, func() { _ = envvars.DeleteUser("NODE_EXTRA_CA_CERTS") })
	fmt.Printf("   Node（NODE_EXTRA_CA_CERTS）= %s\n", p.CertPEM())

	fmt.Println("== 4/6 处理 git 的 insteadOf 规则 ==")
	if n, err := removeGitRewrites(p); err != nil {
		mustWarn(err)
	} else if n == 0 {
		fmt.Println("   没有指向 GitHub 的 insteadOf 规则，无需改动")
	} else {
		undo = append(undo, func() { _, _ = restoreGitRewrites(p) })
		fmt.Printf("   已移除 %d 条规则（原始值备份在 %s，uninstall 会加回去）\n", n, p.GitBackup())
	}

	fmt.Println("== 5/6 注册登录自启 ==")
	if cfg.Autostart {
		self, err := os.Executable()
		if err != nil {
			mustWarn(err)
		} else if installed, err := installSelf(self, p.BinExe()); err != nil {
			mustWarn(err)
		} else if err := autostart.Install(installed); err != nil {
			mustWarn(fmt.Errorf("注册登录自启：%w", err))
		} else {
			undo = append(undo, func() { _ = autostart.Remove() })
			fmt.Printf("   已安装到 %s\n", installed)
			fmt.Printf("   登录自启项已写入 HKCU\\...\\Run\\%s（登录后自动静默提权启动）\n", autostart.ValueName)
		}
	} else {
		fmt.Println("   配置里 autostart=false，跳过")
	}

	fmt.Println("== 6/6 检查当前环境 ==")
	reportEnvironment(cfg)

	fmt.Printf(`
安装完成。注意 install 刻意不写 hosts——GitHub 现在还是直连。
要开始加速，请运行：

    gha run

（运行时会先绑定 80/443，成功后才写 hosts；Ctrl+C 或 gha stop 会还原。）
配置文件：%s
`, cfgFile)
	return 0
}

func cmdUninstall(a Args) int {
	if relaunched, code := requireAdmin(a, false); relaunched {
		return code
	}
	cfg, _, err := loadConfig(a)
	if err != nil {
		return fail(err)
	}
	p := cfg.P()

	fmt.Println("== 1/5 还原 hosts ==")
	if changed, err := hostsRemove(p.BackupDir()); err != nil {
		mustWarn(err)
	} else if changed {
		fmt.Println("   已移除 gha 的 hosts 块")
	} else {
		fmt.Println("   hosts 里没有 gha 的块")
	}

	fmt.Println("== 2/5 移除证书与 CRL ==")
	if pemBytes, err := os.ReadFile(p.CertPEM()); err == nil {
		if err := store.DeleteCert(store.LocalMachine, pemBytes); err != nil {
			mustWarn(fmt.Errorf("删除根证书：%w", err))
		} else {
			fmt.Println("   已从 LocalMachine\\Root 删除根证书")
		}
		if n, err := store.DeleteCRLsByIssuer(store.LocalMachine, pemBytes); err != nil {
			mustWarn(fmt.Errorf("删除 CRL：%w", err))
		} else {
			fmt.Printf("   已从 LocalMachine\\CA 删除 %d 张 CRL\n", n)
		}
	} else {
		fmt.Println("   CA 文件不存在，跳过（可能已卸载过）")
	}

	fmt.Println("== 3/5 清理环境变量 ==")
	for _, name := range []string{"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"} {
		mustWarn(envvars.DeleteUser(name))
	}
	fmt.Println("   已删除 NODE_EXTRA_CA_CERTS / SSL_CERT_FILE / REQUESTS_CA_BUNDLE")

	fmt.Println("== 4/5 恢复 git 规则 ==")
	if n, err := restoreGitRewrites(p); err != nil {
		mustWarn(err)
	} else if n == 0 {
		fmt.Println("   没有备份，无需恢复")
	} else {
		fmt.Printf("   已恢复 %d 条 insteadOf 规则\n", n)
	}

	fmt.Println("== 5/5 删除登录自启 ==")
	if err := autostart.Remove(); err != nil {
		mustWarn(err)
	} else {
		fmt.Printf("   登录自启项 %q 已删除\n", autostart.ValueName)
	}

	if a.Purge {
		if err := os.RemoveAll(p.DataDir); err != nil {
			// 最常见的原因是"正在从 %LOCALAPPDATA%\gha\bin\gha.exe 运行"：
			// Windows 不允许删除正在运行的 exe，目录里会留下一份副本。
			mustWarn(fmt.Errorf("删除数据目录：%w（如果是正在运行的那个 gha.exe，退出后再手动删一次）", err))
		} else {
			fmt.Printf("\n卸载完成，数据目录 %s 已删除。\n", p.DataDir)
			return 0
		}
	}
	fmt.Printf("\n卸载完成。CA 私钥仍保留在 %s（加 --purge 可连数据目录一起删掉）。\n", p.DataDir)
	return 0
}

func cmdCA(a Args) int {
	cfg, _, err := loadConfig(a)
	if err != nil {
		return fail(err)
	}
	p := cfg.P()
	pemBytes, err := os.ReadFile(p.CertPEM())
	if err != nil {
		return fail(fmt.Errorf("还没有根证书，先跑 gha install：%w", err))
	}
	fmt.Printf("# %s\n%s", p.CertPEM(), pemBytes)
	return 0
}

// buildBundle 把 certifi 的 cacert.pem 和我们的 CA 拼在一起。
// 为什么必须拼：Python 的 SSL_CERT_FILE 是"整体替换"语义，只放我们自己的 CA
// 会让所有非 GitHub 站点的 TLS 校验失败。
func buildBundle(p config.Paths, ourPEM []byte) (string, bool) {
	base, ok := pythonCACert()
	if !ok {
		return "", false
	}
	existing, err := os.ReadFile(base)
	if err != nil {
		return "", false
	}
	var sb strings.Builder
	sb.Write(existing)
	if !strings.HasSuffix(string(existing), "\n") {
		sb.WriteString("\n")
	}
	sb.WriteString("# gha root CA\n")
	sb.Write(ourPEM)
	if err := os.WriteFile(p.Bundle(), []byte(sb.String()), 0o644); err != nil {
		mustWarn(fmt.Errorf("写 bundle：%w", err))
		return "", false
	}
	return p.Bundle(), true
}

// pythonCACert 通过 certifi 找到它自带的 CA bundle。
func pythonCACert() (string, bool) {
	for _, exe := range []string{"python", "python3", "py"} {
		if _, err := exec.LookPath(exe); err != nil {
			continue
		}
		out, err := exec.Command(exe, "-c", "import certifi;print(certifi.where())").Output()
		if err != nil {
			continue
		}
		path := strings.TrimSpace(string(out))
		if path != "" {
			return path, true
		}
	}
	return "", false
}

// removeGitRewrites 备份并移除指向 GitHub 的 insteadOf 规则，返回移除条数。
func removeGitRewrites(p config.Paths) (int, error) {
	all, err := gitcfg.Rewrites()
	if err != nil {
		return 0, fmt.Errorf("读取 git 配置：%w", err)
	}
	var targeted []gitcfg.Entry
	for _, e := range all {
		if strings.EqualFold(e.InsteadOf, gitHubPrefix) {
			targeted = append(targeted, e)
		}
	}
	if len(targeted) == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(filepath.Dir(p.GitBackup()), 0o755); err != nil {
		return 0, err
	}
	raw, err := json.MarshalIndent(targeted, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(p.GitBackup(), raw, 0o644); err != nil {
		return 0, fmt.Errorf("备份 git 规则：%w", err)
	}
	for _, e := range targeted {
		if err := gitcfg.Remove(e); err != nil {
			return 0, fmt.Errorf("移除规则 %s：%w", e.Key, err)
		}
	}
	return len(targeted), nil
}

// restoreGitRewrites 把备份的规则加回 git 全局配置。
func restoreGitRewrites(p config.Paths) (int, error) {
	raw, err := os.ReadFile(p.GitBackup())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var entries []gitcfg.Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return 0, fmt.Errorf("解析 %s：%w", p.GitBackup(), err)
	}
	for _, e := range entries {
		if err := gitcfg.Add(e); err != nil {
			return 0, err
		}
	}
	if err := os.Remove(p.GitBackup()); err != nil {
		mustWarn(err)
	}
	return len(entries), nil
}

// reportEnvironment 打印那些"会影响是否能加速"的现场事实，帮用户自己判断。
func reportEnvironment(cfg *config.Config) {
	if priv, err := hostsPrivilegeHint(); err == nil && priv != "" {
		fmt.Printf("   ! %s\n", priv)
	}
	fmt.Printf("   监听：https=%s http=%s control=%s\n", cfg.Listen.HTTPS, cfg.Listen.HTTP, cfg.Listen.Control)
	fmt.Printf("   域名：%d 个（内置 + 追加）\n", len(cfg.AllDomains()))
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "gha: %v\n", err)
	return 1
}

// mustWarn 把"不该中断流程"的错误打出来，但继续走。
func mustWarn(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "   ! %v\n", err)
	}
}
