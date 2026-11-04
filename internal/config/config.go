// Package config 负责 gha 的配置加载与内置默认值。
//
// 设计原则：
//   - 缺省即用，配置文件不存在不是错误；
//   - 内置域名为“显式枚举”，因为 hosts 不支持通配符；
//   - 用户配置只能“追加”域名，不能减少内置清单（否则会静默漏掉关键站点）。
package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Listen 是三个监听地址。控制端口与 CRL 分发共用同一个 listener。
type Listen struct {
	HTTPS   string `json:"https"`
	HTTP    string `json:"http"`
	Control string `json:"control"`
}

// Config 是运行期配置。字段名即配置文件里的 JSON 键名。
type Config struct {
	Listen       Listen   `json:"listen"`
	DoHJSON      []string `json:"doh_json"`
	DoHWire      []string `json:"doh_wire"`
	FallbackDNS  string   `json:"fallback_dns"`
	ExtraDomains []string `json:"domains"`
	IPv6         bool     `json:"ipv6"`
	LogLevel     string   `json:"log_level"`
	Token        string   `json:"token"`
	Autostart    bool     `json:"autostart"`
	DataDir      string   `json:"data_dir"`

	// SeedIPs 是"域名 → 已知可用 IP"的种子表，作为 DoH 结果之外的额外候选
	// 交给拨号层竞速。GitHub 的 DNS 答案会在某些时段被整段黑洞（A 记录依旧
	// 返回、连接却超时），种子表让加速器不依赖"这一次 DNS 恰好给了能用的地址"。
	SeedIPs map[string][]string `json:"seed_ips"`

	// CRLHTTPBase 是叶证书里写进 CRLDistributionPoints 的前缀。
	// 单独抽出来是为了自测时能把 12080 换成高位端口。
	CRLHTTPBase string `json:"crl_http_base"`

	// UpstreamScheme 默认 https；仅测试会用 http。
	UpstreamScheme string `json:"-"`
}

// builtinDomains 是附录 A 的显式枚举清单（顺序即 hosts 里的顺序）。
var builtinDomains = []string{
	"github.com",
	"www.github.com",
	"api.github.com",
	"gist.github.com",
	"codeload.github.com",
	"uploads.github.com",
	"collector.github.com",
	"education.github.com",
	"resources.github.com",
	"archiveprogram.github.com",
	"pages.github.com",
	"raw.githubusercontent.com",
	"raw.github.com",
	"githubusercontent.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
	"media.githubusercontent.com",
	"camo.githubusercontent.com",
	"avatars.githubusercontent.com",
	"avatars0.githubusercontent.com",
	"avatars1.githubusercontent.com",
	"avatars2.githubusercontent.com",
	"avatars3.githubusercontent.com",
	"user-images.githubusercontent.com",
	"private-user-images.githubusercontent.com",
	"cloud.githubusercontent.com",
	"gist.githubusercontent.com",
	"github.githubassets.com",
	"support-assets.githubassets.com",
	"githubassets.com",
	"github.dev",
	"githubapp.com",
	"github.io",
	"www.github.io",
}

// BuiltinDomains 返回内置清单的副本（调用方不得修改内部状态）。
func BuiltinDomains() []string {
	out := make([]string, len(builtinDomains))
	copy(out, builtinDomains)
	return out
}

// Default 返回一份可直接使用的默认配置。
func Default() *Config {
	return &Config{
		Listen: Listen{
			HTTPS:   "127.0.0.1:443",
			HTTP:    "127.0.0.1:80",
			Control: "127.0.0.1:12080",
		},
		DoHJSON: []string{
			"https://223.5.5.5/resolve",
			"https://223.6.6.6/resolve",
		},
		DoHWire: []string{
			"https://doh.pub/dns-query",
		},
		FallbackDNS:    "223.5.5.5:53",
		IPv6:           true,
		LogLevel:       "info",
		Autostart:      true,
		DataDir:        defaultDataDir(),
		CRLHTTPBase:    "http://127.0.0.1:12080",
		UpstreamScheme: "https",
		// 种子表只在 DoH 之外的候选：真实可用地址会变，这里是"多一条路"，
		// 不是唯一来源。改配置文件即可覆盖，不用重新构建。
		SeedIPs: map[string][]string{
			"github.com":                    {"140.82.112.3", "140.82.113.3", "140.82.114.3", "140.82.115.3", "140.82.116.3", "140.82.121.3", "140.82.112.4", "140.82.113.4", "140.82.114.4", "140.82.116.4", "20.205.243.166", "20.207.73.82", "20.200.245.247", "20.201.28.151", "20.233.83.145", "20.27.177.113", "20.175.192.147", "20.26.156.215", "20.29.134.23", "20.199.39.232", "20.217.135.5", "4.237.22.38", "4.208.26.197", "4.228.31.150"},
			"api.github.com":                {"20.205.243.168", "140.82.112.6"},
			"gist.github.com":               {"20.205.243.166", "140.82.112.3"},
			"codeload.github.com":           {"20.205.243.165", "140.82.112.9"},
			"raw.githubusercontent.com":     {"185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"},
			"objects.githubusercontent.com": {"185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"},
			// avatars 与 raw/objects 同在 Fastly anycast（185.199.108–111.133）：
			// 2026-11-03 它没有种子、不在预热名单，整段黑洞时头像请求全部 502。
			"avatars.githubusercontent.com": {"185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133"},
		},
	}
}

// defaultDataDir 返回 %LOCALAPPDATA%\gha；可用 GHA_DATA_DIR 覆盖（测试方便）。
func defaultDataDir() string {
	if v := os.Getenv("GHA_DATA_DIR"); v != "" {
		return v
	}
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		return filepath.Join(la, "gha")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "gha-data"
	}
	return filepath.Join(home, ".gha")
}

// Load 读取配置文件；文件不存在时返回默认配置且不报错。
// 解析失败的字段保持默认值（用 Default() 作为解码基底）。
func Load(path string) (*Config, error) {
	c := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	c.normalize()
	return c, nil
}

// normalize 补齐被零值覆盖的关键字段。
func (c *Config) normalize() {
	d := Default()
	if c.Listen.HTTPS == "" {
		c.Listen.HTTPS = d.Listen.HTTPS
	}
	if c.Listen.HTTP == "" {
		c.Listen.HTTP = d.Listen.HTTP
	}
	if c.Listen.Control == "" {
		c.Listen.Control = d.Listen.Control
	}
	if c.FallbackDNS == "" {
		c.FallbackDNS = d.FallbackDNS
	}
	if c.DataDir == "" {
		c.DataDir = d.DataDir
	}
	if c.CRLHTTPBase == "" {
		c.CRLHTTPBase = d.CRLHTTPBase
	}
	if c.UpstreamScheme == "" {
		c.UpstreamScheme = d.UpstreamScheme
	}
	if len(c.DoHJSON) == 0 {
		c.DoHJSON = d.DoHJSON
	}
	if len(c.DoHWire) == 0 {
		c.DoHWire = d.DoHWire
	}
	if c.LogLevel == "" {
		c.LogLevel = d.LogLevel
	}
	if c.SeedIPs == nil {
		c.SeedIPs = d.SeedIPs
	}
}

// SeedAddrs 把种子表转成解析器要的形式；写错的条目直接忽略（配置手改不致命）。
func (c *Config) SeedAddrs() map[string][]netip.Addr {
	if len(c.SeedIPs) == 0 {
		return nil
	}
	out := make(map[string][]netip.Addr, len(c.SeedIPs))
	for host, ips := range c.SeedIPs {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		for _, raw := range ips {
			a, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err != nil || a.IsLoopback() || a.IsUnspecified() {
				continue
			}
			out[host] = append(out[host], a)
		}
	}
	return out
}

// Save 把配置按 JSON 落盘（0600：里面有控制接口的 token）。
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

// AllDomains 返回“内置清单 + 用户追加”的去重结果，保持内置顺序在前。
func (c *Config) AllDomains() []string {
	seen := make(map[string]struct{}, len(builtinDomains)+len(c.ExtraDomains))
	out := make([]string, 0, len(builtinDomains)+len(c.ExtraDomains))
	for _, d := range builtinDomains {
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	for _, d := range c.ExtraDomains {
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// Paths 汇总数据目录下的固定路径，避免各处硬编码文件名。
type Paths struct{ DataDir string }

func (p Paths) CA() string        { return filepath.Join(p.DataDir, "ca") }
func (p Paths) CertPEM() string   { return filepath.Join(p.CA(), "root.crt") }
func (p Paths) KeyPEM() string    { return filepath.Join(p.CA(), "root.key.pem") }
func (p Paths) Bundle() string    { return filepath.Join(p.CA(), "bundle.pem") }
func (p Paths) Token() string     { return filepath.Join(p.DataDir, "token") }
func (p Paths) Logs() string      { return filepath.Join(p.DataDir, "logs") }
func (p Paths) BackupDir() string { return filepath.Join(p.DataDir, "backup") }
func (p Paths) GitBackup() string { return filepath.Join(p.DataDir, "gitconfig-backup.json") }

// BinDir 存放 install 复制过来的 gha.exe：登录自启项指向这里，而不是用户当初
// 双击的那个路径，这样工程目录被移动或重新编译都不会让自启失效。
func (p Paths) BinDir() string { return filepath.Join(p.DataDir, "bin") }
func (p Paths) BinExe() string { return filepath.Join(p.BinDir(), "gha.exe") }

// P 返回当前配置对应的路径集合。
func (c *Config) P() Paths { return Paths{DataDir: c.DataDir} }
