# gha — 只加速 GitHub 的本地反向代理

`gha` 是一个单文件 Windows 工具：接管 `github.com` 等 GitHub 域名的 TLS，在本地把连接终结掉，
再用更干净的链路和长连接池转发到真实 GitHub。浏览器、`git`、`npm`、`pip` 全部自动生效，
不装驱动、不走远程中转、不改系统代理。

- **只管 GitHub**：内置 34 个 GitHub 域名，其余流量一概不碰（白名单外 SNI 原样透传，不终结、不解密）。
- **单文件、无依赖**：约 8 MB 的 `gha.exe`，Go 静态编译，不装运行时。
- **退出即还原**：`run` 成功绑定端口之后才写 hosts，退出（含关窗口、注销、关机）时逐字节还原。
- **证书只在本机**：自己生成根 CA 现签叶证书，带 CRL 分发点，`git`（schannel）与浏览器都能过。

```
浏览器 / git / node / python
        │  DNS 被 hosts 指到 127.0.0.1，TLS 由 gha 终结
        ▼
   ┌─────────────┐   ① 本地 CA 现签叶证书（带 CRL 分发点）
   │     gha     │   ② DoH(223.5.5.5 / doh.pub) 绕开污染，拿真实 IP
   │  127.0.0.1  │   ③ 多 IP 并发竞速，按延迟+吞吐打分，留最优
   └─────────────┘   ④ 上游 keep-alive 连接池（h2/http1.1 复用）
        │
        ▼
   真实 GitHub（codeload / Fastly / api …）
```

省下的主要是一个跨国 RTT：浏览器到 `127.0.0.1` 的握手几乎是零延迟，真正的三次握手和
TLS 由 gha 在后台用已经热好的连接完成。

## 安装

要求 Windows 10 1809+ / Windows 11（amd64），**管理员权限**（写 hosts、装机器级根证书、写登录自启项）：

```powershell
.\gha.exe install
```

`install` 只做准备，**不会改 hosts**，所以装完立刻断网这种事不会发生。它做六件事：

| 动作 | 落地位置 |
|---|---|
| 生成根 CA（ECDSA P-256，10 年） | `%LOCALAPPDATA%\gha\ca\root.crt` + `root.key.pem`（0600） |
| 把根证书和空 CRL 装进机器级存储 | `LocalMachine\Root`、`LocalMachine\CA` |
| 给 Node / Python 配 CA | `NODE_EXTRA_CA_CERTS`、`SSL_CERT_FILE`、`REQUESTS_CA_BUNDLE`（= certifi 的 CA 包 + 本 CA 合并） |
| 摘掉会让 git 绕过本地代理的规则 | 备份到 `%LOCALAPPDATA%\gha\gitconfig-backup.json`，然后删除 `url.*.insteadOf=https://github.com/` 这类改写 |
| 复制一份稳定的可执行文件 | `%LOCALAPPDATA%\gha\bin\gha.exe` |
| 注册登录自启 | `HKCU\...\Run\gha` = `"…\gha\bin\gha.exe" run --autostart`（登录后静默提权） |

自启项指向的是 `%LOCALAPPDATA%\gha\bin\gha.exe` 而不是你双击的那个 exe：工程目录被移动、
`dist` 被重新编译覆盖，都不会让自启失效。**升级时**：编译出新 exe 后重新跑一次 `install`
（会覆盖 bin 里的副本并重写自启项；如果旧实例还在跑，先 `gha stop` 让文件解锁）。

## 运行

```powershell
.\gha.exe run            # 接管 443/80，写 hosts，前台跑
.\gha.exe run -v         # 多打点日志（每个请求一行）
.\gha.exe status         # 看状态：域名数、请求数、hosts 是否接管、上游
.\gha.exe stop           # 通知退出（会先还原 hosts）
.\gha.exe ca             # 打印根证书路径与 PEM（给 Firefox 之类手动导入用）
```

登录自启跑的是 `gha run --autostart`：隐藏控制台、日志写
`%LOCALAPPDATA%\gha\logs\gha.log`；第二次启动会因端口被占直接退出，不会污染 hosts。

`run` 的顺序是刻意设计的：**先绑定端口 → 起控制接口和 CRL → 预热 DNS → 最后才写 hosts**。
任何一步失败都会在 hosts 还没被改的时候退出，不会把 GitHub 弄成"连不上 127.0.0.1"。
关闭窗口（`CTRL_CLOSE`）、注销、关机、`Ctrl+C` 都会走还原路径；即便被任务管理器强杀，
下次 `run` 会覆盖写、`uninstall` 会清干净。

自测（不碰 hosts、跑在高位端口）：

```powershell
$env:GHA_DATA_DIR = "$env:TEMP\gha-test"
.\gha.exe run --no-hosts --https 127.0.0.1:18443 --http 127.0.0.1:18080
# 另开终端：
curl --resolve github.com:18443:127.0.0.1 --cacert "$env:GHA_DATA_DIR\ca\root.crt" https://github.com:18443/
```

### 为什么还要种子 IP

DNS 返回的地址不等于现在能连的地址：实测 `github.com` 在某段时间里 A 记录照常返回
`20.205.243.166`，但连接一律超时，而同一时刻 `20.207.73.82` 只要 0.17s 就能握手。
所以解析结果只当"候选之一"：内置种子表（`seed_ips`）+ DoH 结果合并后，由拨号层按
150ms 错峰竞速，谁先握手成功用谁。竞速的终点不是 TCP 握手而是 **TLS 握手完成**——
有一批地址 TCP 秒通、握手也成，但一个字节的响应都不回，只看 TCP 会一直选中它们。
真正的粘性地址由"首次拿到响应头"确立，失败过一次的地址进 60 秒回避窗口。

## 卸载

```powershell
.\gha.exe uninstall
```

逐项还原：hosts 块 → 机器级根证书 → 本 CA 签发的 CRL → 三个环境变量 →
`git config` 里被删掉的规则（从备份恢复）→ 登录自启项。CA 目录默认保留（私钥用 DPAPI
加密，留着下次装还能续用）；要连数据目录、bundle、hosts 备份一起清掉就加 `--purge`：

```powershell
.\gha.exe uninstall --purge
```

注意：如果你正从 `%LOCALAPPDATA%\gha\bin\gha.exe` 运行 `--purge`，Windows 不允许删除
正在使用的 exe，目录里会剩这一份——退出后手动删掉 `%LOCALAPPDATA%\gha` 即可（其余内容已经清干净）。

## 客户端支持

| 客户端 | 是否开箱即用 | 说明 |
|---|---|---|
| Edge / Chrome / IE | ✅ | 读 Windows 证书库 |
| `git`（默认 schannel 后端） | ✅ | 叶证书带 CRL 分发点，吊销检查能过 |
| `curl`（Windows 自带，Schannel） | ✅ | 同上 |
| Node（`npm` / `pnpm` / 脚本） | ✅ 安装时配好 | 走 `NODE_EXTRA_CA_CERTS`；换终端生效 |
| Python（`requests` / `pip`） | ✅ 安装时配好 | 走 `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` 合并包 |
| Firefox | ❌ 手动导入 | 自己有证书库：设置 → 隐私与安全 → 证书 → 查看证书 → 导入 `root.crt` |
| 用 OpenSSL 后端的 curl | ❌ 手动 `--cacert` | 例如 Git for Windows 自带的那个 |

`git` 还能用 SSH 吗？**不能**。v1 只监听 443/80，不碰 22 端口，所以 `git@github.com:...` 会连到
本机没人监听的 22。用 HTTPS remote，或者临时 `uninstall` 后再用 SSH。

## 配置文件

`%LOCALAPPDATA%\gha\config.json`（0600，里面有控制接口 token）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `listen.https` / `listen.http` | `127.0.0.1:443` / `:80` | 接管端口 |
| `listen.control` | `127.0.0.1:12080` | 控制接口 + CRL 分发（绑回环） |
| `doh_json` / `doh_wire` | 阿里 / 腾讯 | 两个独立的 DoH 通道 |
| `fallback_dns` | `223.5.5.5:53` | DoH 全挂时的裸 DNS；**绝不**用系统解析（会读到自己写的 hosts） |
| `domains` | 空 | 追加域名（内置清单永远保留） |
| `seed_ips` | 内置几个常用域名 | "域名 → 已知可用 IP"的种子表，和 DoH 结果一起竞速；DoH 给了地址却连不通时靠它 |
| `log_level` | `info` | `debug` 时额外打印 DoH、竞速、透传细节 |

## 故障排查

| 现象 | 原因 / 处理 |
|---|---|
| `run` 报"监听 127.0.0.1:443 失败" | 443 已被别的程序占着（另一个加速器/代理、IIS、Docker）。退出那个程序，或改 `listen.https` 到别的端口 |
| 浏览器报 `NET::ERR_CERT_AUTHORITY_INVALID` | 根证书没进 `LocalMachine\Root`，重跑 `install` |
| `git` 报 `CRYPT_E_NO_REVOCATION_CHECK` | 吊销检查拿不到 CRL。确认 `gha status` 里 `control` 还在跑（CRL 由它分发） |
| `npm` 报 `SELF_SIGNED_CERT_IN_CHAIN` | 环境变量没生效，重开终端；或检查 `NODE_EXTRA_CA_CERTS` 是否指向 `root.crt` |
| GitHub 直接打不开、也没报证书错 | hosts 残留但 gha 没跑。`gha status` 会直接告诉你还留着几行，`gha stop` 可原地还原（自动提权），或者 `gha run` 重新接管 |
| 只有 `github.com` 502、别的域名正常 | 这个域名的候选 IP 被整段黑洞（TCP SYN 被丢，或 TLS 握得上却一个字节不回）。请求层会换 IP 重试；短时间内连续 6 次尝试都拿不到响应时，gha 判定为**链路级故障**并进入 20 秒快速失败窗口：每条请求只赌一次、2.5 秒封顶，日志会出现一行 `upstream 链路级故障 …`，第一条成功的请求立即解除。这样 502 会秒级返回而不是把整屏请求挂满 12 秒；窗口过后自动重探。整段被拦时换 IP 无用，只能等链路恢复（可持续几分钟到十几分钟），或在 `config.json` 的 `seed_ips` 里补几个地址 |
| 首页第一次慢、后面快 | 正常：启动时的上游探测要跑几秒，之后走连接池与评分 |
| 页面显示 `Whoa there! You have sent an invalid request` 或 `Access to this site has been restricted` | 这是 GitHub 对当前出口 IP 的**风控页**，不是 gha 故障：`api.github.com`、`raw.githubusercontent.com` 通常同时仍然正常。减少请求、等几分钟一般会自然解除（`gha stop` 停掉后台探测恢复得更快）。换 IP 没有用 |
| 页面一片空白，源码只有 `OK` 四个字节 | 这是 GitHub 的**软拦截**（`200` + `text/plain` + 极短正文），同上：等几分钟即可，gha 会把这个地址判为不可用并换下一个 |
| 某些页面 404 / 资源加载失败 | 该域名不在白名单。加到 `domains` 后重启 |
| 装证书时命令卡住不返回 | 受限环境（注册表被过滤的沙箱）里 CryptAPI 会挂起；在普通终端里跑 |

日志在控制台；`-v` 下每个请求一行（`host method path status bytes ms ip`，query 里的
`token`/`password`/`secret` 等参数会被打成 `***`）。

## 已知限制

- 只接管 GitHub 相关域名，白名单外 SNI 直接**原样透传**，不终结、不解密、不记录。
- 不支持 SSH（见上）；不做系统代理、不做 VPN、不接管 HTTP/3（QUIC）。
- 上游强制 TLS 1.2+、强制校验证书，不做任何 `InsecureSkipVerify`。
- 域名清单内置在 exe 里，GitHub 加新域名需要重新构建（`domains` 可临时补）。
- hosts 备份写在数据目录 `backup/`（只留最近 5 份）。若原 hosts 文件末尾没有换行，
  写入块时会补一个 CRLF，`uninstall` 不会把它去掉——Windows 自带的 hosts 一律以 CRLF 结尾，
  实际碰不到。
- 根私钥用 DPAPI 加密（`gha-dpapi-v1` 头），只能被当前用户解开；换账户或拷到别的机器都读不出明文。
- CRL 有效期 7 天，实例运行期间每 24 小时重签并刷新存储里的那一份；控制端口短时不可达不影响校验。
- 本机到 GitHub 的 IPv4 有时会**成段**被拦（同一 /24 里只有相邻几个号码通）。gha 会在探测成功
  的地址附近试同网段邻居并纳入候选，但整段被拦时只能等链路恢复。这类故障期间 gha 不会一直重试：
  连续多次尝试无响应会进入 20 秒快速失败窗口（单次尝试、2.5 秒封顶），把 502 的等待时间从 12 秒
  压到 2.5 秒左右，让浏览器自己重试；窗口内要**连续 3 次**成功才恢复正常重试（零星成功不算，
  否则窗口会在"慢但偶尔能通"的波形里反复开关）。
- GitHub 还会对"不像浏览器"的高频请求做风控，整站回 400 `Whoa there!` 或 403
  `Access to this site has been restricted`。为此后台探测刻意压得很低：启动时摸底一次（每域名最多 24 个
  候选），之后每 15 分钟只确认评分最高的 6 个，真出问题才按需补一轮全量；一整轮探不到任何可用地址
  会静默 30 分钟。同时 400/403/429 一律不算"这个地址可用"，也不会被立成粘性地址。
- 还有一种更隐蔽的风控形态：**200 但正文只有几个字节**。GitHub 边缘层对可疑客户端会回
  `200 OK` + `Content-Type: text/plain`，正文就是 `OK`（实测 4 字节，响应头带
  `X-GitHub-Edge-Region`）。浏览器拿到的是一片空白、也不报错。gha 对浏览器导航类的请求
  （`Accept` 含 `text/html`）做了嗅探：`200` + `text/plain` + 正文短于 64 字节且是空串或 `ok`
  时判为软拦截，**惩罚该地址并换一个重试**，不会把空壳当页面交给浏览器。
  即便如此，遇到这类页面时唯一有效的做法仍是减少请求、等限制自然解除（通常几分钟）。

## 从源码构建

需要 Go 1.26+ 与 PowerShell：

```powershell
git clone https://github.com/503329706qq/gha-github-accelerator.git
cd gha-github-accelerator
.\build.ps1                    # 出 dist\gha.exe，版本取 git describe
```

开发时：

```powershell
go test ./...                  # 单元 + 集成测试（沙箱里"写根存储"的用例会自动 skip）
$env:GHA_STORE_WRITE = "1"     # 在普通终端里连"写根存储"的用例一起跑
```

`GHA_NO_ELEVATE=1` 让 `install`/`run` 跳过自我提权（自测用，真正写 hosts 时仍然会因为没权限而失败）。
`GHA_DATA_DIR` 覆盖数据目录，方便并行跑多个实例。

基准对比（直连 vs 经 gha，各 5 次取 p50，历史数据见 [docs/bench.md](docs/bench.md)）：

```powershell
.\scripts\ab-bench.ps1 -Mode Direct -Out docs\bench.md   # gha 没在跑时
.\scripts\ab-bench.ps1 -Mode Gha    -Out docs\bench.md   # gha 跑起来后
```

目录：

```
main.go                 入口
internal/app/           CLI、install/uninstall、run 生命周期、status/stop
internal/ca/            根 CA、叶证书、CRL
internal/proxy/         443 分流、TLS 终结、反向代理、80 跳转
internal/resolver/      DoH（JSON + wire）+ 裸 DNS 兜底
internal/dialer/        多 IP 竞速、打分、粘性地址与回避窗口
internal/hosts/         hosts 块渲染/替换/还原（保留 BOM 与别人的块）
internal/store/         Windows 证书库（crypt32）
internal/control/       127.0.0.1:12080 控制接口
internal/envvars/       HKCU 环境变量
internal/gitcfg/        git config 改写
internal/autostart/     登录自启（HKCU Run 键）
docs/bench.md           基准记录
```

## 原理上的取舍

- **不搞远程中转**：没有"加速服务器"可连，流量始终从你自己的机器直出到 GitHub。
- **不做全局代理**：只改 GitHub 域名的 hosts，其余域名连 DNS 都不经过 gha。
- **不静默失败**：白名单外 SNI 透传失败时返回 TCP 关闭并记日志；启动任何一步失败都在写
  hosts 之前退出。

## 协议

[MIT](LICENSE)。仅供个人在自己的机器上访问 GitHub 使用：本工具不提供任何代理服务器，
不绕过任何网络管控，请遵守所在地区的法律法规与 GitHub 的服务条款。
