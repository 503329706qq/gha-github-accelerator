<#
.SYNOPSIS
    gha 的 A/B 基准：同一批 URL 各跑 N 次，输出 p50 的 TTFB 与下载速度。

.DESCRIPTION
    这个脚本不负责切换环境——Direct 和 Gha 两种模式要分别在对应状态下跑：

        # 1) 先测直连（gha 没在跑，hosts 是干净的）
        .\scripts\ab-bench.ps1 -Mode Direct -Out docs\bench-20261103.md

        # 2) 再启动 gha（另开一个管理员终端）
        gha run
        # 3) 测经过 gha
        .\scripts\ab-bench.ps1 -Mode Gha -Out docs\bench-20261103.md

    两个模式都直接请求真实地址：Gha 模式靠 hosts + 已安装的根证书生效，
    不需要 --resolve，也不要求 gha 监听在 443（监听在高位端口时请自己加 --resolve）。
    若根证书还没装（例如只跑了 CA 步骤），用 -CaCert 传 root.crt。

.PARAMETER Mode
    Direct = 直连；Gha = 经 gha（hosts 已接管）。

.PARAMETER Runs
    每个 URL 采样次数，默认 5。p50 取排序后的中位数。

.PARAMETER Out
    markdown 输出文件；默认 docs\bench-<yyyyMMdd-HHmm>.md。文件不存在时写表头。

.PARAMETER Urls
    自定义 URL 列表（逗号分隔）。默认覆盖：首页 HTML、raw 小文件、codeload 大包、API。

.EXAMPLE
    .\scripts\ab-bench.ps1 -Mode Gha -Runs 7
#>
[CmdletBinding()]
param(
    [ValidateSet("Direct", "Gha")]
    [string]$Mode = "Gha",

    [ValidateRange(1, 50)]
    [int]$Runs = 5,

    [string]$Out,

    [string[]]$Urls,

    [string]$CaCert
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

if (-not $Urls -or $Urls.Count -eq 0) {
    $Urls = @(
        "https://github.com/",
        "https://raw.githubusercontent.com/octocat/Hello-World/master/README",
        "https://codeload.github.com/pallets/flask/zip/refs/heads/main",
        "https://api.github.com/repos/cli/cli"
    )
}

if (-not $Out) {
    $Out = Join-Path $root ("docs\bench-{0}.md" -f (Get-Date -Format "yyyyMMdd-HHmm"))
}
$outPath = if ([System.IO.Path]::IsPathRooted($Out)) { $Out } else { Join-Path $root $Out }
$outDir = Split-Path -Parent $outPath
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

$curlArgs = @("-sS", "-o", "NUL", "--max-time", "60")
if ($CaCert) {
    $ca = if ([System.IO.Path]::IsPathRooted($CaCert)) { $CaCert } else { Join-Path $root $CaCert }
    $curlArgs += @("--cacert", $ca)
}

function Get-Median {
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) { return 0 }
    $sorted = $Values | Sort-Object
    $n = $sorted.Count
    if ($n % 2 -eq 1) { return [double]$sorted[[int](($n - 1) / 2)] }
    return ([double]$sorted[$n / 2 - 1] + [double]$sorted[$n / 2]) / 2
}

Write-Host ("== ab-bench: mode={0} runs={1} ==" -f $Mode, $Runs)
$rows = @()

foreach ($url in $Urls) {
    $ttfbs = @()
    $speeds = @()
    $codes = @()

    for ($i = 1; $i -le $Runs; $i++) {
        $fmt = "%{http_code} %{time_starttransfer} %{time_total} %{speed_download} %{size_download}"
        # 直连经常直接被重置（curl 退出码非 0 并往 stderr 写东西），
        # 这里临时放宽错误策略，把它记成失败样本，而不是让整个基准中断。
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
        $line = & curl.exe @curlArgs -w $fmt $url 2>$null
        $curlExit = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($curlExit -ne 0 -or -not $line) {
            $codes += "ERR"
            continue
        }
        $parts = ($line -split "\s+")
        if ($parts.Count -lt 5) { $codes += "ERR"; continue }
        $codes += $parts[0]
        $ttfbs += [double]$parts[1]
        $speeds += [double]$parts[3]
    }

    $okCount = @($codes | Where-Object { $_ -match "^\d{3}$" }).Count
    $row = [pscustomobject]@{
        Mode    = $Mode
        Url     = $url
        Ok      = "$okCount/$Runs"
        TTFB_ms = if ($ttfbs.Count) { [math]::Round((Get-Median $ttfbs) * 1000) } else { "-" }
        KBps    = if ($speeds.Count) { [math]::Round((Get-Median $speeds) / 1024) } else { "-" }
    }
    $rows += $row
    Write-Host ("{0}  ok={1}  ttfb={2}ms  {3} KB/s" -f $url, $row.Ok, $row.TTFB_ms, $row.KBps)
}

$stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
if (-not (Test-Path $outPath)) {
    @(
        "# gha 基准记录",
        "",
        "同一台机器、同一时段分别测直连与经 gha；每项 $Runs 次取 p50。TTFB = time_starttransfer。",
        ""
    ) | Set-Content -Path $outPath -Encoding UTF8
}

$md = @()
$md += ""
$md += "## $stamp — $Mode"
$md += ""
$md += "| URL | 成功 | TTFB p50 | 速度 p50 |"
$md += "|---|---|---|---|"
foreach ($r in $rows) {
    $md += ("| {0} | {1} | {2} ms | {3} KB/s |" -f $r.Url, $r.Ok, $r.TTFB_ms, $r.KBps)
}
$md | Add-Content -Path $outPath -Encoding UTF8

Write-Host ""
Write-Host "已追加到 $outPath"
Write-Host "提示：两次运行的时段越接近越好；GitHub 的 CDN 抖动很大，单次对比没有意义。"
