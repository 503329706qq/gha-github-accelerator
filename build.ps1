#Requires -Version 5.1
<#
.SYNOPSIS
    构建 dist\gha.exe，版本号从 git 取。

.DESCRIPTION
    默认用 `git describe --tags --always --dirty` 作为版本；没有 git 或不在仓库里时退回 "dev"。
    想手动指定：$env:VERSION = "1.2.3"; .\build.ps1

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Version 1.2.3
#>
[CmdletBinding()]
param(
    [string]$Version = $env:VERSION
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    if (-not $Version) {
        $Version = (git describe --tags --always --dirty 2>$null)
        if (-not $Version) { $Version = "dev" }
    }

    New-Item -ItemType Directory -Force -Path dist | Out-Null

    # -s -w 去掉符号表和 DWARF：体积大约减半，崩溃栈里仍然是函数名 + 行号。
    $ldflags = "-s -w -X main.version=$Version"
    Write-Host "building dist/gha.exe (version $Version)"
    go build -trimpath -ldflags $ldflags -o dist/gha.exe .
    if ($LASTEXITCODE -ne 0) { throw "go build failed with exit code $LASTEXITCODE" }

    $exe = Get-Item dist/gha.exe
    Write-Host ("built {0} ({1:N1} MB)" -f $exe.FullName, ($exe.Length / 1MB))
    Write-Host "smoke: $(.\dist\gha.exe version)"
}
finally {
    Pop-Location
}
