param([switch]$Elevated)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSCommandPath
$exe = Join-Path (Split-Path -Parent $root) "dist\gha.exe"
$log = Join-Path (Split-Path -Parent $root) "install-out.txt"
if (-not $Elevated) {
  $a = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Elevated"
  Start-Process powershell -Verb RunAs -ArgumentList $a -Wait
  exit 0
}
& $exe install *> $log
