# setup-wireguard.ps1 - fetch the dependencies for the native WireGuard
# (kernel-speed) backend of Xiaohe, i.e. phase 2 of the speed fix.
#
#   wireguard-go  -> golang.zx2c4.com/wireguard   (userspace WG, ~Gbps class)
#   wintun.dll    -> the TUN adapter driver
#
# Run once, from an administrator PowerShell with the proxy already up:
#
#   powershell -ExecutionPolicy Bypass -File scripts\setup-wireguard.ps1
#
# It edits go.mod / go.sum / vendor (so the WG backend can compile) and drops
# wintun.dll next to the built exe and the core. After this, build normally
# with scripts\build.ps1.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$proxy = "http://127.0.0.1:10808"
$env:HTTPS_PROXY = $proxy
$env:HTTP_PROXY = $proxy
$env:GOPROXY = "https://proxy.golang.org,direct"

Write-Host "[1/3] go get wireguard-go ..." -ForegroundColor Cyan
go get golang.zx2c4.com/wireguard@latest
if ($LASTEXITCODE -ne 0) { throw "go get failed - is the proxy up?" }
go mod tidy
go mod vendor
if ($LASTEXITCODE -ne 0) { throw "go mod vendor failed" }

Write-Host "[2/3] wintun.dll ..." -ForegroundColor Cyan
# Pin a known release; bump WINTUN_VER when a newer one is wanted.
$WINTUN_VER = "0.14.1"
$url = "https://www.wintun.net/builds/wintun-$WINTUN_VER.zip"
$zip = Join-Path $env:TEMP "wintun-$WINTUN_VER.zip"
Invoke-WebRequest -Uri $url -OutFile $zip -Proxy $proxy -UseBasicParsing

$tmp = Join-Path $env:TEMP "wintun-$WINTUN_VER"
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -Path $zip -DestinationPath $tmp -Force
$dll = Get-ChildItem $tmp -Recurse -Filter "wintun.dll" | Select-Object -First 1
if (-not $dll) { throw "wintun.dll not found in the archive" }

Write-Host "[3/3] placing wintun.dll ..." -ForegroundColor Cyan
Copy-Item $dll.FullName (Join-Path $root "bin\wintun.dll") -Force
Copy-Item $dll.FullName (Join-Path $root "core-bin\wintun.dll") -Force

Write-Host ""
Write-Host "Done. Rebuild with scripts\build.ps1, then enable the native WG"
Write-Host "backend in Settings (needs an elevated first run to create the TUN"
Write-Host "adapter, same as the WireGuard app)." -ForegroundColor Green
