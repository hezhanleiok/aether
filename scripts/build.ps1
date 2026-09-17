# build.ps1 — build the release exe. The core is NOT downloaded: if
# core-bin\aether.exe exists locally it is copied beside the built exe.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "==> building AetherVPN.exe..."
go build -ldflags "-H windowsgui -s -w" -o bin\AetherVPN.exe .\cmd\aethergui
if ($LASTEXITCODE -ne 0) { throw "build failed" }

$core = Join-Path $root "core-bin\aether.exe"
if (Test-Path $core) {
    Write-Host "==> packaging local core beside the exe..."
    New-Item -ItemType Directory -Force -Path bin\core-bin | Out-Null
    Copy-Item $core bin\core-bin\aether.exe -Force
    & bin\core-bin\aether.exe --version
} else {
    Write-Warning "no local core in core-bin\ — the GUI will search beside the exe / PATH, or set the path in Settings"
}

Write-Host "==> done: bin\AetherVPN.exe"
Get-Item bin\AetherVPN.exe | Select-Object FullName, Length | Format-List
