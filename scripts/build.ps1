# build.ps1 - build the client exe and stage the local core next to it.
# The core is NOT downloaded: if core-bin\aether.exe exists locally it is
# copied beside the built exe, together with the pt\ helpers (psiphon /
# lyrebird) that the core needs for the chained exits.
#
# NOTE: Windows Defender regularly quarantines freshly built, unsigned Go
# binaries here ("file contains a virus or potentially unwanted software"),
# which shows up either as a failed go build or as the output file being
# renamed to Xiaohe.exe~. Retrying usually succeeds; if it never does, add
# an exclusion for this folder (admin PowerShell):
#
#   Add-MpPreference -ExclusionPath "E:\aether\bin", "E:\aether\build"
#
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$out = Join-Path $root "bin\Xiaohe.exe"

# Defender renames a quarantined file instead of deleting it; those leftovers
# would silently keep an old binary on disk.
Get-ChildItem (Join-Path $root "bin") -Filter "*.exe~" -ErrorAction SilentlyContinue |
    ForEach-Object { Write-Host "==> removing $($_.Name) (left by the antivirus)"; Remove-Item $_.FullName -Force }

Write-Host "==> building Xiaohe.exe..."
$built = $false
for ($i = 1; $i -le 3 -and -not $built; $i++) {
    go build -tags wgtun -ldflags "-H windowsgui -s -w" -o $out .\cmd\aethergui
    if ($LASTEXITCODE -eq 0 -and (Test-Path $out)) {
        $built = $true
        break
    }
    Write-Host "==> attempt ${i} was blocked (usually the antivirus); retrying..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}
if (-not $built) {
    Write-Host ""
    Write-Host "The build stayed blocked. Windows Defender is almost always the" -ForegroundColor Red
    Write-Host "reason - it treats unsigned Go binaries (and the bundled psiphon"
    Write-Host "helper) as suspicious. Either allow the detection in Windows"
    Write-Host "Security, or add an exclusion in an administrator PowerShell:"
    Write-Host ""
    Write-Host "  Add-MpPreference -ExclusionPath `"$root\bin`", `"`$env:TEMP\go-build*`"" -ForegroundColor Cyan
    throw "build failed"
}

$core = Join-Path $root "core-bin\aether.exe"
if (Test-Path $core) {
    Write-Host "==> staging the local core beside the exe..."
    New-Item -ItemType Directory -Force -Path bin\core-bin | Out-Null
    Copy-Item $core bin\core-bin\aether.exe -Force
    & bin\core-bin\aether.exe --version
} else {
    Write-Warning "no local core in core-bin\ - the GUI will search beside the exe / PATH, or set the path in Settings"
}

# The core looks for psiphon-tunnel-core.exe / lyrebird.exe in its own
# directory and in pt\ next to it. Without them the Psiphon and Tor exits
# cannot start.
$pt = Join-Path $root "core-bin\pt"
if (Test-Path $pt) {
    Write-Host "==> staging pt\ helpers (psiphon, lyrebird)..."
    New-Item -ItemType Directory -Force -Path bin\core-bin\pt | Out-Null
    Copy-Item (Join-Path $pt "*") bin\core-bin\pt -Recurse -Force
} else {
    Write-Warning "no core-bin\pt\ - the Psiphon and Tor exits cannot start"
}

Write-Host "==> done: bin\Xiaohe.exe"
Get-Item $out | Select-Object FullName, Length | Format-List
