# setup-core.ps1 — install a local Aether Core binary into core-bin/.
# The core is NOT downloaded from anywhere: the user provides the path to an
# aether.exe (or libaether.dll) they already have. The GUI also finds cores
# beside its own exe or in core-bin\ automatically.
#
# Usage:
#   powershell -File scripts\setup-core.ps1 -CorePath C:\path\to\aether.exe
#   powershell -File scripts\setup-core.ps1 -CorePath C:\path\to\libaether.dll
param(
    [Parameter(Mandatory = $true)]
    [string]$CorePath
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $CorePath)) {
    throw "core file not found: $CorePath"
}

$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root "core-bin"
New-Item -ItemType Directory -Force -Path $dest | Out-Null

$name = Split-Path -Leaf $CorePath
Copy-Item $CorePath (Join-Path $dest $name) -Force
Write-Host "installed: $(Join-Path $dest $name)"

if ($name -match '\.exe$') {
    & (Join-Path $dest $name) --version
}
