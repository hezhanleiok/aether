# Builds a release: portable zip + Windows installer, and (with -Token)
# publishes both as a GitHub release.
#
#   .\scripts\release.ps1
#   .\scripts\release.ps1 -Version 1.2.0
#   .\scripts\release.ps1 -Token <PAT>          # build + publish
#
# The GUI and its core are always packaged together so the two can never
# drift apart on a user's machine.
#
# NOTE: kept ASCII-only on purpose - PowerShell 5.1 reads .ps1 files with the
# system ANSI codepage, so non-ASCII text here would be mis-parsed. The
# Chinese release notes live in release-notes.md and are read as UTF-8.

param(
    [string]$Version = "1.1.0",
    [string]$Token = $env:GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$build     = Join-Path $root "build"
$stage     = Join-Path $build "AetherVPN-$Version"
$payload   = Join-Path $root "cmd\aethersetup\payload\bundle.zip"
$payloadBak = Join-Path $env:TEMP "bundle-placeholder.zip"

if (Test-Path $payload) { Copy-Item $payload $payloadBak -Force }

try {
    Remove-Item -Recurse -Force $build -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $build | Out-Null

    Write-Host "[1/5] Building GUI client..." -ForegroundColor Cyan
    go build -ldflags="-H=windowsgui" -o (Join-Path $build "AetherVPN.exe") ./cmd/aethergui
    if ($LASTEXITCODE -ne 0) { throw "GUI build failed" }

    Write-Host "[2/5] Staging portable package..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path (Join-Path $stage "core-bin") | Out-Null
    Copy-Item (Join-Path $build "AetherVPN.exe") $stage -Force
    Copy-Item (Join-Path $root "core-bin\aether.exe") (Join-Path $stage "core-bin\aether.exe") -Force
    $readme = "AetherVPN $Version`r`n`r`n" +
              "  - Run AetherVPN.exe directly (portable, no install needed)`r`n" +
              "  - core-bin\aether.exe is the bundled Aether core`r`n" +
              "  - Updates replace GUI and core together, so they always match`r`n"
    [System.IO.File]::WriteAllText((Join-Path $stage "README.txt"), $readme)

    Write-Host "[3/5] Creating zip..." -ForegroundColor Cyan
    $zip = Join-Path $build "AetherVPN-$Version-win-x64.zip"
    Compress-Archive -Path $stage -DestinationPath $zip -Force

    Write-Host "[4/5] Building installer..." -ForegroundColor Cyan
    Copy-Item $zip $payload -Force
    go build -ldflags="-H=windowsgui" -o (Join-Path $build "AetherVPN-Setup-$Version.exe") ./cmd/aethersetup
    if ($LASTEXITCODE -ne 0) { throw "Installer build failed" }
    Copy-Item $payloadBak $payload -Force   # keep big binaries out of the repo

    Write-Host "[5/5] Rendering release notes..." -ForegroundColor Cyan
    $tplPath = Join-Path $root "scripts\release-notes.md"
    $tpl = [System.IO.File]::ReadAllText($tplPath, [System.Text.Encoding]::UTF8)
    $notes = $tpl.Replace("{version}", $Version)
    [System.IO.File]::WriteAllText((Join-Path $build "RELEASE_NOTES.md"), $notes, (New-Object System.Text.UTF8Encoding $false))

    if (-not $Token) {
        Write-Host ""
        Write-Host "Build finished. Artifacts in build\ :" -ForegroundColor Green
        Get-ChildItem $build -File | ForEach-Object { Write-Host ("  " + $_.Name + "  " + [math]::Round($_.Length / 1MB, 1) + " MB") }
        Write-Host "To publish: .\scripts\release.ps1 -Version $Version -Token <PAT>" -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Creating GitHub release v$Version ..." -ForegroundColor Cyan
    $proxy = "http://127.0.0.1:10808"
    $hdr = @{ Authorization = "Bearer $Token"; Accept = "application/vnd.github+json" }

    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/hezhanleiok/aether/releases" `
        -Method Post -Headers $hdr -Proxy $proxy -ContentType "application/json" `
        -Body (@{ tag_name = "v$Version"; name = "AetherVPN v$Version"; body = $notes; draft = $false; prerelease = $false } | ConvertTo-Json)

    foreach ($f in @("AetherVPN-$Version-win-x64.zip", "AetherVPN-Setup-$Version.exe")) {
        $p = Join-Path $build $f
        $bytes = [System.IO.File]::ReadAllBytes($p)
        $up = "https://uploads.github.com/repos/hezhanleiok/aether/releases/$($rel.id)/assets?name=$f"
        Invoke-RestMethod -Uri $up -Method Post -Headers $hdr -Proxy $proxy `
            -ContentType "application/octet-stream" -Body $bytes | Out-Null
        Write-Host ("  uploaded " + $f) -ForegroundColor Green
    }
    Write-Host ""
    Write-Host ("Release published: " + $rel.html_url) -ForegroundColor Green
}
catch {
    if (Test-Path $payloadBak) { Copy-Item $payloadBak $payload -Force }
    throw
}
