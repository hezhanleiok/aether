# Builds the Windows release: portable ZIP + installer, plus checksums, and
# (with -Token) publishes it as a GitHub release.
#
#   .\scripts\release.ps1                     # build only
#   .\scripts\release.ps1 -Version 1.2.0
#   .\scripts\release.ps1 -Token <PAT>        # build + publish
#
# Pipeline: Build -> Stage -> Validate -> Package -> Checksum -> Release
#
# The GUI and its core are packaged together, so the two can never drift apart.
#
# NOTE: ASCII-only on purpose - PowerShell 5.1 reads .ps1 files with the system
# ANSI codepage, so non-ASCII text here would be mis-parsed. File contents that
# need Chinese are written with an explicit UTF-8 writer below.

param(
    [string]$Version = "1.1.3",
    [string]$Token = $env:GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$build = Join-Path $root "build"
$stage = Join-Path $build "AetherVPN-$Version-win-x64"
$zip = Join-Path $build "AetherVPN-$Version-win-x64.zip"
$setup = Join-Path $build "AetherVPN-Setup-$Version.exe"
$payload = Join-Path $root "cmd\aethersetup\payload\bundle.zip"
$payloadBak = Join-Path $env:TEMP "bundle-placeholder.zip"

function Write-Utf8($Path, $Text) {
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding $false))
}

if (Test-Path $payload) { Copy-Item $payload $payloadBak -Force }

try {
    Remove-Item -Recurse -Force $build -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $build | Out-Null

    # ---------------------------------------------------------------- Build
    Write-Host "[1/6] Build" -ForegroundColor Cyan
    go build -ldflags="-H=windowsgui" -o (Join-Path $build "AetherVPN.exe") ./cmd/aethergui
    if ($LASTEXITCODE -ne 0) { throw "GUI build failed" }
    Write-Host "      GUI      -> AetherVPN.exe"

    # ---------------------------------------------------------------- Stage
    Write-Host "[2/6] Stage" -ForegroundColor Cyan
    New-Item -ItemType Directory -Force -Path (Join-Path $stage "core-bin") | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $stage "docs") | Out-Null

    Copy-Item (Join-Path $build "AetherVPN.exe") (Join-Path $stage "AetherVPN.exe") -Force
    Copy-Item (Join-Path $root "core-bin\aether.exe") (Join-Path $stage "core-bin\aether.exe") -Force

    # Both binaries are pure Go (CGO_ENABLED=0, no `import "C"` anywhere), so
    # they are statically linked and need no third-party DLLs or runtime files
    # beside them. Nothing is added here just to make the package look bigger.

    Write-Utf8 (Join-Path $stage "README.txt") @"
AetherVPN $Version

  双击 AetherVPN.exe 即可启动，无需安装。

目录说明
  AetherVPN.exe        图形界面（Go 编写，静态链接，无需额外运行库）
  core-bin\aether.exe  Aether 核心，独立进程，由界面调用
  docs\                项目文档
  LICENSE.txt          许可与第三方声明
  CHANGELOG.txt        版本变更记录

说明
  - 界面与核心分离：核心是可独立替换的进程，但更新时二者随同一个更新包
    一起替换，以保证版本配套。
  - 首次启动会在 %LOCALAPPDATA%\AetherGUI 下保存设置，卸载只需删除该目录。
  - 若本机没有 WebView2 运行时，界面会自动改用 Edge/Chrome 的无边框窗口，
    功能完全一致。
"@

    Write-Utf8 (Join-Path $stage "LICENSE.txt") @"
AetherVPN
Copyright (c) xiaohe

本客户端（GUI）由 xiaohe 开发并发布，采用试用授权：自首次启动起可免费
试用 7 天，到期后软件会提示续期，授权状态与到期时间由项目仓库中的
version.json 远程控制。

第三方组件
  - Aether（CluvexStudio）：本软件内置并随包分发其官方核心二进制文件
    aether.exe。该核心的版权与许可证归原作者 CluvexStudio 所有，本项目
    仅作调用与随包分发，未修改其核心代码。
  - 其余 Go 语言依赖见仓库 go.mod 与 vendor\ 目录。

本软件按「原样」提供，作者不对使用后果作任何担保。请遵守所在地法律法规
以及所访问网络服务的使用条款。
"@

    Write-Utf8 (Join-Path $stage "CHANGELOG.txt") @"
$Version
  - 修复 MASQUE 连不上（连接超时预算不足，跑不满网关搜索即被判失败）
  - WireGuard / Gool / MasqueH2 / MasqueH3 回归实测跑通真实流量
  - 授权到期时间延长至 2026-10-01

1.1.4
  - 修复 Gool（WARP-in-WARP）连接成功后反复断开重连（不再因出口地区主动断开）
  - 内置 Aether 核心升级至官方最新稳定版 v2.1.0

1.1.3
  - 重新整理 Windows 便携版目录结构（界面/核心分离，附带文档与许可）
  - 发布流程改为 Build/Stage/Validate/Package/Checksum 并附 SHA256 校验和
  - Gool（WARP-in-WARP）增加出口检测与自动重选
  - 修复手动指定节点后 MASQUE H2/H3 无法连接的问题
  - 新增应用图标（任务栏/窗口/安装包）

1.1.1
  - 便携包改为平铺结构，解压即可运行
  - 修复手动选节点导致 MASQUE 系列握手失败

1.1.0
  - 首个 Release 版本：便携版 + 安装版
  - 改用 GitHub Release 发布，不再把 exe 放在仓库根目录
"@

    if (Test-Path (Join-Path $root "ARCHITECTURE.md")) {
        Copy-Item (Join-Path $root "ARCHITECTURE.md") (Join-Path $stage "docs\ARCHITECTURE.md") -Force
    }
    if (Test-Path (Join-Path $root "README.md")) {
        Copy-Item (Join-Path $root "README.md") (Join-Path $stage "docs\README.md") -Force
    }
    Write-Host "      staged -> $stage"

    # ------------------------------------------------------------- Validate
    Write-Host "[3/6] Validate" -ForegroundColor Cyan
    $required = @(
        (Join-Path $stage "AetherVPN.exe"),
        (Join-Path $stage "core-bin\aether.exe"),
        (Join-Path $stage "README.txt"),
        (Join-Path $stage "LICENSE.txt"),
        (Join-Path $stage "CHANGELOG.txt")
    )
    foreach ($f in $required) {
        if (-not (Test-Path $f)) { throw "missing staged file: $f" }
        if ((Get-Item $f).Length -eq 0) { throw "empty staged file: $f" }
    }
    # The core must actually run: this proves the packaged binary is intact and
    # not dependent on anything from the development machine.
    $coreVersion = & (Join-Path $stage "core-bin\aether.exe") --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "packaged core did not run: $coreVersion" }
    Write-Host ("      core ok -> " + ($coreVersion | Out-String).Trim())

    # -------------------------------------------------------------- Package
    Write-Host "[4/6] Package" -ForegroundColor Cyan
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -Force
    Copy-Item $zip $payload -Force
    go build -ldflags="-H=windowsgui" -o $setup ./cmd/aethersetup
    if ($LASTEXITCODE -ne 0) { throw "installer build failed" }
    Copy-Item $payloadBak $payload -Force   # keep big binaries out of the repo
    Write-Host "      zip     -> $(Split-Path $zip -Leaf)"
    Write-Host "      setup   -> $(Split-Path $setup -Leaf)"

    # ------------------------------------------------------------- Checksum
    Write-Host "[5/6] Checksum" -ForegroundColor Cyan
    $sums = @()
    foreach ($f in @($zip, $setup)) {
        $h = (Get-FileHash -Path $f -Algorithm SHA256).Hash.ToLower()
        $sums += ("{0}  {1}" -f $h, (Split-Path $f -Leaf))
    }
    $sumFile = Join-Path $build "SHA256SUMS.txt"
    Write-Utf8 $sumFile (($sums -join "`n") + "`n")
    Write-Host "      -> SHA256SUMS.txt"
    $sums | ForEach-Object { Write-Host "         $_" }

    # -------------------------------------------------------------- Release
    if (-not $Token) {
        Write-Host ""
        Write-Host "[6/6] Release skipped (no token). Artifacts in build\" -ForegroundColor Yellow
        return
    }

    Write-Host "[6/6] Release" -ForegroundColor Cyan
    # The proxy is optional and comes from the environment: a dev box behind a
    # local proxy sets HTTPS_PROXY, while a CI runner has direct egress and
    # leaves it unset. Hard-coding one here would break the runner.
    $proxy = $env:HTTPS_PROXY
    $hdr = @{ Authorization = "Bearer $Token"; Accept = "application/vnd.github+json" }

    $notesPath = Join-Path $root "scripts\release-notes.md"
    $notes = [System.IO.File]::ReadAllText($notesPath, [System.Text.Encoding]::UTF8)
    $notes = $notes.Replace("{version}", $Version)
    $notes += "`n`n### SHA256`n`n``````n" + ($sums -join "`n") + "`n``````n"

    $body = @{ tag_name = "v$Version"; name = "AetherVPN v$Version"; body = $notes; draft = $false; prerelease = $false } | ConvertTo-Json

    # Splatting so the proxy key is only present when one is configured -
    # passing -Proxy $null is an error.
    $post = @{
        Uri         = "https://api.github.com/repos/hezhanleiok/aether/releases"
        Method      = 'Post'
        Headers     = $hdr
        ContentType = "application/json; charset=utf-8"
        Body        = [System.Text.Encoding]::UTF8.GetBytes($body)
    }
    if ($proxy) { $post.Proxy = $proxy }
    $rel = Invoke-RestMethod @post

    foreach ($f in @((Split-Path $zip -Leaf), (Split-Path $setup -Leaf), "SHA256SUMS.txt")) {
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $build $f))
        $put = @{
            Uri         = "https://uploads.github.com/repos/hezhanleiok/aether/releases/$($rel.id)/assets?name=$f"
            Method      = 'Post'
            Headers     = $hdr
            ContentType = "application/octet-stream"
            Body        = $bytes
        }
        if ($proxy) { $put.Proxy = $proxy }
        Invoke-RestMethod @put | Out-Null
        Write-Host "      uploaded $f"
    }
    Write-Host ""
    Write-Host ("Release published: " + $rel.html_url) -ForegroundColor Green
}
catch {
    if (Test-Path $payloadBak) { Copy-Item $payloadBak $payload -Force }
    throw
}
