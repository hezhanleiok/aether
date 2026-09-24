# Gool manual outer/inner probe (diagnostic only).
#
# Starts the core in WARP-in-WARP mode with one hand-picked outer/inner pair,
# waits for the tunnel, then reports the real exit through the tunnel.
#
#   .\scripts\gool-probe.ps1 -Outer 162.159.192.171:890 -Inner 188.114.97.36:903
#
# Nothing here changes the client: it only sets the two AETHER_WIW_* variables
# the core already understands (--wiw-outer / --wiw-inner).
#
# NOTE: ASCII-only on purpose - PowerShell 5.1 reads .ps1 with the system ANSI
# codepage, so non-ASCII text here would be mis-parsed.

param(
    [Parameter(Mandatory = $true)][string]$Outer,
    [Parameter(Mandatory = $true)][string]$Inner,
    [int]$WaitSec = 45
)

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$core = Join-Path $root "core-bin\aether.exe"
if (-not (Test-Path $core)) {
    Write-Output "core not found: $core"
    exit 1
}

Get-Process aether -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

$env:AETHER_PROTOCOL = "gool"
$env:AETHER_WIW_OUTER_PEER = $Outer
$env:AETHER_WIW_INNER_PEER = $Inner
$env:AETHER_SOCKS = "127.0.0.1:1819"
$env:AETHER_HTTP_PROXY = "127.0.0.1:1820"
$env:AETHER_IP = "both"
$env:AETHER_SCAN = "balanced"
$env:AETHER_LOG_LEVEL = "info"

$errLog = Join-Path $env:TEMP "goolprobe.err"
$outLog = Join-Path $env:TEMP "goolprobe.out"
$proc = Start-Process -FilePath $core -PassThru -NoNewWindow `
    -RedirectStandardOutput $outLog -RedirectStandardError $errLog

# Wait for the SOCKS listener: it only appears once the tunnel is really up.
$ready = $false
for ($i = 0; $i -lt $WaitSec; $i++) {
    Start-Sleep -Seconds 1
    if (Get-NetTCPConnection -LocalPort 1819 -State Listen -ErrorAction SilentlyContinue) {
        $ready = $true
        break
    }
}

if (-not $ready) {
    Write-Output "Outer   -> $Outer"
    Write-Output "Inner   -> $Inner"
    Write-Output "Result  -> FAILED to connect (timeout ${WaitSec}s)"
    Get-Process aether -ErrorAction SilentlyContinue | Stop-Process -Force
    exit 1
}

Start-Sleep -Seconds 3

$ip = (curl.exe -s -m 20 -4 -x socks5h://127.0.0.1:1819 https://api.ipify.org).Trim()
$trace = curl.exe -s -m 20 -4 -x socks5h://127.0.0.1:1819 https://www.cloudflare.com/cdn-cgi/trace
$colo = (($trace | Select-String '^colo=') -replace 'colo=', '').Trim()
$loc = (($trace | Select-String '^loc=') -replace 'loc=', '').Trim()
$warp = (($trace | Select-String '^warp=') -replace 'warp=', '').Trim()

# ip-api is only a cross-check; it fails often, so the Cloudflare loc above is
# the primary country signal.
$geo = ""
try {
    $g = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -TimeoutSec 12
    $geo = $g.country
}
catch {
    $geo = "(geo lookup failed)"
}

Write-Output "Outer   -> $Outer"
Write-Output "Inner   -> $Inner"
Write-Output "Exit IP -> $ip"
Write-Output "Country -> $loc   (ip-api: $geo)"
Write-Output "Colo    -> $colo   warp=$warp"

Get-Process aether -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
