# Registry and guard for local patches inside vendor/.
#
# WHY: every patch below lives in vendor/, which `go mod vendor` overwrites with
# the pristine upstream sources. A wiped patch does not fail loudly - the build
# still succeeds and we silently lose the AWG junk layer. So
# each patch is (a) registered here with a marker string that only the patched
# file contains, and (b) stored as a full copy under patches/full/.
#
# USAGE (run from the repo root):
#   .\scripts\apply-vendor-patches.ps1            # check: are all patches in place?
#   .\scripts\apply-vendor-patches.ps1 -Check     # same as above (explicit)
#   .\scripts\apply-vendor-patches.ps1 -Apply     # restore patched files into vendor/ (after `go mod vendor`)
#   .\scripts\apply-vendor-patches.ps1 -Snapshot  # save current vendor/ files into patches/full/
#
# Run -Check before every build. Add new patches to $Patches below when you edit
# anything under vendor/, then run -Snapshot immediately.
param(
    [switch]$Check,
    [switch]$Apply,
    [switch]$Snapshot
)

$ErrorActionPreference = 'Stop'
$Vendor = 'vendor/golang.zx2c4.com/wireguard'
$Store = 'patches/full'

# marker = a string that exists ONLY in the patched version of the file.
$Patches = @(
    @{
        Name   = 'awg-junk'
        Why    = 'AmneziaWG anti-DPI decoys: junk (jc/jmin/jmax) + fake first packet (i1), generator, pre-handshake send'
        Files  = @(
            @{ Path = "$Vendor/device/awgjunk.go"; Marker = 'type awgJunk struct' },
            @{ Path = "$Vendor/device/device.go"; Marker = 'junk awgJunk' },
            @{ Path = "$Vendor/device/send.go"; Marker = 'device.junk.enabled()' },
            @{ Path = "$Vendor/device/uapi.go"; Marker = 'applyJunkConfig' }
        )
    }
)

# History (do NOT re-apply): the WARP "reserved bytes" patch (device.reserved +
# SetReserved + Type|reserved<<8) was added on 7a703df and REMOVED again - WARP
# rejects non-zero reserved bytes, so the vendored tree is back to upstream for
# those two files. Kept here so nobody re-adds it without re-verifying on real
# hardware.
#
# 'bind-windows-batch' belongs to the same memory: it drained up to
# winRingBatchSize RIO completions per Receive call. Measured 2026-10-05 on
# 162.159.192.42:4233 against a fixed speedtest server: batch 55 Mbps down vs
# nobatch 103 Mbps (official WireGuard kernel driver 301). Batch made downloads
# WORSE - the earlier "34 -> 100" was endpoint/time-of-day noise. It is NOT in
# $Patches above on purpose: do not re-apply it to chase the gap to 301, that
# ~100 Mbps ceiling is a userspace-vs-kernel gap, not a batching gap.

function Check-All {
    $bad = 0
    foreach ($p in $Patches) {
        Write-Output ("patch: {0} - {1}" -f $p.Name, $p.Why)
        foreach ($f in $p.Files) {
            $present = $false
            if (Test-Path $f.Path) {
                $present = Select-String -Path $f.Path -Pattern $f.Marker -SimpleMatch -Quiet
            }
            $state = if ($present) { 'OK' } else { 'MISSING' }
            if (-not $present) { $bad++ }
            Write-Output ("   [{0,-7}] {1}  (marker: {2})" -f $state, $f.Path, $f.Marker)
        }
    }
    if ($bad -gt 0) {
        Write-Output ''
        Write-Output "ERROR: $bad patched file(s) missing or unpatched. Run: .\scripts\apply-vendor-patches.ps1 -Apply"
        exit 1
    }
    Write-Output ''
    Write-Output 'OK: all vendor patches in place.'
}

function Apply-All {
    foreach ($p in $Patches) {
        foreach ($f in $p.Files) {
            $src = Join-Path $Store $f.Path
            if (-not (Test-Path $src)) {
                Write-Output ("SKIP (no stored copy): {0}" -f $src)
                continue
            }
            $dst = $f.Path
            $dir = Split-Path -Parent $dst
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Copy-Item -Path $src -Destination $dst -Force
            Write-Output ("applied: {0}" -f $dst)
        }
    }
    Check-All
}

function Snapshot-All {
    foreach ($p in $Patches) {
        foreach ($f in $p.Files) {
            if (-not (Test-Path $f.Path)) {
                Write-Output ("SKIP (missing in vendor): {0}" -f $f.Path)
                continue
            }
            $dst = Join-Path $Store $f.Path
            $dir = Split-Path -Parent $dst
            if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Copy-Item -Path $f.Path -Destination $dst -Force
            Write-Output ("snapshot: {0}" -f $dst)
        }
    }
}

if ($Apply) { Apply-All; exit 0 }
if ($Snapshot) { Snapshot-All; exit 0 }
Check-All
