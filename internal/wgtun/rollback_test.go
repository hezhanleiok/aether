//go:build wgtun

package wgtun

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// TestRestoreInterfaceMetricNotFoundIsIdempotent pins the P4.1 fix: when the
// tunnel adapter has already been closed (data-plane-dead path runs t.Down()
// before Revert), its metric row is gone and setIpInterfaceEntry returns
// ERROR_NOT_FOUND. That is the goal state already reached, so restoreInterfaceMetric
// must treat it as success and clear the stash — NOT report a partial failure
// that would leave the crash-recovery state file behind for the next connect.
func TestRestoreInterfaceMetricNotFoundIsIdempotent(t *testing.T) {
	origSet := revertSetMetric
	revertSetMetric = func(r *windows.MibIpInterfaceRow) error { return windows.ERROR_NOT_FOUND }
	defer func() { revertSetMetric = origSet }()

	m := &routeManager{
		luid:     12345,
		ifMetric: [2]ifMetricState{{have: true, metric: 25, auto: 1}, {have: true, metric: 25, auto: 1}},
	}
	if err := m.restoreInterfaceMetric(); err != nil {
		t.Fatalf("restoreInterfaceMetric on already-absent rows: %v", err)
	}
	if m.ifMetric[0].have || m.ifMetric[1].have {
		t.Fatalf("stash not cleared after not-found: %+v", m.ifMetric)
	}
}

// TestRestoreInterfaceMetricRealErrorReported pins that a REAL restore failure
// (access denied, not "already gone") is still reported and the stash kept for a
// later retry — the fix must not swallow genuine Windows API errors.
func TestRestoreInterfaceMetricRealErrorReported(t *testing.T) {
	origSet := revertSetMetric
	revertSetMetric = func(r *windows.MibIpInterfaceRow) error { return windows.ERROR_ACCESS_DENIED }
	defer func() { revertSetMetric = origSet }()

	m := &routeManager{
		luid:     12345,
		ifMetric: [2]ifMetricState{{have: true, metric: 25, auto: 1}},
	}
	if err := m.restoreInterfaceMetric(); err == nil {
		t.Fatal("expected error for ACCESS_DENIED, got nil")
	}
	if !m.ifMetric[0].have {
		t.Fatal("failed metric stash must be kept for retry")
	}
}

// TestRevertNotFoundCleansState is the end-to-end proof of the P4.1 goal: a
// rollback where the routes AND the metric rows are all already gone (exactly
// the data-plane-dead aftermath) must complete WITHOUT a partial-failure error,
// and must therefore run clearState() so the next connect does not need
// recoverFromState to clean up. Uses mocks + a temp dir, never real state.
func TestRevertNotFoundCleansState(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	// A state file on disk represents the residue a clean rollback must remove.
	if err := writeStateFile(wgtunState{Version: stateFileVersion, LUID: 12345}); err != nil {
		t.Fatalf("writeStateFile: %v", err)
	}

	origDel, origSet := revertDeleteRoute, revertSetMetric
	revertDeleteRoute = func(r *windows.MibIpForwardRow2) error { return windows.ERROR_NOT_FOUND }
	revertSetMetric = func(r *windows.MibIpInterfaceRow) error { return windows.ERROR_NOT_FOUND }
	defer func() { revertDeleteRoute, revertSetMetric = origDel, origSet }()

	m := &routeManager{
		luid:     12345,
		added:    []windows.MibIpForwardRow2{{}, {}},
		ifMetric: [2]ifMetricState{{have: true, metric: 25, auto: 1}, {have: true, metric: 25, auto: 1}},
	}
	if err := m.Revert(); err != nil {
		t.Fatalf("Revert with everything already absent must succeed, got: %v", err)
	}
	if _, err := os.Stat(stateFilePath()); !os.IsNotExist(err) {
		t.Fatalf("state file must be cleared by a clean Revert, stat err=%v", err)
	}
}

// TestRevertDNSKeyAbsentIsIdempotent pins that revertDNS treats a vanished
// registry key (the adapter's Tcpip\Interfaces\<guid> key is removed with the
// adapter) as idempotent success, clearing its bookkeeping. The all-zero GUID is
// reserved by Windows and can never be a real adapter, so OpenKey deterministically
// returns ErrNotExist without touching real state.
func TestRevertDNSKeyAbsentIsIdempotent(t *testing.T) {
	m := &routeManager{
		dnsPath:    `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{00000000-0000-0000-0000-000000000000}`,
		oldDNS:     "1.1.1.1",
		haveOldDNS: true,
	}
	if err := m.revertDNS(); err != nil {
		t.Fatalf("revertDNS on absent key must be idempotent success, got: %v", err)
	}
	if m.dnsPath != "" || m.haveOldDNS || m.oldDNS != "" {
		t.Fatalf("DNS bookkeeping not cleared: dnsPath=%q oldDNS=%q haveOldDNS=%v",
			m.dnsPath, m.oldDNS, m.haveOldDNS)
	}
}
