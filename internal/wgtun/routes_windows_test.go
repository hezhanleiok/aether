//go:build wgtun

package wgtun

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestInterfaceMetricRoundtrip is an OFFLINE self-check for the Get/Set IP
// Interface parameter chain - the exact thing that failed in the first machine
// test. It does NOT touch routes or DNS and never changes the metric: for each
// address family it reads a real interface's metric, writes the SAME value back
// through a clean (freshly initialized) row, then re-reads to confirm nothing
// moved. Requires elevation only because SetIpInterfaceEntry is privileged.
func TestInterfaceMetricRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a real SetIpInterfaceEntry (privileged); skipped in -short/offline mode")
	}
	luid, ok := firstInterfaceLuid(t)
	if !ok {
		t.Skip("no interface LUID available for the offline self-check")
	}

	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		// read current
		var cur windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&cur)
		cur.Family = family
		cur.InterfaceLuid = luid
		if err := getIpInterfaceEntry(&cur); err != nil {
			t.Logf("family %d: no interface entry (skip): %v", family, err)
			continue
		}

		// write the same value through a clean row
		var set windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&set)
		set.Family = family
		set.InterfaceLuid = luid
		set.UseAutomaticMetric = cur.UseAutomaticMetric
		set.Metric = cur.Metric
		if err := setIpInterfaceEntry(&set); err != nil {
			t.Fatalf("family %d: set(same value) failed: %v", family, err)
		}

		// re-read and verify unchanged
		var after windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&after)
		after.Family = family
		after.InterfaceLuid = luid
		if err := getIpInterfaceEntry(&after); err != nil {
			t.Fatalf("family %d: re-get failed: %v", family, err)
		}
		if after.Metric != cur.Metric || after.UseAutomaticMetric != cur.UseAutomaticMetric {
			t.Fatalf("family %d: metric changed: before(metric=%d,auto=%d) after(metric=%d,auto=%d)",
				family, cur.Metric, cur.UseAutomaticMetric, after.Metric, after.UseAutomaticMetric)
		}
		t.Logf("family %d: roundtrip OK (metric=%d, auto=%d)", family, after.Metric, after.UseAutomaticMetric)
	}
}

// firstInterfaceLuid returns the LUID of the first adapter GetAdaptersAddresses
// reports, so the roundtrip test can run against a real interface without
// hard-coding an LUID.
func firstInterfaceLuid(t *testing.T) (uint64, bool) {
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, nil, &size)
	if err != nil && err != windows.ERROR_BUFFER_OVERFLOW {
		t.Logf("GetAdaptersAddresses size probe: %v", err)
		return 0, false
	}
	buf := make([]byte, size)
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, aa, &size); err != nil {
		t.Logf("GetAdaptersAddresses: %v", err)
		return 0, false
	}
	for ; aa != nil; aa = aa.Next {
		if aa.Luid != 0 {
			return aa.Luid, true
		}
	}
	return 0, false
}

// TestRevertIdempotent verifies Revert clears its bookkeeping on success and a
// second call is a no-op (no repeated syscalls). Uses mocks, never real state.
func TestRevertIdempotent(t *testing.T) {
	var delCalls, setCalls int
	origDel, origSet := revertDeleteRoute, revertSetMetric
	revertDeleteRoute = func(r *windows.MibIpForwardRow2) error { delCalls++; return nil }
	revertSetMetric = func(r *windows.MibIpInterfaceRow) error { setCalls++; return nil }
	defer func() { revertDeleteRoute, revertSetMetric = origDel, origSet }()

	m := &routeManager{
		luid:     12345,
		added:    []windows.MibIpForwardRow2{{}, {}},
		ifMetric: [2]ifMetricState{{have: true, metric: 25, auto: 1}, {have: true, metric: 25, auto: 1}},
	}

	if err := m.Revert(); err != nil {
		t.Fatalf("first Revert: %v", err)
	}
	if len(m.added) != 0 || m.ifMetric[0].have || m.ifMetric[1].have {
		t.Fatalf("bookkeeping not cleared: added=%d ifMetric=%+v", len(m.added), m.ifMetric)
	}
	del1, set1 := delCalls, setCalls

	if err := m.Revert(); err != nil {
		t.Fatalf("second Revert: %v", err)
	}
	if delCalls != del1 || setCalls != set1 {
		t.Fatalf("second Revert repeated syscalls: del %d->%d, set %d->%d", del1, delCalls, set1, setCalls)
	}
}

// TestRevertPartialFailure verifies that when one sub-step fails, the others
// still run, the failure is aggregated into the returned error, and the failed
// item is kept for a later retry. Uses mocks, never real state.
func TestRevertPartialFailure(t *testing.T) {
	var delCalls, setCalls int
	origDel, origSet := revertDeleteRoute, revertSetMetric
	revertDeleteRoute = func(r *windows.MibIpForwardRow2) error {
		delCalls++
		if delCalls == 1 {
			return windows.ERROR_ACCESS_DENIED // first route fails to delete
		}
		return nil
	}
	revertSetMetric = func(r *windows.MibIpInterfaceRow) error { setCalls++; return nil }
	defer func() { revertDeleteRoute, revertSetMetric = origDel, origSet }()

	m := &routeManager{
		luid:     12345,
		added:    []windows.MibIpForwardRow2{{}, {}},
		ifMetric: [2]ifMetricState{{have: true, metric: 25, auto: 1}, {have: true, metric: 25, auto: 1}},
	}

	if err := m.Revert(); err == nil {
		t.Fatal("expected aggregated error")
	}
	if setCalls != 2 {
		t.Fatalf("metric restore did not run for both families despite route failure: %d", setCalls)
	}
	if len(m.added) != 1 {
		t.Fatalf("failed route should be kept for retry, got %d", len(m.added))
	}
	// Retry succeeds and clears the remainder.
	if err := m.Revert(); err != nil {
		t.Fatalf("second Revert after retry: %v", err)
	}
	if len(m.added) != 0 {
		t.Fatalf("added not cleared after retry: %d", len(m.added))
	}
}

// TestRestoreLinkMetricsOnlyWritesDrifted covers the physical-link metric guard
// (the 2026-10-04 "WLAN metric left altered" incident): it must restore a
// drifted family, must NOT write to a family that still matches the snapshot,
// must treat a vanished adapter as "nothing to restore", and must surface a real
// restore failure. Mocks only — never touches real state.
func TestRestoreLinkMetricsOnlyWritesDrifted(t *testing.T) {
	origGet, origSet := revertGetMetric, revertSetMetric
	defer func() { revertGetMetric, revertSetMetric = origGet, origSet }()

	type key struct {
		luid   uint64
		family uint16
	}
	// current models the live adapters: IPv4 drifted to metric 0 / auto 0 (the
	// exact shape observed on WLAN), IPv6 still at its snapshot value.
	current := map[key]ifMetricState{
		{1, windows.AF_INET}:  {have: true, metric: 0, auto: 0},
		{1, windows.AF_INET6}: {have: true, metric: 30, auto: 1},
	}
	var writes []key
	revertGetMetric = func(row *windows.MibIpInterfaceRow) error {
		st, ok := current[key{row.InterfaceLuid, row.Family}]
		if !ok {
			return windows.ERROR_NOT_FOUND // adapter gone
		}
		row.Metric = st.metric
		row.UseAutomaticMetric = st.auto
		return nil
	}
	revertSetMetric = func(row *windows.MibIpInterfaceRow) error {
		writes = append(writes, key{row.InterfaceLuid, row.Family})
		current[key{row.InterfaceLuid, row.Family}] = ifMetricState{have: true, metric: row.Metric, auto: row.UseAutomaticMetric}
		return nil
	}

	entries := []linkMetricJSON{
		{LUID: 1, Family: windows.AF_INET, Metric: 30, Auto: 1},   // drifted
		{LUID: 1, Family: windows.AF_INET6, Metric: 30, Auto: 1},  // matches: must not be written
		{LUID: 2, Family: windows.AF_INET, Metric: 25, Auto: 1},   // adapter gone: skipped, no error
	}
	if err := restoreLinkMetrics(entries); err != nil {
		t.Fatalf("restoreLinkMetrics: %v", err)
	}
	if len(writes) != 1 || writes[0] != (key{1, windows.AF_INET}) {
		t.Fatalf("writes = %v; want exactly the drifted IPv4 entry", writes)
	}
	if got := current[key{1, windows.AF_INET}]; got.metric != 30 || got.auto != 1 {
		t.Fatalf("restored = metric %d auto %d; want 30/1", got.metric, got.auto)
	}

	// A real restore failure must be reported, not swallowed.
	revertSetMetric = func(row *windows.MibIpInterfaceRow) error { return windows.ERROR_ACCESS_DENIED }
	current[key{1, windows.AF_INET6}] = ifMetricState{have: true, metric: 0, auto: 0}
	if err := restoreLinkMetrics([]linkMetricJSON{{LUID: 1, Family: windows.AF_INET6, Metric: 30, Auto: 1}}); err == nil {
		t.Fatal("restoreLinkMetrics with a failing Set: want error, got nil")
	}
}

// TestStateFileLifecycle covers the crash-recovery round trip: a state file
// written before a crash is picked up by recoverFromState, which restores the
// recorded metric/routes and then deletes the file. Uses mocks + a temp dir, no
// real state.
func TestStateFileLifecycle(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	var setCalls, delCalls int
	origSet, origDel := revertSetMetric, revertDeleteRoute
	revertSetMetric = func(r *windows.MibIpInterfaceRow) error { setCalls++; return nil }
	revertDeleteRoute = func(r *windows.MibIpForwardRow2) error { delCalls++; return nil }
	defer func() { revertSetMetric, revertDeleteRoute = origSet, origDel }()

	st := wgtunState{
		Version: stateFileVersion,
		LUID:    12345,
		Metric: [2]metricStateJSON{
			{Have: true, Metric: 25, Auto: 1},
			{Have: true, Metric: 25, Auto: 1},
		},
		Routes: []routeRowJSON{
			{InterfaceLuid: 12345, DestFamily: windows.AF_INET, DestAddr: []byte{0, 0, 0, 0}, DestPrefixLen: 0, NextHopFamily: windows.AF_INET, NextHopAddr: []byte{0, 0, 0, 0}},
		},
	}
	if err := writeStateFile(st); err != nil {
		t.Fatalf("writeStateFile: %v", err)
	}

	if err := recoverFromState(); err != nil {
		t.Fatalf("recoverFromState: %v", err)
	}
	if setCalls != 2 {
		t.Fatalf("metric restore should run for both families, got %d", setCalls)
	}
	if delCalls != 1 {
		t.Fatalf("route delete should run once, got %d", delCalls)
	}
	if _, err := os.Stat(stateFilePath()); !os.IsNotExist(err) {
		t.Fatalf("state file should be deleted after recovery, stat err=%v", err)
	}
}

// TestStateFileRecoveryFailure verifies that a failed recovery step keeps the
// state file on disk (as evidence) and returns an aggregated error.
func TestStateFileRecoveryFailure(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	origSet, origDel := revertSetMetric, revertDeleteRoute
	revertSetMetric = func(r *windows.MibIpInterfaceRow) error { return windows.ERROR_ACCESS_DENIED }
	revertDeleteRoute = func(r *windows.MibIpForwardRow2) error { return nil }
	defer func() { revertSetMetric, revertDeleteRoute = origSet, origDel }()

	st := wgtunState{
		Version: stateFileVersion,
		LUID:    12345,
		Metric: [2]metricStateJSON{
			{Have: true, Metric: 25, Auto: 1},
		},
	}
	if err := writeStateFile(st); err != nil {
		t.Fatalf("writeStateFile: %v", err)
	}

	if err := recoverFromState(); err == nil {
		t.Fatal("expected recovery to fail when a step fails")
	}
	if _, err := os.Stat(stateFilePath()); err != nil {
		t.Fatalf("state file should be kept on failure, stat err=%v", err)
	}
}

// TestRecoveryNotFoundIsIdempotent verifies that "element not found" during
// recovery is treated as idempotent success (the interface/route is already
// gone, which is the goal), so recovery keeps going and clears the state file
// instead of aborting with RECOVERY FAILED.
func TestRecoveryNotFoundIsIdempotent(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	var delCalls int
	origSet, origDel := revertSetMetric, revertDeleteRoute
	// Metric restore reports "element not found" (the wintun adapter is gone).
	revertSetMetric = func(r *windows.MibIpInterfaceRow) error { return windows.ERROR_NOT_FOUND }
	revertDeleteRoute = func(r *windows.MibIpForwardRow2) error { delCalls++; return nil }
	defer func() { revertSetMetric, revertDeleteRoute = origSet, origDel }()

	st := wgtunState{
		Version: stateFileVersion,
		LUID:    12345,
		Metric: [2]metricStateJSON{
			{Have: true, Metric: 25, Auto: 1},
			{Have: true, Metric: 25, Auto: 1},
		},
		Routes: []routeRowJSON{
			{InterfaceLuid: 12345, DestFamily: windows.AF_INET, DestAddr: []byte{0, 0, 0, 0}, DestPrefixLen: 0, NextHopFamily: windows.AF_INET, NextHopAddr: []byte{0, 0, 0, 0}},
		},
	}
	if err := writeStateFile(st); err != nil {
		t.Fatalf("writeStateFile: %v", err)
	}

	// Not-found must not fail recovery.
	if err := recoverFromState(); err != nil {
		t.Fatalf("recoverFromState should treat not-found as success: %v", err)
	}
	// Recovery continued past the not-found metric and still deleted the route.
	if delCalls != 1 {
		t.Fatalf("route delete should still run after not-found metric, got %d", delCalls)
	}
	// And the state file was cleared (no residue left behind).
	if _, err := os.Stat(stateFilePath()); !os.IsNotExist(err) {
		t.Fatalf("state file should be cleared, stat err=%v", err)
	}
}

// TestStateFileCorrupt verifies that a corrupt/unparseable state file is parked
// as *.corrupt and never blocks start-up (recoverFromState returns nil).
func TestStateFileCorrupt(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	if err := os.WriteFile(stateFilePath(), []byte("{ this is not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}

	if err := recoverFromState(); err != nil {
		t.Fatalf("corrupt state should not block start-up: %v", err)
	}
	if _, err := os.Stat(stateFilePath()); !os.IsNotExist(err) {
		t.Fatalf("corrupt state file should be parked, stat err=%v", err)
	}
	if _, err := os.Stat(stateFilePath() + ".corrupt"); err != nil {
		t.Fatalf("corrupt state should be renamed to .corrupt, stat err=%v", err)
	}
}

// TestResiduePresent verifies the residue signal tracks the state file's real
// existence: no file → no residue; a file (from a crash) → residue; a successful
// recoverFromState deletes the file and clears the residue.
func TestResiduePresent(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	if ResiduePresent() {
		t.Fatal("no state file should mean no residue")
	}

	if err := writeStateFile(wgtunState{Version: stateFileVersion, LUID: 1}); err != nil {
		t.Fatalf("writeStateFile: %v", err)
	}
	if !ResiduePresent() {
		t.Fatal("state file present should mean residue")
	}

	// Successful recovery (no metric/routes recorded, so it just deletes the
	// file) must clear the residue.
	if err := recoverFromState(); err != nil {
		t.Fatalf("recoverFromState: %v", err)
	}
	if ResiduePresent() {
		t.Fatal("residue should be cleared after successful recovery")
	}
}
