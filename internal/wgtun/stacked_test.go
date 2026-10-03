//go:build wgtun

package wgtun

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestStackedRecoveryDeletesInnerRoute verifies that recoverFromState, on a
// stacked state, first deletes the inner endpoint route (using the OUTER
// adapter's LUID) before restoring metric and clearing the file.
func TestStackedRecoveryDeletesInnerRoute(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	var deletedLuids []uint64
	origSet, origDel := revertSetMetric, revertDeleteRoute
	revertSetMetric = func(r *windows.MibIpInterfaceRow) error { return windows.ERROR_NOT_FOUND }
	revertDeleteRoute = func(r *windows.MibIpForwardRow2) error {
		deletedLuids = append(deletedLuids, r.InterfaceLuid)
		return nil
	}
	defer func() { revertSetMetric, revertDeleteRoute = origSet, origDel }()

	const outerLUID = uint64(88888)
	st := wgtunState{
		Version: stateFileVersion,
		LUID:    99999, // metric-restore LUID (a different value, on purpose)
		Stacked: true,
		InnerEp: innerEpState{Dst: "162.159.192.100", LUID: outerLUID, IfIndex: 4, Family: windows.AF_INET},
		Metric:  [2]metricStateJSON{{Have: true, Metric: 25, Auto: 1}},
	}
	if err := writeStateFile(st); err != nil {
		t.Fatalf("writeStateFile: %v", err)
	}

	if err := recoverFromState(); err != nil {
		t.Fatalf("recoverFromState: %v", err)
	}

	// The inner endpoint route (on the OUTER adapter, luid=88888) must have been
	// deleted first.
	found := false
	for _, l := range deletedLuids {
		if l == outerLUID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("inner endpoint route (luid %d) was not deleted; deleted=%v", outerLUID, deletedLuids)
	}

	// And the state file is cleared.
	if _, err := os.Stat(stateFilePath()); !os.IsNotExist(err) {
		t.Fatalf("state file should be cleared, stat err=%v", err)
	}
}

// TestExcludeEndpoint keeps the outer probe pool free of the inner endpoint:
// both layers on one UDP 5-tuple creates a routing loop inside the outer tunnel.
func TestExcludeEndpoint(t *testing.T) {
	cands := []string{"8.6.112.7:4500", "8.6.112.8:2408", "8.34.146.7:2408"}
	got := excludeEndpoint(cands, "8.6.112.8:2408")
	if len(got) != 2 || got[0] != "8.6.112.7:4500" || got[1] != "8.34.146.7:2408" {
		t.Fatalf("excludeEndpoint = %v", got)
	}
	// No exclusion: input must pass through untouched.
	if all := excludeEndpoint(cands, ""); len(all) != 3 {
		t.Fatalf("excludeEndpoint(noop) = %v", all)
	}
	// A miss changes nothing.
	if same := excludeEndpoint(cands, "9.9.9.9:4500"); len(same) != 3 {
		t.Fatalf("excludeEndpoint(miss) = %v", same)
	}
}

// TestBuildStacked verifies the offline assembly: outer identity from aether.toml
// (with its Reserved), inner from a saved account file (Reserved dropped — a
// tunnel_type=wireguard account fails its handshake with Reserved applied),
// outer endpoint = fastest cached, inner endpoint differs.
func TestBuildStacked(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	configDir := t.TempDir()
	toml := `wg_private_key = "UGC3bYif/poF1x11MGunhAUnvoVqCY2raka2iasXCX4="
wg_peer_public_key = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
ipv4 = "172.16.0.2"
ipv6 = "2606:4700:110:8407::1"
client_id = "8znU"
assigned_endpoint = "162.159.192.7"
`
	if err := os.WriteFile(filepath.Join(configDir, "aether.toml"), []byte(toml), 0o600); err != nil {
		t.Fatalf("write aether.toml: %v", err)
	}

	inner := &WarpAccount{
		PrivateKey:    "qD01vJkqOSOq9mC7sgXllL1sikcLc6WKz7oufDHjg1E=",
		PublicKey:     "rsB4YqmNhRqU7TsU4/kSf0zSv8bw9/Gd2ZPfivDfZno=",
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		AddressV4:     "172.16.0.2",
		AddressV6:     "2606:4700:110:83d8::1",
		Reserved:      [3]byte{171, 231, 48},
	}
	accPath, err := SaveAccount(inner)
	if err != nil {
		t.Fatalf("SaveAccount: %v", err)
	}

	outerCfg, innerCfg, err := BuildStacked(configDir, accPath)
	if err != nil {
		t.Fatalf("BuildStacked: %v", err)
	}

	if outerCfg.PrivateKey != "UGC3bYif/poF1x11MGunhAUnvoVqCY2raka2iasXCX4=" {
		t.Fatalf("outer priv = %q", outerCfg.PrivateKey)
	}
	if outerCfg.Reserved != [3]byte{} || outerCfg.HasReserved {
		t.Fatalf("outer reserved = %v hasReserved=%v, want dropped", outerCfg.Reserved, outerCfg.HasReserved)
	}
	if innerCfg.PrivateKey != inner.PrivateKey {
		t.Fatalf("inner priv mismatch")
	}
	if innerCfg.Reserved != [3]byte{} || innerCfg.HasReserved {
		t.Fatalf("inner reserved = %v hasReserved=%v, want none (wireguard-type account rejects it)",
			innerCfg.Reserved, innerCfg.HasReserved)
	}
	if outerCfg.HasReserved {
		t.Fatal("outer reserved must be dropped in BuildStacked (Reserved-carrying handshakes are rejected end-to-end)")
	}
	if innerCfg.InterfaceName != "Xiaohe-inner" {
		t.Fatalf("inner ifname = %q", innerCfg.InterfaceName)
	}
	if innerCfg.MTU != 1360 { // outer 1440 - 80
		t.Fatalf("inner MTU = %d", innerCfg.MTU)
	}
	if outerCfg.MTU != 1440 {
		t.Fatalf("outer MTU = %d", outerCfg.MTU)
	}
	if outerCfg.Endpoint == "" || outerCfg.Endpoint == innerCfg.Endpoint {
		t.Fatalf("endpoints: outer=%q inner=%q", outerCfg.Endpoint, innerCfg.Endpoint)
	}
}
