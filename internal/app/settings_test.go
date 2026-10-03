package app

import (
	"testing"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/vpn"
)

func TestTunnelBusy(t *testing.T) {
	busy := []vpn.Status{
		vpn.StatusConnecting,
		vpn.StatusConnected,
		vpn.StatusReconnecting,
		vpn.StatusAetherUp,
		vpn.StatusStartingPsiphon,
		vpn.StatusPsiphonConnecting,
		vpn.StatusTesting,
	}
	for _, st := range busy {
		if !tunnelBusy(st) {
			t.Errorf("tunnelBusy(%q) = false, want true", st)
		}
	}
	safe := []vpn.Status{
		vpn.StatusDisconnected,
		vpn.StatusFailed,
		vpn.StatusUnavailable,
	}
	for _, st := range safe {
		if tunnelBusy(st) {
			t.Errorf("tunnelBusy(%q) = true, want false", st)
		}
	}
}

// TestReconcileStackedWireGuard verifies the protocol-switch guard: a change is
// rejected only while the tunnel is busy, and a change is honoured while
// disconnected.
func TestReconcileStackedWireGuard(t *testing.T) {
	cur := config.Settings{StackedWireGuard: false}

	// Busy + attempted toggle -> reverted to current value.
	next := config.Settings{StackedWireGuard: true}
	got := reconcileStackedWireGuard(next, cur, true)
	if got.StackedWireGuard != false {
		t.Errorf("busy toggle: got %v, want reverted to %v", got.StackedWireGuard, false)
	}

	// Disconnected + attempted toggle -> honoured.
	got = reconcileStackedWireGuard(next, cur, false)
	if got.StackedWireGuard != true {
		t.Errorf("disconnected toggle: got %v, want %v", got.StackedWireGuard, true)
	}

	// Busy but no change -> untouched.
	same := config.Settings{StackedWireGuard: false}
	got = reconcileStackedWireGuard(same, cur, true)
	if got.StackedWireGuard != false {
		t.Errorf("busy no-change: got %v, want %v", got.StackedWireGuard, false)
	}
}

// TestStackedWireGuardStateGuards maps every VPN status to whether flipping
// StackedWireGuard is allowed. It pins the contract the GUI relies on: only the
// busy (live/transitional) states block the switch, while Disconnected, Failed,
// Unavailable and TrafficTestFailed all permit a change. Failed in particular
// must stay unlocked — a failed tunnel is terminal and the user must be able to
// switch protocol and retry (regression guard for the frontend switch locking up
// on Failed, which was stricter than the backend tunnelBusy guard).
func TestStackedWireGuardStateGuards(t *testing.T) {
	cur := config.Settings{StackedWireGuard: false}
	next := config.Settings{StackedWireGuard: true}

	cases := []struct {
		st   vpn.Status
		want bool // true: change honoured (allowed); false: reverted (blocked)
	}{
		{vpn.StatusDisconnected, true},
		{vpn.StatusFailed, true}, // terminal: user must be able to switch and retry
		{vpn.StatusUnavailable, true},
		{vpn.StatusTrafficFailed, true},
		{vpn.StatusConnecting, false},
		{vpn.StatusConnected, false},
		{vpn.StatusReconnecting, false},
		{vpn.StatusTesting, false},
		{vpn.StatusAetherUp, false},
		{vpn.StatusStartingPsiphon, false},
		{vpn.StatusPsiphonConnecting, false},
	}
	for _, c := range cases {
		busy := tunnelBusy(c.st)
		got := reconcileStackedWireGuard(next, cur, busy)
		honoured := got.StackedWireGuard == true
		if honoured != c.want {
			t.Errorf("status %q: change honoured=%v, want %v (tunnelBusy=%v)", c.st, honoured, c.want, busy)
		}
	}
}
