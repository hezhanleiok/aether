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
