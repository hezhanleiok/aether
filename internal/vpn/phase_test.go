//go:build wgtun

package vpn

import (
	"testing"

	"github.com/aethergui/aethergui/internal/coremgr"
	"github.com/aethergui/aethergui/internal/config"
)

// TestManagerSetPhase proves the SSE-side progress label is set and cleared
// independently of the connect/disconnect Status machine.
func TestManagerSetPhase(t *testing.T) {
	m := New(coremgr.NewManager(coremgr.NewProcessBackend()))

	m.SetPhase("probe 37/112")
	if got := m.State().Phase; got != "probe 37/112" {
		t.Fatalf("Phase = %q; want %q", got, "probe 37/112")
	}

	m.SetPhase("inner-handshake")
	if got := m.State().Phase; got != "inner-handshake" {
		t.Fatalf("Phase = %q; want %q", got, "inner-handshake")
	}

	m.SetPhase("")
	if got := m.State().Phase; got != "" {
		t.Fatalf("Phase = %q; want empty", got)
	}
}

// TestSetNativeStateClearsPhase proves the deferred-phase cleanup added in
// 2b-1: a phase label survives while Connecting but is wiped the moment the
// state machine leaves the connecting state (success/failure/cancel), so a
// stale "inner-handshake" can't linger on a disconnected UI.
func TestSetNativeStateClearsPhase(t *testing.T) {
	m := New(coremgr.NewManager(coremgr.NewProcessBackend()))

	m.SetPhase("inner-handshake")
	m.SetNativeState(StatusConnecting, config.ModeWARP, "")
	if got := m.State().Phase; got != "inner-handshake" {
		t.Fatalf("Phase while Connecting = %q; want %q", got, "inner-handshake")
	}

	m.SetNativeState(StatusConnected, config.ModeWARP, "")
	if got := m.State().Phase; got != "" {
		t.Fatalf("Phase after Connected = %q; want empty", got)
	}

	// Failure path also clears it.
	m.SetPhase("probe 37/112")
	m.SetNativeState(StatusFailed, config.ModeWARP, "boom")
	if got := m.State().Phase; got != "" {
		t.Fatalf("Phase after Failed = %q; want empty", got)
	}
}
