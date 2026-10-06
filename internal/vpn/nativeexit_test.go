package vpn

import (
	"testing"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/coremgr"
)

// newManager builds a Manager around an empty process backend: no core ever
// starts, but the stop/cleanup paths have a real object to work on.
func newManager() *Manager {
	return New(coremgr.NewManager(coremgr.NewProcessBackend()))
}

// TestBackendReadyGateIsTheStaleEventGuard pins the fix for the real-machine
// incident: after the user cancelled (the native tunnel was already reverted),
// the core kept bootstrapping and its late psiphon_ready pushed the global
// state straight to Connected. With a gate installed, that event may only set
// backendReady — never Connected.
func TestBackendReadyGateIsTheStaleEventGuard(t *testing.T) {
	m := newManager()

	// No gate: the classic path promotes to Connected, unchanged.
	m.markBackendReady(func(st *State) { st.Error = "" })
	if m.State().Status != StatusConnected {
		t.Fatalf("no gate: status = %q, want Connected", m.State().Status)
	}
	if !m.BackendReady() {
		t.Fatal("backendReady must be recorded")
	}

	// Gate closed (session cancelled): the same event must NOT connect.
	m.Disconnect() // resets backendReady and the gate for a clean session
	if m.BackendReady() {
		t.Fatal("Disconnect must clear backendReady")
	}
	cancelled := true // the native exit session was invalidated by a disconnect
	m.SetConnectGate(func() bool { return !cancelled })
	m.markBackendReady(func(st *State) { st.Error = "" })
	if m.State().Status == StatusConnected {
		t.Fatal("a gated (cancelled) session must not be promoted to Connected by a core event")
	}
	if !m.BackendReady() {
		t.Fatal("the event itself is still recorded — backend ready is a fact")
	}

	// The gate only ever holds Connected; it must not swallow the status when
	// the session is valid again (a fresh, wanted session).
	m.Disconnect()
	valid := false
	m.SetConnectGate(func() bool { return valid })
	m.markBackendReady(func(st *State) { st.Error = "" })
	if m.State().Status != StatusDisconnected {
		t.Fatalf("still gated: status = %q", m.State().Status)
	}
	valid = true
	m.markBackendReady(func(st *State) { st.Error = "" })
	if m.State().Status != StatusConnected {
		t.Fatalf("valid session: status = %q, want Connected", m.State().Status)
	}
}

// TestDisconnectClearsExitState pins the cleanup contract: nothing of one
// session's exit bookkeeping may survive into the next connect — the old code
// left st.Chain = "psiphon_only" behind, which made a disconnected app look
// like it still had an exit backend.
func TestDisconnectClearsExitState(t *testing.T) {
	m := newManager()
	// Simulate what a native-exit session leaves behind.
	m.mu.Lock()
	m.chain = ChainPsiphonOnly
	m.st.Chain = ChainPsiphonOnly
	m.exitHTTPPort = 1822
	m.backendReady = true
	m.mu.Unlock()
	m.SetConnectGate(func() bool { return false })

	m.Disconnect()

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.chain != ChainNone {
		t.Errorf("chain = %q, want none", m.chain)
	}
	if m.st.Chain != "" {
		t.Errorf("st.Chain = %q, want empty", m.st.Chain)
	}
	if m.exitHTTPPort != 0 {
		t.Errorf("exitHTTPPort = %d, want 0", m.exitHTTPPort)
	}
	if m.backendReady {
		t.Error("backendReady must be cleared")
	}
	if m.connectGate != nil {
		t.Error("connectGate must be cleared — a stale gate would block the NEXT session's Connected forever")
	}
	if m.State().Status != StatusDisconnected {
		t.Errorf("status = %q, want Disconnected", m.State().Status)
	}
}

// TestOnlyChainFor covers the mapping the native exit hands the core:
// psiphon/tor exit choices become the only-mode chains, everything else (and
// in particular reverse, where the backend is the ENTRY) maps to none.
func TestOnlyChainFor(t *testing.T) {
	cases := map[string]string{
		"":                  ChainNone,
		ChainPsiphon:        ChainPsiphonOnly,
		ChainPsiphonOnly:    ChainPsiphonOnly,
		ChainPsiphonReverse: ChainNone,
		ChainTor:            ChainTorOnly,
		ChainTorOnly:        ChainTorOnly,
	}
	for chain, want := range cases {
		s := config.Defaults()
		s.ExitChain = chain
		if got := OnlyChainFor(s); got != want {
			t.Errorf("OnlyChainFor(%q) = %q, want %q", chain, got, want)
		}
	}
}
