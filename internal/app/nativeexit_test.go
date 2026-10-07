//go:build wgtun

package app

import (
	"testing"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/vpn"
)

// TestExitSelectionMatrix pins the product table: the EXIT — not the protocol
// toggle — decides whether the native transport is involved at all.
//
//	Default: useNativeWG == false, NativeExitOnly == ""
//	Psiphon: useNativeWG == true,  NativeExitOnly == "psiphon"
//	Tor:     useNativeWG == true,  NativeExitOnly == "tor"
//
// Note the second row deliberately ALSO sets NativeWireGuard=true: useNativeWG
// is the EXIT gate (Psiphon/Tor only) and must stay false for the default exit
// regardless of the native toggle. The default exit's OPT-IN native dispatch is
// a separate decision (defaultExitNative in Connect) and is covered by
// TestDefaultExitNative below, not by this matrix.
func TestExitSelectionMatrix(t *testing.T) {
	a := newNativeApp()
	cases := []struct {
		name         string
		chain        string
		nativeToggle bool
		wantUse      bool
		wantExit     string
	}{
		{"default, native off", "", false, false, ""},
		{"default, native on", "", true, false, ""},
		{"psiphon, native off", "psiphon", false, true, "psiphon"},
		{"psiphon, native on", "psiphon", true, true, "psiphon"},
		{"tor, native off", "tor", false, true, "tor"},
		{"tor, native on", "tor", true, true, "tor"},
		{"psiphon_reverse", "psiphon_reverse", true, false, ""},
	}
	for _, c := range cases {
		s := a.Settings
		s.ExitChain = c.chain
		s.NativeWireGuard = c.nativeToggle
		if got := a.useNativeWG(s); got != c.wantUse {
			t.Errorf("%s: useNativeWG = %v, want %v", c.name, got, c.wantUse)
		}
		if got := vpn.NativeExitOnly(s); got != c.wantExit {
			t.Errorf("%s: NativeExitOnly = %q, want %q", c.name, got, c.wantExit)
		}
	}
}

// TestDefaultExitNative pins the default-exit OPT-IN native dispatch: stacked
// beats the single toggle, the single toggle beats the core, and with neither
// set the default exit stays on the core path.
func TestDefaultExitNative(t *testing.T) {
	cases := []struct {
		name    string
		native  bool
		stacked bool
		want    string
	}{
		{"core by default", false, false, ""},
		{"native toggle", true, false, "wg"},
		{"stacked wins over native toggle", true, true, "stacked"},
		{"stacked alone", false, true, "stacked"},
	}
	for _, c := range cases {
		s := config.Settings{NativeWireGuard: c.native, StackedWireGuard: c.stacked}
		if got := defaultExitNative(s); got != c.want {
			t.Errorf("%s: defaultExitNative = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestNativeTransportChoice pins the AWG-first rule for a native exit: auto
// ("" and unrecognised values) keeps the AmneziaWG obfuscation because plain
// WireGuard is measurably easier to block, while an explicit "wg" is honoured.
//
// The choice is read from ExitNativeTransport — a dedicated transport
// preference — and deliberately NOT from AWGJunk/AWGI1. Those are the
// obfuscation PARAMETERS; reusing AWGI1 == "none" as a transport signal
// (f4cb020) conflated the I1 packet layer with the transport layer and left the
// UI no way to ask for plain WireGuard on a Psiphon/Tor exit.
func TestNativeTransportChoice(t *testing.T) {
	a := newNativeApp()
	cases := []struct {
		name string
		tsp  string
		want string
	}{
		{"auto/unset -> AWG", "", "awg"},
		{"explicit awg -> AWG", "awg", "awg"},
		{"explicit wg -> WG", "wg", "wg"},
		{"case insensitive -> WG", "WG", "wg"},
		{"padded -> WG", " wg ", "wg"},
		{"unrecognised -> AWG (auto)", "bogus", "awg"},
	}
	for _, c := range cases {
		s := a.Settings
		s.ExitNativeTransport = c.tsp
		if got := a.nativeTransportChoice(s); got != c.want {
			t.Errorf("%s: transport = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestNativeExitGeneration covers the session bookkeeping: a fresh session is
// valid; endNativeExit invalidates exactly its own generation; a rollback of a
// stale generation does NOT own the teardown; a newer session supersedes an
// older one.
func TestNativeExitGeneration(t *testing.T) {
	a := newNativeApp()

	g1 := a.beginNativeExit("psiphon", "awg")
	if !a.nativeExitValid(g1) {
		t.Fatal("fresh session must be valid")
	}
	// The first rollback owns the teardown.
	if !a.endNativeExit(g1) {
		t.Fatal("ending the live session must report ownership")
	}
	if a.nativeExitValid(g1) {
		t.Fatal("ended session must be invalid")
	}
	// Idempotent: a second rollback of the same generation must not own it.
	if a.endNativeExit(g1) {
		t.Fatal("double end must report no ownership (idempotency)")
	}

	// A newer session supersedes the old: rolling back the OLD one must not
	// tear down the new one's state.
	g2 := a.beginNativeExit("tor", "wg")
	if !a.nativeExitValid(g2) {
		t.Fatal("second session must be valid")
	}
	if a.nativeExitValid(g1) {
		t.Fatal("stale generation must be invalid")
	}
	if a.endNativeExit(g1) {
		t.Fatal("ending a stale generation must not report ownership")
	}
	if !a.nativeExitValid(g2) {
		t.Fatal("stale end must not affect the newer session")
	}
}

// TestNativeExitDisconnectInvalidates proves the Disconnect entry point kills
// the session: a live session must not survive Disconnect, so its late core
// events can no longer pass the gate.
func TestNativeExitDisconnectInvalidates(t *testing.T) {
	a := newNativeApp()
	gen := a.beginNativeExit("psiphon", "awg")
	if !a.nativeExitValid(gen) {
		t.Fatal("session must start valid")
	}
	a.Disconnect()
	if a.nativeExitValid(gen) {
		t.Fatal("Disconnect must invalidate the native exit session")
	}
}

// TestNativeExitSettingsUntouched keeps the default-exit guarantee honest at
// the settings level too: nothing about a native exit leaks into the default
// settings (the reverse direction — that Default never CALLS the native path —
// is TestExitSelectionMatrix plus the dispatch in Connect).
func TestNativeExitSettingsUntouched(t *testing.T) {
	s := config.Defaults()
	if s.ExitChain != "" {
		t.Fatalf("default exit_chain = %q, want empty", s.ExitChain)
	}
	if s.AWGJunk || s.AWGI1 != "" {
		t.Fatal("AWG must be off in default settings (opt-in)")
	}
}
