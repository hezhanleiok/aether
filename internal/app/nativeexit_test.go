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
// Note the second row deliberately ALSO sets NativeWireGuard=true: a user who
// enabled the native toggle must still not send the DEFAULT exit through the
// native transport — that conflation is exactly the bug this matrix guards.
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

// TestNativeTransportChoice pins the AWG-first rule: the native exit defaults
// to the AmneziaWG obfuscation (plain WireGuard is measurably easier to
// block), and plain WG is chosen ONLY when the user explicitly turned the
// obfuscation off. Unset defaults must not be read as "user wants plain WG".
func TestNativeTransportChoice(t *testing.T) {
	a := newNativeApp()
	cases := []struct {
		name string
		junk bool
		i1   string
		want string
	}{
		{"defaults -> AWG", false, "", "awg"},
		{"junk on -> AWG", true, "", "awg"},
		{"I1 profile -> AWG", false, "quic", "awg"},
		{"explicit off -> WG", false, "none", "wg"},
		{"explicit off (case) -> WG", false, "NONE", "wg"},
	}
	for _, c := range cases {
		s := a.Settings
		s.AWGJunk = c.junk
		s.AWGI1 = c.i1
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
