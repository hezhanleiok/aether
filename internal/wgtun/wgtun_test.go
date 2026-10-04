//go:build wgtun

package wgtun

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestKeyToHex(t *testing.T) {
	// base64 of 32 zero bytes -> 64 zero hex chars.
	got, err := keyToHex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatalf("keyToHex: %v", err)
	}
	if len(got) != 64 || got != strings.Repeat("0", 64) {
		t.Fatalf("got %q (%d chars), want 64 zeros", got, len(got))
	}

	if _, err := keyToHex("short"); err == nil {
		t.Fatal("expected error for a short key")
	}
}

func TestBuildUAPI(t *testing.T) {
	priv := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	pub := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	cfg := Config{
		PrivateKey:    priv,
		PeerPublicKey: pub,
		Endpoint:      "162.159.192.7:2408",
	}
	out, err := buildUAPI(cfg)
	if err != nil {
		t.Fatalf("buildUAPI: %v", err)
	}
	zeroKey := strings.Repeat("0", 64)
	for _, want := range []string{
		"private_key=" + zeroKey,
		"public_key=" + zeroKey,
		"endpoint=162.159.192.7:2408",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("UAPI missing %q\n%s", want, out)
		}
	}
}

// TestSetAdapterMTU asserts the MTU fix issues the right syscall arguments for
// BOTH families: this is what separates "adapter MTU really pinned to 1280"
// (like the official client) from "wireguard-go merely reports 1280" (the bug —
// the adapter stayed at wintun's 65535 default and TCP emitted packets the
// tunnel could not carry).
func TestSetAdapterMTU(t *testing.T) {
	orig := setInterfaceEntry
	defer func() { setInterfaceEntry = orig }()

	var got []windows.MibIpInterfaceRow
	setInterfaceEntry = func(row *windows.MibIpInterfaceRow) error {
		got = append(got, *row)
		return nil
	}

	const luid = 0x1122334455667788
	if err := setAdapterMTU(luid, 1280); err != nil {
		t.Fatalf("setAdapterMTU: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("syscalls = %d, want 2 (IPv4 + IPv6)", len(got))
	}
	wantFamilies := []uint16{windows.AF_INET, windows.AF_INET6}
	for i, row := range got {
		if row.Family != wantFamilies[i] {
			t.Errorf("call %d: family = %d, want %d", i, row.Family, wantFamilies[i])
		}
		if row.InterfaceLuid != luid {
			t.Errorf("call %d: luid = %#x, want %#x", i, row.InterfaceLuid, luid)
		}
		if row.NlMtu != 1280 {
			t.Errorf("call %d: NlMtu = %d, want 1280", i, row.NlMtu)
		}
	}

	// A rejected MTU must be reported, and a rejected family must not stop the
	// other one from being configured.
	got = nil
	calls := 0
	setInterfaceEntry = func(row *windows.MibIpInterfaceRow) error {
		calls++
		if calls == 1 {
			return windows.ERROR_ACCESS_DENIED
		}
		got = append(got, *row)
		return nil
	}
	if err := setAdapterMTU(luid, 1280); err == nil {
		t.Fatal("first family failing: want error")
	}
	if len(got) != 1 || got[0].Family != windows.AF_INET6 {
		t.Fatalf("IPv6 not configured after IPv4 failed: %+v", got)
	}

	// An invalid MTU must not touch the adapter at all.
	got = nil
	setInterfaceEntry = func(row *windows.MibIpInterfaceRow) error {
		got = append(got, *row)
		return nil
	}
	if err := setAdapterMTU(luid, 0); err == nil {
		t.Fatal("MTU 0: want error")
	}
	if len(got) != 0 {
		t.Fatalf("invalid MTU issued %d syscalls, want 0", len(got))
	}
}

// TestHasHandshake verifies the UAPI handshake-dump parser used by WaitHandshake.
func TestHasHandshake(t *testing.T) {
	if hasHandshake("") {
		t.Fatal("empty dump should report no handshake")
	}
	if hasHandshake("last_handshake_time_sec=0\nlast_handshake_time_nsec=0\n") {
		t.Fatal("zero handshake time should report no handshake")
	}
	if !hasHandshake("private_key=deadbeef\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=123\n") {
		t.Fatal("positive handshake time should report handshaken")
	}
}
