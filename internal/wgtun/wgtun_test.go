//go:build wgtun

package wgtun

import (
	"strings"
	"testing"
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
		Reserved:      [3]byte{243, 57, 212},
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

// TestReservedEncoding locks in the WARP reserved-bytes convention: the three
// bytes must land in the top three bytes of the initiation's uint32 type field
// (byte 0 is the message type, bytes 1..3 are the reserved client identifier).
func TestReservedEncoding(t *testing.T) {
	const msgType = 1 // device.MessageInitiationType
	reserved := [3]byte{0xF3, 0x39, 0xD4}
	// 243,57,212 is the Reserved triple from aether.toml ("Fzk=..."-style id).
	typ := msgType | uint32(reserved[0])<<8 | uint32(reserved[1])<<16 | uint32(reserved[2])<<24
	if got := []byte{byte(typ), byte(typ >> 8), byte(typ >> 16), byte(typ >> 24)}; got[0] != 1 || got[1] != reserved[0] || got[2] != reserved[1] || got[3] != reserved[2] {
		t.Fatalf("reserved encoding wrong: %v", got)
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
