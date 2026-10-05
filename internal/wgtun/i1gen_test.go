//go:build wgtun

package wgtun

import (
	"bytes"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"
)

// pinned returns a deterministic generator so the packet shapes can be asserted
// (the connect path passes nil and gets crypto/rand).
func pinned() *rand.ChaCha8 {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	return rand.NewChaCha8(seed)
}

// TestGenerateI1QUICShape pins what a classifier keys on: the long-header byte
// and the QUIC version, plus that the packet stays inside the size budget.
func TestGenerateI1QUICShape(t *testing.T) {
	pkt, err := GenerateI1(I1QUIC, "www.apple.com", pinned())
	if err != nil {
		t.Fatal(err)
	}
	if pkt[0] != 0xC0 {
		t.Fatalf("first byte = 0x%02x, want 0xC0 (QUIC long header, Initial)", pkt[0])
	}
	if !bytes.Equal(pkt[1:5], []byte{0x00, 0x00, 0x00, 0x01}) {
		t.Fatalf("version = %x, want 00000001", pkt[1:5])
	}
	if len(pkt) > maxI1Size {
		t.Fatalf("packet is %d bytes, max %d", len(pkt), maxI1Size)
	}
	if !bytes.Contains(pkt, []byte("www.apple.com")) {
		t.Fatal("QUIC I1 must carry the SNI it was given")
	}
}

// TestGenerateI1ProfilesShape pins the marker bytes of the other profiles: the
// STUN magic cookie, the DNS header/QTYPE tail, and the SIP request line.
func TestGenerateI1ProfilesShape(t *testing.T) {
	r := pinned()

	stun, err := GenerateI1(I1STUN, "", r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stun[:2], []byte{0x00, 0x01}) {
		t.Fatalf("STUN type = %x, want 0001 (binding request)", stun[:2])
	}
	if !bytes.Equal(stun[4:8], []byte{0x21, 0x12, 0xa4, 0x42}) {
		t.Fatalf("STUN magic cookie = %x, want 2112a442", stun[4:8])
	}

	dns, err := GenerateI1(I1DNS, "", r)
	if err != nil {
		t.Fatal(err)
	}
	if dns[2] != 0x01 || dns[3] != 0x00 {
		t.Fatalf("DNS flags = %x, want 0100 (standard query, RD)", dns[2:4])
	}
	if !bytes.Equal(dns[len(dns)-4:], []byte{0x00, 0x01, 0x00, 0x01}) {
		t.Fatalf("DNS tail = %x, want QTYPE A / QCLASS IN", dns[len(dns)-4:])
	}
	if dns[len(dns)-5] != 0x00 {
		t.Fatal("DNS name must be NUL-terminated")
	}

	sip, err := GenerateI1(I1SIP, "sip.example.com", r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(sip), "INVITE sip:user@sip.example.com SIP/2.0") {
		t.Fatalf("SIP request line = %q", string(sip[:40]))
	}

	randpkt, err := GenerateI1(I1Random, "", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(randpkt) != 128 {
		t.Fatalf("random I1 = %d bytes, want 128", len(randpkt))
	}
}

// TestGenerateI1NoneAndUnknown: "none" must be a clean no-op (not a random
// packet), and a typo must be an error rather than a silent fallback.
func TestGenerateI1NoneAndUnknown(t *testing.T) {
	for _, p := range []string{"", I1None, "NoNe"} {
		pkt, err := GenerateI1(p, "", pinned())
		if err != nil || pkt != nil {
			t.Fatalf("GenerateI1(%q) = %v, %v; want nil packet", p, pkt, err)
		}
	}
	if _, err := GenerateI1("quicc", "", pinned()); err == nil {
		t.Fatal("unknown profile must be an error, not a silent fallback")
	}
}

// TestParseI1 covers both input forms: raw hex (an externally generated packet
// must go out byte-for-byte, e.g. warpscout's -i1) and a profile name.
func TestParseI1(t *testing.T) {
	raw := []byte{0xc1, 0x00, 0x00, 0x00, 0x01, 0xaa}
	got, err := ParseI1(hex.EncodeToString(raw), "", pinned())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("hex passthrough = %x, want %x", got, raw)
	}
	// AmneziaWG's "<b 0x..>" wrapper must be accepted too.
	got, err = ParseI1("<b 0x"+hex.EncodeToString(raw)+">", "", pinned())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("<b ..> wrapper = %x, want %x", got, raw)
	}
	// A profile name still works.
	got, err = ParseI1("stun", "", pinned())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[4:8], []byte{0x21, 0x12, 0xa4, 0x42}) {
		t.Fatalf("profile path = %x, want a STUN packet", got[:8])
	}
	// Oversized input is rejected instead of being truncated.
	big := make([]byte, maxI1Size+1)
	if _, err := ParseI1(hex.EncodeToString(big), "", pinned()); err == nil {
		t.Fatal("oversized I1 must be rejected")
	}
}

// TestBuildUAPICarriesI1 proves the fake packet reaches the device: the UAPI
// stream must carry it, and must NOT when it is unset (the baseline).
func TestBuildUAPICarriesI1(t *testing.T) {
	base := Config{
		PrivateKey:    testOverridePrivKey,
		PeerPublicKey: testOverridePubKey,
		Endpoint:      "8.35.211.174:500",
	}
	plain, err := buildUAPI(base)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "i1=") {
		t.Fatalf("baseline UAPI must not carry i1:\n%s", plain)
	}
	withI1 := base
	withI1.JunkI1 = []byte{0xc1, 0x00, 0x00, 0x00, 0x01}
	got, err := buildUAPI(withI1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "i1=c100000001") {
		t.Fatalf("UAPI missing the i1 key:\n%s", got)
	}
}
