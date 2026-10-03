//go:build wgtun

package wgtun

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	privRaw, _ := base64.StdEncoding.DecodeString(priv)
	pubRaw, _ := base64.StdEncoding.DecodeString(pub)
	if len(privRaw) != 32 || len(pubRaw) != 32 {
		t.Fatalf("key lens = %d/%d, want 32/32", len(privRaw), len(pubRaw))
	}
	// Clamp checks.
	if privRaw[0]&7 != 0 {
		t.Fatalf("private key not clamped (low 3 bits)")
	}
	if privRaw[31]&128 != 0 {
		t.Fatalf("private key not clamped (top bit)")
	}
	if privRaw[31]&64 == 0 {
		t.Fatalf("private key not clamped (bit 6)")
	}
	// Public key must equal X25519(priv, basepoint).
	derived, _ := curve25519.X25519(privRaw, curve25519.Basepoint)
	if !bytes.Equal(derived, pubRaw) {
		t.Fatalf("public key mismatch")
	}
}

func TestRegisterAccount(t *testing.T) {
	// client_id "AQID" = base64([1,2,3]).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST only (no PATCH)", r.Method)
		}
		if r.Header.Get("User-Agent") != cfUserAgent {
			t.Errorf("UA = %s", r.Header.Get("User-Agent"))
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("bad body: %v", err)
		}
		if req["key"] == "" {
			t.Errorf("missing key in request")
		}
		if req["key_type"] != "curve25519" {
			t.Errorf("key_type = %q, want curve25519", req["key_type"])
		}
		if req["tunnel_type"] != "wireguard" {
			t.Errorf("tunnel_type = %q, want wireguard", req["tunnel_type"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"test-id",
			"token":"test-token",
			"key_type":"curve25519",
			"tunnel_type":"wireguard",
			"config":{
				"client_id":"AQID",
				"peers":[{"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}],
				"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::1"}}
			}
		}`))
	}))
	defer srv.Close()

	acc, err := RegisterAccount(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("RegisterAccount: %v", err)
	}
	if acc.PrivateKey == "" || acc.PublicKey == "" {
		t.Fatal("missing local keys")
	}
	if acc.PeerPublicKey != "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
		t.Fatalf("peer key = %q", acc.PeerPublicKey)
	}
	if acc.AddressV4 != "172.16.0.2" {
		t.Fatalf("v4 = %q", acc.AddressV4)
	}
	if acc.AddressV6 != "2606:4700:110::1" {
		t.Fatalf("v6 = %q", acc.AddressV6)
	}
	if acc.Reserved != [3]byte{1, 2, 3} {
		t.Fatalf("reserved = %v, want [1 2 3]", acc.Reserved)
	}
	if acc.AccountID != "test-id" || acc.Token != "test-token" {
		t.Fatalf("id/token = %q/%q", acc.AccountID, acc.Token)
	}
	if acc.TunnelType != "wireguard" {
		t.Fatalf("tunnel_type = %q, want wireguard", acc.TunnelType)
	}
}

func TestRegisterAccountMissingClientID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"i","token":"t","key_type":"curve25519","tunnel_type":"wireguard","config":{"peers":[{"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}],"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::1"}}}}`))
	}))
	defer srv.Close()

	acc, err := RegisterAccount(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("RegisterAccount: %v", err)
	}
	if acc.Reserved != [3]byte{} {
		t.Fatalf("reserved = %v, want zero when client_id absent", acc.Reserved)
	}
}

func TestSaveAccountDoesNotOverwrite(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	a1 := &WarpAccount{PublicKey: "key-one", PrivateKey: "p1"}
	a2 := &WarpAccount{PublicKey: "key-two", PrivateKey: "p2"}
	p1, err := SaveAccount(a1)
	if err != nil {
		t.Fatalf("SaveAccount(a1): %v", err)
	}
	p2, err := SaveAccount(a2)
	if err != nil {
		t.Fatalf("SaveAccount(a2): %v", err)
	}
	if p1 == p2 {
		t.Fatalf("account paths collide: %s", p1)
	}
	if AccountFingerprint(a1) == AccountFingerprint(a2) {
		t.Fatalf("fingerprints collide")
	}
}
