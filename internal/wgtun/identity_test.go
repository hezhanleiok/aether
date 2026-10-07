//go:build wgtun

package wgtun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The standard wireguard-go test identity (public fixtures, NOT a real machine's
// keys). They are base64-encoded 32-byte values and are valid for the parser.
const (
	testPriv = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	testPub  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
)

// writeIdentity writes an aether.toml-shaped identity file with the given fields.
func writeIdentity(t *testing.T, dir, priv, pub, ipv4, endpoint string) {
	t.Helper()
	var b strings.Builder
	if priv != "" {
		b.WriteString("wg_private_key = \"" + priv + "\"\n")
	}
	if pub != "" {
		b.WriteString("wg_peer_public_key = \"" + pub + "\"\n")
	}
	if ipv4 != "" {
		b.WriteString("ipv4 = \"" + ipv4 + "\"\n")
	}
	if endpoint != "" {
		b.WriteString("assigned_endpoint = \"" + endpoint + "\"\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "aether.toml"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write aether.toml: %v", err)
	}
}

// writeOverride writes a wgtun-override.conf-shaped file with the given fields.
func writeOverride(t *testing.T, dir, priv, pub, endpoint, extra string) {
	t.Helper()
	var b strings.Builder
	if priv != "" {
		b.WriteString("PrivateKey = " + priv + "\n")
	}
	if pub != "" {
		b.WriteString("PublicKey = " + pub + "\n")
	}
	if endpoint != "" {
		b.WriteString("Endpoint = " + endpoint + "\n")
	}
	b.WriteString(extra)
	if err := os.WriteFile(filepath.Join(dir, "wgtun-override.conf"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write wgtun-override.conf: %v", err)
	}
}

// TestLoadIdentityOverrideMissingKeysFallsBackToToml pins the 2026-10-06 fix: an
// override that lacks PrivateKey/PublicKey must NOT blank the identity — it must
// contribute its own fields (endpoint) and take the keys from aether.toml.
func TestLoadIdentityOverrideMissingKeysFallsBackToToml(t *testing.T) {
	dir := t.TempDir()
	writeIdentity(t, dir, testPriv, testPub, "172.16.0.2", "162.159.192.7")
	writeOverride(t, dir, "", "", "162.159.192.99:2408", "")

	cfg, err := LoadIdentity(dir, "")
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if cfg.PrivateKey != testPriv || cfg.PeerPublicKey != testPub {
		t.Fatalf("identity fell back wrongly: priv/pubic came from override, not aether.toml")
	}
	if cfg.Endpoint != "162.159.192.99:2408" {
		t.Fatalf("override endpoint not preserved: %q", cfg.Endpoint)
	}
}

// TestLoadIdentityOverrideKeepsSettings pins that a partial override preserves
// its endpoint/DNS/MTU while the identity still comes from aether.toml.
func TestLoadIdentityOverrideKeepsSettings(t *testing.T) {
	dir := t.TempDir()
	writeIdentity(t, dir, testPriv, testPub, "172.16.0.2", "162.159.192.7")
	writeOverride(t, dir, "", "", "8.6.112.7:4500", "DNS = 1.1.1.1, 8.8.8.8\nMTU = 1420\n")

	cfg, err := LoadIdentity(dir, "")
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if cfg.PrivateKey != testPriv || cfg.PeerPublicKey != testPub {
		t.Fatalf("identity not taken from aether.toml")
	}
	if cfg.Endpoint != "8.6.112.7:4500" {
		t.Fatalf("override endpoint not preserved: %q", cfg.Endpoint)
	}
	if cfg.MTU != 1420 {
		t.Fatalf("override MTU not preserved: %d", cfg.MTU)
	}
	if len(cfg.DNS) != 2 || cfg.DNS[0] != "1.1.1.1" || cfg.DNS[1] != "8.8.8.8" {
		t.Fatalf("override DNS not preserved: %v", cfg.DNS)
	}
}

// TestLoadIdentityOverrideGarbageDoesNotBlankIdentity reproduces the incident
// where an HTML file (not a WireGuard config) landed in wgtun-override.conf:
// the identity must still come from aether.toml, and the override must be a
// harmless no-op.
func TestLoadIdentityOverrideGarbageDoesNotBlankIdentity(t *testing.T) {
	dir := t.TempDir()
	writeIdentity(t, dir, testPriv, testPub, "172.16.0.2", "162.159.192.7")
	// A foreign file that is not a WireGuard config at all.
	garbage := `<div style="x=y">tutorial</div>
<h2 style="a=b">cloudflare worker</h2>
<a href="https://example.com">link</a>
`
	if err := os.WriteFile(filepath.Join(dir, "wgtun-override.conf"), []byte(garbage), 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}

	cfg, err := LoadIdentity(dir, "")
	if err != nil {
		t.Fatalf("LoadIdentity must not fail on a non-WireGuard override: %v", err)
	}
	if cfg.PrivateKey != testPriv || cfg.PeerPublicKey != testPub {
		t.Fatalf("identity was blanked by a garbage override")
	}
	if cfg.Endpoint == "" {
		t.Fatalf("endpoint must still be derived from aether.toml")
	}
}

// TestLoadIdentityNoIdentityFails pins the final diagnostic: with no identity in
// either source, LoadIdentity fails with a clear error rather than a confusing
// per-file "missing PrivateKey or PublicKey".
func TestLoadIdentityNoIdentityFails(t *testing.T) {
	dir := t.TempDir() // no aether.toml, no override
	_, err := LoadIdentity(dir, "")
	if err == nil || !strings.Contains(err.Error(), "no WireGuard identity") {
		t.Fatalf("err = %v; want a clear 'no WireGuard identity' error", err)
	}
}

// TestLoadIdentityOverrideOnly pins that a full override still works when
// aether.toml is absent (the override is a complete wgcf/warpscout export).
func TestLoadIdentityOverrideOnly(t *testing.T) {
	dir := t.TempDir()
	writeOverride(t, dir, testPriv, testPub, "162.159.192.7:2408", "Address = 172.16.0.2/32\n")

	cfg, err := LoadIdentity(dir, "")
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if cfg.PrivateKey != testPriv || cfg.PeerPublicKey != testPub {
		t.Fatalf("override identity not used")
	}
	if cfg.Endpoint != "162.159.192.7:2408" {
		t.Fatalf("override endpoint not used: %q", cfg.Endpoint)
	}
	if cfg.IPv4 != "172.16.0.2" {
		t.Fatalf("override address not used: %q", cfg.IPv4)
	}
}

// TestLoadIdentityEndpointPinWins pins that an explicit endpoint pin beats both
// aether.toml and the override.
func TestLoadIdentityEndpointPinWins(t *testing.T) {
	dir := t.TempDir()
	writeIdentity(t, dir, testPriv, testPub, "172.16.0.2", "162.159.192.7")
	writeOverride(t, dir, "", "", "8.6.112.7:4500", "")

	cfg, err := LoadIdentity(dir, "9.9.9.9:2408")
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	if cfg.Endpoint != "9.9.9.9:2408" {
		t.Fatalf("explicit pin did not win: %q", cfg.Endpoint)
	}
}
