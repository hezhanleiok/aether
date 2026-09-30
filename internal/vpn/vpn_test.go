package vpn

import (
	"strings"
	"testing"

	"github.com/aethergui/aethergui/internal/config"
)

func TestEnvForMasqueH3(t *testing.T) {
	s := config.Defaults()
	s.Mode = config.ModeMasqueH3
	env := envFor(s)
	if env["AETHER_PROTOCOL"] != "masque" {
		t.Errorf("protocol = %s, want masque", env["AETHER_PROTOCOL"])
	}
	if env["AETHER_MASQUE_HTTP2"] != "0" {
		t.Errorf("h2 = %s, want 0", env["AETHER_MASQUE_HTTP2"])
	}
	if env["AETHER_IP"] != "v4" {
		t.Errorf("ip = %s, want v4", env["AETHER_IP"])
	}
}

func TestEnvForGool(t *testing.T) {
	s := config.Defaults()
	s.Mode = config.ModeGool
	env := envFor(s)
	if env["AETHER_PROTOCOL"] != "gool" {
		t.Errorf("protocol = %s, want gool", env["AETHER_PROTOCOL"])
	}
}

func TestEnvForWireGuard(t *testing.T) {
	s := config.Defaults()
	s.Mode = config.ModeWARP
	env := envFor(s)
	if env["AETHER_PROTOCOL"] != "wg" {
		t.Errorf("protocol = %s, want wg", env["AETHER_PROTOCOL"])
	}
}

func TestEnvForSplitRulesAndLAN(t *testing.T) {
	s := config.Defaults()
	s.Mode = config.ModeSplit
	s.SplitDirect = []string{"example.com"}
	s.SplitBlock = []string{"ads.example"}
	s.LANAccess = true
	env := envFor(s)
	if !strings.Contains(env["AETHER_ROUTE_DIRECT"], "example.com") {
		t.Errorf("direct rules missing: %q", env["AETHER_ROUTE_DIRECT"])
	}
	if !strings.Contains(env["AETHER_ROUTE_DIRECT"], "private") {
		t.Errorf("LAN access must add private: %q", env["AETHER_ROUTE_DIRECT"])
	}
	if !strings.Contains(env["AETHER_ROUTE_BLOCK"], "ads.example") {
		t.Errorf("block rules missing: %q", env["AETHER_ROUTE_BLOCK"])
	}
}

func TestEnvForPinnedGateway(t *testing.T) {
	s := config.Defaults()
	// A pin comes from the node pool, which is probed as WireGuard-class
	// endpoints, so it may only be handed to the WireGuard transport.
	s.Mode = config.ModeWARP
	s.CachedGateway = "162.159.192.1:2408"
	s.AutoScan = false
	env := envFor(s)
	if env["AETHER_PEER"] != "162.159.192.1:2408" {
		t.Errorf("peer = %q, want pinned gateway", env["AETHER_PEER"])
	}
	// With AutoScan on, the pin must NOT be used.
	s.AutoScan = true
	env = envFor(s)
	if _, ok := env["AETHER_PEER"]; ok {
		t.Error("auto scan must not pin a peer")
	}
	// A MASQUE-class transport must never receive a WireGuard address: forcing
	// one makes the TLS handshake fail and the core then retries that same
	// gateway until the watchdog gives up.
	s.AutoScan = false
	s.Mode = config.ModeMasqueH3
	env = envFor(s)
	if _, ok := env["AETHER_PEER"]; ok {
		t.Error("masque must not be pinned to a wireguard endpoint")
	}
}

func TestEnvForCustomDNS(t *testing.T) {
	s := config.Defaults()
	s.DNSMode = config.DNSCustom
	s.DNSServers = []string{"1.1.1.1", "8.8.8.8"}
	env := envFor(s)
	if env["AETHER_DNS"] != "1.1.1.1,8.8.8.8" {
		t.Errorf("dns = %q", env["AETHER_DNS"])
	}
}

// The chained exit (Aether -> Psiphon) is only correct if the core gets the
// right switches and Psiphon's own notices are read back correctly.

func TestParseEgressRegions(t *testing.T) {
	line := "[2026-09-30T07:43:32.975Z INFO  aether::psiphon] [*] psiphon can leave from: AT AU BE DE JP US"
	got := parseEgressRegions(line)
	want := []string{"AT", "AU", "BE", "DE", "JP", "US"}
	if len(got) != len(want) {
		t.Fatalf("regions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("regions = %v, want %v", got, want)
		}
	}
	if parseEgressRegions("nothing here") != nil {
		t.Error("unrelated lines must yield no regions")
	}
}

func TestParseChainRegion(t *testing.T) {
	if got := parseChainRegion("[+] psiphon through the tunnel exit: 217.160.10.119, DE via FRA, 1100ms to cloudflare"); got != "DE" {
		t.Errorf("region = %q, want DE", got)
	}
	if got := parseChainRegion("no exit marker here"); got != "" {
		t.Errorf("region = %q, want empty", got)
	}
}

func TestCoreScanValue(t *testing.T) {
	// The core knows "verified"; Stealth is the UI name for it.
	if got := CoreScanValue(config.ScanStealth); got != "verified" {
		t.Errorf("stealth = %q, want verified", got)
	}
	if got := CoreScanValue(config.ScanIronclad); got != "ironclad" {
		t.Errorf("ironclad = %q", got)
	}
	if got := CoreScanValue(config.ScanBalanced); got != "balanced" {
		t.Errorf("balanced = %q", got)
	}
}

func TestEnvForChainedExit(t *testing.T) {
	s := config.Defaults()
	if env := envFor(s); env["AETHER_PSIPHON"] != "" {
		t.Fatalf("chained exit must be off by default, got %q", env["AETHER_PSIPHON"])
	}

	s.ExitChain = ChainPsiphon
	s.ExitRegion = "jp"
	env := envFor(s)
	if env["AETHER_PSIPHON"] != "chain" {
		t.Errorf("AETHER_PSIPHON = %q, want chain", env["AETHER_PSIPHON"])
	}
	if env["AETHER_PSIPHON_REGION"] != "JP" {
		t.Errorf("region = %q, want JP (upper-cased)", env["AETHER_PSIPHON_REGION"])
	}
	// Windows proxies speak HTTP, so the chain needs an HTTP listener too -
	// that is what the system proxy is pointed at.
	if env["AETHER_PSIPHON_HTTP"] == "" {
		t.Error("chained exit needs an HTTP listener for the system proxy")
	}
	if env["AETHER_PSIPHON_BIND"] == "" {
		t.Error("chained exit needs the psiphon bind address")
	}
	// The Aether hop stays in charge: psiphon dials through its SOCKS port.
	if env["AETHER_SOCKS"] == "" {
		t.Error("the aether hop must still expose its own socks listener")
	}

	// Automatic = no region at all, never an empty one.
	s.ExitRegion = ""
	if _, ok := envFor(s)["AETHER_PSIPHON_REGION"]; ok {
		t.Error("automatic exit must not send a region")
	}
}
