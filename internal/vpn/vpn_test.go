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
