// Package config holds every user-facing setting of the client and persists
// it to %LOCALAPPDATA%\AetherGUI\config.json.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Mode is one of the ten VPN modes the user can pick on the main page.
type Mode string

const (
	ModeFullVPN   Mode = "full_vpn"  // system proxy + all traffic through the tunnel
	ModeProxy     Mode = "proxy"     // global system proxy on the SOCKS listener
	ModeSplit     Mode = "split"     // user-controlled split rules
	ModeDirect    Mode = "direct"    // direct connection, tunnel off
	ModeWARP      Mode = "warp"      // WireGuard transport (classic WARP)
	ModeGool      Mode = "gool"      // WARP-in-WARP
	ModeWireGuard Mode = "wireguard" // alias of warp; kept for UI clarity
	ModeMasqueH2  Mode = "masque_h2" // MASQUE on HTTP/2 (TCP)
	ModeMasqueH3  Mode = "masque_h3" // MASQUE on HTTP/3 (QUIC)
	ModeAuto      Mode = "auto"      // auto transport selection
)

// IPMode controls IPv4/IPv6 scanning and connectivity.
type IPMode string

const (
	IPv4Only IPMode = "ipv4"
	IPv6Only IPMode = "ipv6"
	Dual     IPMode = "dual"
)

// DNSMode selects how the client resolves names.
type DNSMode string

const (
	DNSSystem DNSMode = "system"
	DNSCustom DNSMode = "custom"
	DNSDoH    DNSMode = "doh"
	DNSDoT    DNSMode = "dot" // reported by the core as unsupported; kept for forward-compat
)

// ScanMode mirrors the core's scan modes.
type ScanMode string

const (
	ScanTurbo    ScanMode = "turbo"
	ScanBalanced ScanMode = "balanced"
	ScanThorough ScanMode = "thorough"
	ScanStealth  ScanMode = "stealth"
	ScanIronclad ScanMode = "ironclad"
)

// AmneziaWG junk defaults. These are warpscout's own defaults (-jc 6,
// -jmin 10, -jmax 50) — the same numbers AmneziaWG clients ship with, and the
// ones the local A/B runs measured with.
const (
	DefaultJunkCount   = 6
	DefaultJunkMinSize = 10
	DefaultJunkMaxSize = 50
)

// DefaultAWGI1 is the fake-first-packet profile the AWG entry turns on. QUIC
// is warpscout's documented "start here" profile: of the I1 shapes it
// generates, the QUIC one is the one that most often gets through.
const DefaultAWGI1 = "quic"

// Settings is the whole persisted state of the client.
type Settings struct {
	// Identity / mode
	Mode Mode `json:"mode"`
	// Protocol transport overrides (empty = follow mode)
	PreferredProfile string `json:"preferred_profile"` // noize profile

	// NativeWireGuard runs the WARP transport through wireguard-go + a wintun
	// TUN adapter (kernel speed) instead of Aether's user-space netstack. It
	// reuses the same WARP identity the core provisioned in aether.toml. OFF
	// by default: it needs elevation, and it only takes effect in a build that
	// actually ships the backend (the "wgtun" build tag) - elsewhere the field
	// is inert.
	NativeWireGuard bool `json:"native_wireguard"`

	// StackedWireGuard upgrades the native WireGuard path to warp-in-warp: an
	// outer WARP tunnel (aether.toml identity) carries an inner WARP tunnel
	// (newest account under warp-accounts/), so the egress is a second,
	// freshly-registered identity. Implies the native backend (same wintun +
	// elevation requirements); only meaningful in WireGuard-class modes and in
	// wgtun builds. OFF by default.
	StackedWireGuard bool `json:"stacked_wireguard"`

	// AWGJunk turns on the AmneziaWG junk decoys on the native WireGuard
	// backend: JunkCount random packets of JunkMinSize..JunkMaxSize bytes are
	// sent from the same socket immediately BEFORE each handshake initiation,
	// so the flow no longer opens with a bare 148-byte WireGuard initiation.
	// This is the "AWG" protocol in the switcher — it is WireGuard with
	// obfuscation, not a different transport, so it only exists on the native
	// backend (the core's netstack cannot send them). OFF = WireGuard baseline.
	//
	// Honest scope: only the junk half of AmneziaWG is implemented. The fake
	// first packet (I1, e.g. a canned QUIC Initial) is NOT — and upstream
	// tooling (warpscout) reports that I1, not the junk sizes, is what usually
	// gets a connection past DPI. Treat this as "junk on/off", not as full AWG.
	AWGJunk bool `json:"awg_junk"`

	// Junk parameters used when AWGJunk is on. 0 = use the defaults below
	// (warpscout's own: -jc 6, -jmin 10, -jmax 50).
	JunkCount   int `json:"junk_count"`
	JunkMinSize int `json:"junk_min_size"`
	JunkMaxSize int `json:"junk_max_size"`

	// AWGI1 is the AmneziaWG fake first packet: a profile name
	// (quic/dns/stun/sip/random/none) or raw hex for an externally generated
	// packet. It is the half of AmneziaWG that upstream reports as the one
	// that actually matters (DPI judges a flow by how it opens), so the AWG
	// entry in the switcher turns it on together with the junk. "" = none.
	//
	// This is purely an I1 PACKET setting — it is NOT a transport selector.
	// "" and "none" both mean "send no fake first packet"; neither one selects
	// plain WireGuard. The transport a Psiphon/Tor exit rides is chosen by
	// ExitNativeTransport instead.
	AWGI1 string `json:"awg_i1"`
	// AWGI1SNI is the hostname the quic/sip profiles mention. Empty = a
	// well-known host nobody blocks.
	AWGI1SNI string `json:"awg_i1_sni"`

	// Networking
	IPStack       IPMode `json:"ip_stack"`
	SocksPort     int    `json:"socks_port"`
	HTTPProxyPort int    `json:"http_proxy_port"` // 0 = off

	// IPv6 switch (independent of ip_stack: the tunnel may carry v6 even when scanning is v4)
	IPv6Enabled bool `json:"ipv6_enabled"`

	// DNS
	DNSMode      DNSMode     `json:"dns_mode"`
	DNSServers   []string    `json:"dns_servers"`    // custom servers
	DoHEndpoint  string      `json:"doh_endpoint"`   // e.g. https://1.1.1.1/dns-query
	DoTEndpoint  string      `json:"dot_endpoint"`   // host:853
	DNSLeakGuard bool        `json:"dns_leak_guard"` // force tunnel DNS while connected
	DNSSplit     []SplitRule `json:"dns_split"`

	// Gateway
	AutoGateway    bool     `json:"auto_gateway"`    // auto-select fastest
	FastestGateway bool     `json:"fastest_gateway"` // prefer lowest latency
	CachedGateway  string   `json:"cached_gateway"`  // "ip:port" pinned
	AutoScan       bool     `json:"auto_scan"`       // rescan on startup/failure
	ScanMode       ScanMode `json:"scan_mode"`
	GatewayTimeout int      `json:"gateway_timeout"` // seconds
	AutoFailover   bool     `json:"auto_failover"`

	// General behaviour
	AutoStart      bool `json:"auto_start"`   // launch with Windows
	AutoConnect    bool `json:"auto_connect"` // connect after launch
	AutoReconnect  bool `json:"auto_reconnect"`
	MinimizeToTray bool `json:"minimize_to_tray"`
	CloseKeepsVPN  bool `json:"close_keeps_vpn"` // keep running after window close
	KillSwitch     bool `json:"kill_switch"`
	LANAccess      bool `json:"lan_access"` // bypass LAN addresses
	AllowLAN       bool `json:"allow_lan"`

	// Split rules (user-controlled; never auto-generated)
	SplitBlock  []string `json:"split_block"`  // never reach the network
	SplitDirect []string `json:"split_direct"` // bypass the tunnel
	VpnApps     []string `json:"vpn_apps"`     // processes that must use the tunnel
	BypassApps  []string `json:"bypass_apps"`  // processes that must bypass it

	// Core management (paths are owned by the GUI, never hard-coded)
	CorePath      string   `json:"core_path"`       // explicit core exe/dll; "" = local search
	CoreKind      string   `json:"core_kind"`       // preferred backend: "" | process | library
	CoreExtraArgs []string `json:"core_extra_args"` // extra CLI args appended on start

	// Advanced
	LogLevel       string `json:"log_level"`       // error..trace
	ConnectTimeout int    `json:"connect_timeout"` // seconds
	ReconnectDelay int    `json:"reconnect_delay"` // seconds
	MTU            int    `json:"mtu"`             // 0 = core default
	Protocol       string `json:"protocol"`        // masque|wg|gool|mim
	UseH2          bool   `json:"use_h2"`          // MASQUE over HTTP/2
	ECH            bool   `json:"ech"`             // encrypted client hello
	Keepalive      int    `json:"keepalive"`       // wg keepalive secs
	LastNode       string `json:"last_node"`       // selected node id

	// Exit chain. "" (default) = the tunnel alone is the exit; "psiphon" =
	// Aether -> Psiphon chained exit: the core carries Psiphon inside the
	// tunnel, so the final egress is a Psiphon server instead of the (often
	// mainland-CN) Aether edge. Psiphon never replaces the Aether hop.
	// Off unless the user turns it on: first run and upgrades keep plain
	// Aether, and leaving the mode stops and reaps Psiphon again.
	ExitChain  string `json:"exit_chain"`  // "" | psiphon
	ExitRegion string `json:"exit_region"` // "" = automatic; else ISO-3166-1 alpha-2, e.g. JP
	// ExitNativeTransport pins the native transport a Psiphon/Tor exit rides:
	// "" (auto) | "awg" | "wg". Auto means AmneziaWG, because plain WireGuard
	// is measurably easier to block on this network — that default is
	// deliberate and is preserved here.
	//
	// It is a SEPARATE field from AWGJunk/AWGI1 on purpose: those are the
	// AmneziaWG obfuscation PARAMETERS (junk decoys and the fake first packet),
	// not a transport choice. The transport used to be inferred from
	// AWGI1 == "none" (added in f4cb020), which conflated the I1 packet layer
	// with the transport layer and left the UI no way to express the intent —
	// selecting WireGuard in the switcher could never reach the Psiphon exit.
	ExitNativeTransport string `json:"exit_native_transport"`
	// ExitLoc is the core's exit-country policy (AETHER_EXIT_LOC): "!" prefix
	// denies (e.g. "!CN" = refuse tunnels exiting to mainland China and
	// re-select), a bare list allows only those (e.g. "US,JP"). Empty =
	// automatic, no restriction. Opt-in: on networks where every WARP egress
	// geo-resolves to CN, a deny policy makes the core re-hop forever.
	ExitLoc string `json:"exit_loc"`

	// CustomEndpoint pins a hand-picked WireGuard-class endpoint ("ip:port"),
	// overriding the core's own scan. This is the bridge to the proven-fast
	// workflow: wgcf + warpscout (or any WARP endpoint scanner) measure real
	// endpoint latency, pick the best, and paste it here. The core's own scan
	// ranks by handshake RTT, which favours the nearest (often congested)
	// edge; hand-picking the fastest endpoint is what restores throughput.
	// Applied to WireGuard (AETHER_PEER) and Gool outer hop (AETHER_WIW_OUTER_PEER).
	CustomEndpoint string `json:"custom_endpoint"`

	// UI preferences
	Language string `json:"language"` // zh-CN (default) | en-US
	Theme    string `json:"theme"`    // light (default) | dark

	// Update channels (placeholders - repos provided by the user later)
	UpdateChannel string `json:"update_channel"`  // empty | release
	CoreUpdateURL string `json:"core_update_url"` // owner-supplied; never hard-coded
	GUIUpdateURL  string `json:"gui_update_url"`  // owner-supplied; never hard-coded
}

// SplitRule routes a domain's DNS lookups to specific servers.
type SplitRule struct {
	Domain  string   `json:"domain"`
	Servers []string `json:"servers"`
}

// Defaults returns the shipped default configuration.
func Defaults() Settings {
	return Settings{
		// Auto is the safe, expected first-run choice.  Users can select a
		// transport explicitly from the main screen before connecting.
		Mode:    ModeAuto,
		IPStack: IPv4Only, // IPv4 default: most home networks lack working IPv6, and the
		// core picks IPv6 endpoints under Dual → verify timeouts.
		SocksPort:      1819,
		HTTPProxyPort:  1820,
		IPv6Enabled:    true,
		DNSMode:        DNSSystem,
		DNSServers:     []string{"1.1.1.1", "1.0.0.1"},
		DoHEndpoint:    "https://1.1.1.1/dns-query",
		DNSLeakGuard:   true,
		AutoGateway:    true,
		FastestGateway: true,
		AutoScan:       true,
		ScanMode:       ScanBalanced,
		GatewayTimeout: 30,
		AutoFailover:   true,
		AutoConnect:    false,
		AutoReconnect:  true,
		MinimizeToTray: true,
		CloseKeepsVPN:  true,
		KillSwitch:     false,
		LANAccess:      true,
		AllowLAN:       true,
		LogLevel:       "info",
		ConnectTimeout: 30,
		ReconnectDelay: 2,
		MTU:            0,
		Protocol:       "",
		Keepalive:      5,
		Language:       "zh-CN",
		Theme:          "light",
	}
}

// Dir is the per-user data directory.
func Dir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "AetherGUI")
}

// Path is the config file location.
func Path() string { return filepath.Join(Dir(), "config.json") }

var (
	mu     sync.Mutex
	cur    Settings
	loaded bool
)

// Load reads settings from disk, applying defaults for anything missing.
func Load() (Settings, error) {
	mu.Lock()
	defer mu.Unlock()
	s := Defaults()
	raw, err := os.ReadFile(Path())
	if err == nil {
		_ = json.Unmarshal(raw, &s)
	}
	loaded = true
	cur = s
	return s, nil
}

// Current returns the cached settings, loading them once if needed.
func Current() Settings {
	mu.Lock()
	defer mu.Unlock()
	if !loaded {
		mu.Unlock()
		s, _ := Load()
		mu.Lock()
		cur = s
		loaded = true
	}
	return cur
}

// Save persists settings and updates the cache.
func Save(s Settings) error {
	mu.Lock()
	defer mu.Unlock()
	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(Path(), raw, 0o644); err != nil {
		return err
	}
	cur = s
	loaded = true
	return nil
}
