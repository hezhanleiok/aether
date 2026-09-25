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
	ModePsiphon   Mode = "psiphon"   // Psiphon, carried by the core itself (v2.1.0+)
)

// ExitMode selects where the traffic leaves from, independently of the
// transport. It is deliberately separate: choosing Psiphon here is what starts
// psiphon, and nothing else may do it.
type ExitMode string

const (
	// ExitDefault leaves through the tunnel itself (no third-party egress).
	ExitDefault ExitMode = "default"
	// ExitPsiphon routes the exit through psiphon, which the core ships.
	ExitPsiphon ExitMode = "psiphon"
)

// PsiphonRegion is one entry of the country picker. The code is what the core
// receives (--psiphon-region <cc>); "" means "let Psiphon choose".
type PsiphonRegion struct {
	Code string `json:"code"`
	Name string `json:"name"`
	Flag string `json:"flag"`
}

// PsiphonRegions is the single source of truth for the picker — the settings
// UI, the home screen and the log all read from here, so adding a country is
// a one-line change and can never drift between screens.
//
// These are *requests*, not guarantees: Psiphon picks an egress server from
// what it currently has, so the country that comes back may differ.
var PsiphonRegions = []PsiphonRegion{
	{Code: "", Name: "自动", Flag: "🌐"},
	{Code: "US", Name: "United States", Flag: "🇺🇸"},
	{Code: "DE", Name: "Germany", Flag: "🇩🇪"},
	{Code: "JP", Name: "Japan", Flag: "🇯🇵"},
	{Code: "NL", Name: "Netherlands", Flag: "🇳🇱"},
	{Code: "SG", Name: "Singapore", Flag: "🇸🇬"},
	{Code: "GB", Name: "United Kingdom", Flag: "🇬🇧"},
	{Code: "FR", Name: "France", Flag: "🇫🇷"},
	{Code: "CA", Name: "Canada", Flag: "🇨🇦"},
	{Code: "AU", Name: "Australia", Flag: "🇦🇺"},
	{Code: "KR", Name: "South Korea", Flag: "🇰🇷"},
}

// RegionLabel returns the human name for a code ("自动" when unset).
func RegionLabel(code string) string {
	for _, r := range PsiphonRegions {
		if r.Code == code {
			return r.Name
		}
	}
	if code == "" {
		return "自动"
	}
	return code
}

// RegionFlag returns the flag emoji for a code.
func RegionFlag(code string) string {
	for _, r := range PsiphonRegions {
		if r.Code == code {
			return r.Flag
		}
	}
	return "🌐"
}

// PsiphonSettings holds the Psiphon-specific options. Psiphon ships inside the
// core (v2.1.0+), so the client keeps no server list, credentials or keys —
// it only picks a country and a fronting shape.
type PsiphonSettings struct {
	Enabled bool   `json:"enabled"`
	Region  string `json:"region"` // "" | US | DE | JP | ...
	Mode    string `json:"mode"`   // "" (auto) | cdn | direct
}

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

// Settings is the whole persisted state of the client.
type Settings struct {
	// Identity / mode
	Mode Mode `json:"mode"`
	// Protocol transport overrides (empty = follow mode)
	PreferredProfile string `json:"preferred_profile"` // noize profile

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

	// Psiphon: carried inside the core, so the client holds no server list,
	// credentials or keys — only the requested country and fronting shape.
	Psiphon PsiphonSettings `json:"psiphon"`

	// Exit is the egress choice on the home screen. It is what decides whether
	// psiphon ever runs — never the app start-up, and never "launch with
	// Windows", which starts the client only.
	Exit ExitMode `json:"exit_mode"`

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
		Mode:           ModeAuto,
		IPStack:        IPv4Only, // IPv4 default: most home networks lack working IPv6, and the
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
		Psiphon:        PsiphonSettings{Enabled: false, Region: "", Mode: "cdn"},
		// Psiphon is opt-in: a fresh install never runs it, and neither does
		// "launch with Windows" — that starts the client only.
		Exit:           ExitDefault,
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
