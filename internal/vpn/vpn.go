// Package vpn is the connection manager: it derives the AETHER_* environment
// from user settings, runs the state machine (disconnected → connecting →
// connected / failed → reconnecting) on top of the Core Controller, and
// publishes state changes to subscribers (the UI).
package vpn

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/coremgr"
	"github.com/aethergui/aethergui/internal/logx"
)

// Status is the coarse connection state shown on the main page.
type Status string

const (
	StatusDisconnected Status = "Disconnected"
	StatusConnecting   Status = "Connecting"
	StatusConnected    Status = "Connected"
	StatusReconnecting Status = "Reconnecting"
	StatusTesting      Status = "Testing"
	StatusUnavailable  Status = "Unavailable"
	StatusFailed       Status = "Failed"

	// Chained-exit states (Aether -> Psiphon). "Connected" is only shown
	// when the whole chain carries traffic, so these exist to tell the
	// stages apart instead of claiming success early:
	//   Connecting -> AetherConnected -> StartingPsiphon -> PsiphonConnecting
	//   -> Connected  (or TrafficTestFailed)
	StatusAetherUp          Status = "AetherConnected"
	StatusStartingPsiphon   Status = "StartingPsiphon"
	StatusPsiphonConnecting Status = "PsiphonConnecting"
	StatusTrafficFailed     Status = "TrafficTestFailed"

	// Region of the chained exit, reported by the core
	// ("psiphon through the tunnel exit: <ip>, <CC> via <colo>").
	StatusConnectedChain Status = StatusConnected
)

// Exit backends. The core carries each of these itself; the GUI only picks
// the switches and the local ports (see the listener consts below).
const (
	ChainNone           = ""                // Aether only (default)
	ChainPsiphon        = "psiphon"         // Aether -> Psiphon
	ChainPsiphonOnly    = "psiphon_only"    // Psiphon alone, no tunnel
	ChainPsiphonReverse = "psiphon_reverse" // Psiphon -> Aether (dial the tunnel through Psiphon)
	ChainTor            = "tor"             // Aether -> Tor
	ChainTorOnly        = "tor_only"        // Tor alone, no tunnel
)

// Local listeners per backend. Ports must not collide with each other or
// with the Aether hop (1819 SOCKS / 1820 HTTP): the core's own tor default
// bind is 1820, which is exactly why tor gets 1823/1824 here.
const (
	PsiphonSocksPort = 1821
	PsiphonHTTPPort  = 1822
	TorSocksPort     = 1823
	TorHTTPPort      = 1824
)

// Only-mode listeners ("no tunnel underneath it").
//
// MEASURED against core 2.1.0 (2026-10-06): in only mode the core IGNORES
// AETHER_PSIPHON_BIND / AETHER_TOR_BIND and puts the backend's SOCKS on the
// core's own bind, 1819 — 1821/1823 are the CHAIN ports and are simply not
// listening here. The HTTP listener does honour the *_HTTP variable (psiphon
// measured: 1822). Tor's HTTP port is only REQUESTED by us (1824); it has
// never been observed bound because Tor never reached ready on this network,
// so nothing here may treat it as a measured fact — see ExitHTTPPort, which
// reads the port the core actually announces.
const (
	OnlySocksPort    = 1819
	OnlyTorSocksPort = 1819
	// OnlyPsiphonHTTPPort / OnlyTorHTTPPort are the values we ask for.
	OnlyPsiphonHTTPPort = PsiphonHTTPPort
	OnlyTorHTTPPort     = TorHTTPPort
)

// State is the full observable state of the manager.
type State struct {
	Status      Status      `json:"status"`
	Mode        config.Mode `json:"mode"`
	ExitIP      string      `json:"exit_ip"`
	ExitCountry string      `json:"exit_country"`
	ExitFlag    string      `json:"exit_flag"`
	LatencyMs   int64       `json:"latency_ms"`
	Gateway     string      `json:"gateway"`
	Transport   string      `json:"transport"`
	Error       string      `json:"error"`
	Phase       string      `json:"phase"`
	StartedAt   time.Time   `json:"started_at"`
	CoreRunning bool        `json:"core_running"`

	// Chain is the active exit chain ("" or "psiphon").
	Chain string `json:"chain"`
	// ExitRegions is what the chained exit currently offers, taken from the
	// core's "psiphon can leave from:" notice. Never hard-coded: the list is
	// whatever Psiphon reports, and it drives the region picker in the UI.
	ExitRegions []string `json:"exit_regions"`
	// ChainRegion is the country the chained exit actually left from.
	ChainRegion string `json:"chain_region"`
}

// Manager drives one active connection through the Core Controller.
type Manager struct {
	mu     sync.RWMutex
	st     State
	core   *coremgr.Manager
	subMu  sync.Mutex
	subs   []func(State)
	stopCh chan struct{}
	// chain is the exit chain of the running session ("" or "psiphon"); it
	// decides whether "the tunnel is up" already means "connected" or only
	// "the Aether hop is up".
	chain string
	// dropHook fires when the core exits while a session was up. Nothing
	// watched that before, so a crashed core simply went quiet.
	dropHook func()
	// exitHTTPPort is the HTTP CONNECT port the exit backend ANNOUNCED ("" if
	// it announced none). Read through ExitHTTPPort; see parseHTTPProxyPort.
	exitHTTPPort int
	// backendReady records that the core (or its exit backend) reported
	// itself up during this session. Read through BackendReady.
	backendReady bool
	// connectGate, when set, gates promotion to Connected: the core's own
	// "ready" events then only set backendReady, and the gate's owner decides
	// when Connected is true. See SetConnectGate.
	connectGate func() bool
}

// SetConnectGate installs (nil clears) the gate that the core's ready events
// must pass before they may set Connected.
//
// The native-exit orchestration needs this: for the Psiphon/Tor exits,
// "backend ready" is only ONE precondition — the HTTP proxy must be up and
// the system proxy set before the session is connected — and a late
// psiphon_ready belonging to an already-cancelled session must not be able to
// flip the UI back to Connected while the tunnel is already gone.
func (m *Manager) SetConnectGate(fn func() bool) {
	m.mu.Lock()
	m.connectGate = fn
	m.mu.Unlock()
}

// BackendReady reports whether the exit backend reported itself ready during
// this session.
func (m *Manager) BackendReady() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.backendReady
}

// markBackendReady records a "the core / its backend is up" event. With a
// connect gate installed that is ALL it does — the gate's owner promotes to
// Connected. Without one (the classic core-driven path) the event itself is
// the signal, exactly as before.
func (m *Manager) markBackendReady(setStatus func(*State)) {
	m.mu.Lock()
	m.backendReady = true
	gate := m.connectGate
	m.mu.Unlock()
	if gate != nil && !gate() {
		logx.Infof("[vpn] backend ready; holding Connected until the session orchestration finishes")
		return
	}
	m.set(StatusConnected, setStatus)
}

// ExitHTTPPort returns the HTTP CONNECT port the exit backend actually
// announced, or 0 when it announced none.
//
// Why this exists: the GUI must never point the Windows system proxy at a
// port it merely guessed. Psiphon-only was measured to answer on 1822, but
// Tor-only has never reached ready here, so its HTTP port is unknown - and a
// system proxy pointed at a dead port is the classic "green VPN, dead
// browser" failure. The core prints the listener it opened ("... http proxy
// on 127.0.0.1:1822"); we read that instead of assuming.
func (m *Manager) ExitHTTPPort() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.exitHTTPPort
}

// parseHTTPProxyPort reads the port out of the core's listener notice, e.g.
// "[+] psiphon http proxy on 127.0.0.1:1822". Returns 0 when the line is not
// such a notice.
func parseHTTPProxyPort(line string) int {
	match := reHTTPProxyOn.FindStringSubmatch(line)
	if len(match) != 2 {
		return 0
	}
	n, err := strconv.Atoi(match[1])
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return n
}

var reHTTPProxyOn = regexp.MustCompile(`http proxy on 127\.0\.0\.1:(\d+)`)

// SetDropHook registers the callback run when the core drops a live session.
func (m *Manager) SetDropHook(fn func()) {
	m.mu.Lock()
	m.dropHook = fn
	m.mu.Unlock()
}

// Chain returns the exit chain of the running session.
func (m *Manager) Chain() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.chain
}

// New creates a manager around a Core Controller.
func New(core *coremgr.Manager) *Manager {
	return &Manager{core: core, st: State{Status: StatusDisconnected}}
}

// Subscribe registers a state listener; it fires immediately with the
// current state, then on every change.
func (m *Manager) Subscribe(fn func(State)) {
	m.subMu.Lock()
	m.subs = append(m.subs, fn)
	m.subMu.Unlock()
	m.mu.RLock()
	st := m.st
	m.mu.RUnlock()
	fn(st)
}

func (m *Manager) publish() {
	m.mu.RLock()
	st := m.st
	m.mu.RUnlock()
	m.subMu.Lock()
	subs := append([]func(State){}, m.subs...)
	m.subMu.Unlock()
	for _, fn := range subs {
		fn(st)
	}
}

// Publish re-emits the current state to every subscriber. The UI uses it for
// the one-second tick that refreshes derived values (connected duration).
func (m *Manager) Publish() { m.publish() }

func (m *Manager) set(status Status, mutate func(*State)) {
	m.mu.Lock()
	m.st.Status = status
	m.st.CoreRunning = m.core.Running()
	if mutate != nil {
		mutate(&m.st)
	}
	m.mu.Unlock()
	m.publish()
}

// State returns a snapshot.
func (m *Manager) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := m.st
	st.CoreRunning = m.core.Running()
	return st
}

// peerMatchesTransport reports whether a gateway pinned from the node pool may
// be handed to the core as AETHER_PEER for this transport.
//
// The pool is probed over TCP/443 against Cloudflare edges, so a pin is valid
// for the WireGuard-class transports only. On MASQUE the same address is not a
// MASQUE gateway and the handshake fails, which used to hang every later
// connect attempt.
func peerMatchesTransport(proto string) bool {
	// Only the plain WireGuard transport can take a single pinned endpoint.
	// gool needs an outer+inner pair (it scans for both and ignored a lone
	// AETHER_PEER anyway), MASQUE/MIM need their own gateways, and "" means
	// the core chooses the transport itself.
	return proto == "wg"
}

func transportName(proto string) string {
	if proto == "" {
		return "auto"
	}
	return proto
}

// envFor derives every AETHER_* variable the core needs from settings.
func envFor(s config.Settings) map[string]string {
	env := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			env[k] = v
		}
	}
	switch s.Mode {
	case config.ModeAuto:
		// let the core pick its own transport
	case config.ModeMasqueH3:
		// masque_h3 mode covers plain MASQUE/H3 and MASQUE-in-MASQUE;
		// protocol tells them apart. mim needs AETHER_PROTOCOL=mim.
		if s.Protocol == "mim" {
			set("AETHER_PROTOCOL", "mim")
			// Fragment the TLS ClientHello on the H2 transport to survive
			// DPI interference; harmless when the QUIC path is used.
			// Empirically verified: 1-3 byte fragments pass where the
			// default 16-32 still gets RST.
			set("AETHER_MASQUE_H2_FRAGMENT", "1")
			set("AETHER_MASQUE_H2_FRAGMENT_SIZE", "1-3")
			set("AETHER_MASQUE_H2_FRAGMENT_DELAY", "5-20")
			if s.UseH2 {
				set("AETHER_MASQUE_HTTP2", "1")
			} else {
				set("AETHER_MASQUE_HTTP2", "0")
			}
			logx.Infof("[vpn] MIM: fragment=1 size=1-3 delay=5-20 h2=%v", s.UseH2)
		} else {
			set("AETHER_PROTOCOL", "masque")
			set("AETHER_MASQUE_HTTP2", "0")
		}
	case config.ModeMasqueH2:
		set("AETHER_PROTOCOL", "masque")
		set("AETHER_MASQUE_HTTP2", "1")
		// H2 over TCP 443 is the primary target of TLS-level DPI;
		// fragment the ClientHello so the handshake completes.
		// Empirically verified: 1-3 byte fragments pass where the
		// default 16-32 still gets RST.
		set("AETHER_MASQUE_H2_FRAGMENT", "1")
		set("AETHER_MASQUE_H2_FRAGMENT_SIZE", "1-3")
		set("AETHER_MASQUE_H2_FRAGMENT_DELAY", "5-20")
		logx.Infof("[vpn] MasqueH2: fragment=1 size=1-3 delay=5-20 h2=1")
	case config.ModeWARP, config.ModeWireGuard:
		set("AETHER_PROTOCOL", "wg")
	case config.ModeGool:
		set("AETHER_PROTOCOL", "gool")
	default:
		switch s.Protocol {
		case "wg":
			set("AETHER_PROTOCOL", "wg")
		case "gool":
			set("AETHER_PROTOCOL", "gool")
		case "mim":
			set("AETHER_PROTOCOL", "mim")
			if s.UseH2 {
				set("AETHER_MASQUE_HTTP2", "1")
			}
		default:
			set("AETHER_PROTOCOL", "masque")
			if s.UseH2 {
				set("AETHER_MASQUE_HTTP2", "1")
			}
		}
	}
	switch s.IPStack {
	case config.IPv4Only:
		set("AETHER_IP", "v4")
	case config.IPv6Only:
		set("AETHER_IP", "v6")
	default:
		set("AETHER_IP", "both")
	}
	// Exit backend. The core runs each of these itself (it spawns and reaps
	// the psiphon/tor side processes); the GUI only picks the switches and
	// the two local listener addresses per backend.
	switch s.ExitChain {
	case ChainPsiphon, ChainPsiphonOnly, ChainPsiphonReverse:
		mode := map[string]string{ChainPsiphon: "chain", ChainPsiphonOnly: "only", ChainPsiphonReverse: "reverse"}[s.ExitChain]
		set("AETHER_PSIPHON", mode)
		// Only mode: the core ignores BIND and puts SOCKS on 1819 (measured),
		// so asking for the chain port 1821 here would leave a variable that
		// disagrees with reality. Keep the requested value honest instead.
		bind := PsiphonSocksPort
		if mode == "only" {
			bind = OnlySocksPort
		}
		set("AETHER_PSIPHON_BIND", fmt.Sprintf("127.0.0.1:%d", bind))
		// Own the datastore path so it can be cleaned after a killed session.
		set("AETHER_PSIPHON_DIR", PsiphonDir())
		// Windows' system proxy speaks HTTP, not SOCKS, so ask for an HTTP
		// CONNECT listener too and point the system at it. Reverse mode is
		// the exception: there Psiphon is the *entry*, the exit is still the
		// tunnel's own 1819/1820, and an extra listener would be dead weight.
		if mode != "reverse" {
			set("AETHER_PSIPHON_HTTP", fmt.Sprintf("127.0.0.1:%d", PsiphonHTTPPort))
		}
		if s.ExitRegion != "" {
			set("AETHER_PSIPHON_REGION", strings.ToUpper(s.ExitRegion))
		}
		httpPort := PsiphonHTTPPort
		if mode == "only" {
			httpPort = OnlyPsiphonHTTPPort
		}
		logx.Infof("[vpn] exit backend: psiphon mode=%s region=%q socks=%d http=%d (only-mode SOCKS is the core's own bind, 1819)",
			mode, s.ExitRegion, bind, httpPort)
	case ChainTor, ChainTorOnly:
		mode := map[string]string{ChainTor: "chain", ChainTorOnly: "only"}[s.ExitChain]
		set("AETHER_TOR", mode)
		// The core's tor default bind is 127.0.0.1:1820 - the same port the
		// GUI uses for the Aether HTTP proxy. Overriding it is not optional.
		// Only mode: SOCKS lands on 1819 (measured), not the chain's 1823.
		bind := TorSocksPort
		if mode == "only" {
			bind = OnlyTorSocksPort
		}
		set("AETHER_TOR_BIND", fmt.Sprintf("127.0.0.1:%d", bind))
		set("AETHER_TOR_HTTP", fmt.Sprintf("127.0.0.1:%d", TorHTTPPort))
		logx.Infof("[vpn] exit backend: tor mode=%s socks=%d http=%d (only-mode SOCKS is the core's own bind, 1819; the HTTP port is only requested, the core's announcement decides)",
			mode, bind, TorHTTPPort)
	}
	// Exit-country policy (the core's --exit-loc): "!CN" refuses a tunnel
	// whose egress geo-resolves to CN and re-selects; "US,JP" allows only
	// those countries. This is the core-native way to get "自动选最快的非 CN
	// 网关": the scan still picks the fastest handshake, and anything whose
	// exit lands in a denied country is re-checked (default every 60s) and
	// re-scanned until the exit is accepted.
	if loc := sanitizeExitLoc(s.ExitLoc); loc != "" {
		set("AETHER_EXIT_LOC", loc)
	}
	set("AETHER_SOCKS", fmt.Sprintf("127.0.0.1:%d", s.SocksPort))
	if s.HTTPProxyPort > 0 {
		set("AETHER_HTTP_PROXY", fmt.Sprintf("127.0.0.1:%d", s.HTTPProxyPort))
	}
	// H2 and MIM default to ironclad. It costs more per candidate (a real HTTP
	// request through a real tunnel instead of trusting the CONNECT-IP reply)
	// but that is exactly what makes it faster end to end here: balanced
	// happily picks the first endpoint that answers a probe and ends up with
	// rtt ≈5.9s (and, on IPv4-only, sometimes none at all), while ironclad
	// measured ≈970ms and connected in 77s instead of 256s.
	// Leaving AETHER_SCAN empty hands the choice back to the core, which
	// defaults to balanced — and balanced keeps sweeping candidates until its
	// whole budget runs out before committing. Measured here that is a 120s
	// wait for the very gateway turbo picks in 3s. An explicit choice is
	// always respected; only the default had no reason to be that slow.
	// Note: turbo was tried here to cut the wait (4s vs 120s, verified working),
	// but it gives up too early whenever endpoints sit in cooldown — measured
	// here it then fails every retry, while the default keeps probing. Leave the
	// core its own choice unless the user picked one; users who want the fast
	// sweep can still select turbo in the scan-mode setting.
	// The UI's five modes are passed straight through, except Stealth: the
	// core calls that mode "verified" (its own help lists
	// turbo|balanced|thorough|verified|ironclad). An empty value is not sent
	// at all, which leaves the core on its default, balanced.
	set("AETHER_SCAN", CoreScanValue(s.ScanMode))
	if s.PreferredProfile != "" {
		set("AETHER_NOIZE", s.PreferredProfile)
	}
	if s.AutoReconnect {
		set("AETHER_QUICK_RECONNECT", "1")
	}
	// A pinned gateway comes from the node pool, which is probed over TCP/443
	// against plain Cloudflare edges. Those addresses are WireGuard-class
	// endpoints, so the pin is safe for wg/gool — but they are NOT MASQUE
	// gateways. Forcing one onto MASQUE makes the TLS handshake fail with
	// CERTIFICATE_VERIFY_FAILED, after which the core keeps retrying that same
	// gateway until the watchdog gives up (seen as a hang on every later
	// connect). So MASQUE-class transports always fall back to the core's own
	// scan instead.
	if s.CachedGateway != "" && !s.AutoScan {
		if peerMatchesTransport(env["AETHER_PROTOCOL"]) {
			set("AETHER_PEER", s.CachedGateway)
		} else {
			logx.Infof("[vpn] pinned gateway %s is not a %s endpoint; scanning instead",
				s.CachedGateway, transportName(env["AETHER_PROTOCOL"]))
		}
	}
	// A hand-picked endpoint overrides the scan entirely and skips the
	// nearest-edge bias. This is how the fast workflow plugs in: measure
	// endpoints with wgcf/warpscout, paste the winner, and the same WireGuard
	// protocol runs over the good path instead of the nearest congested one.
	if ep := validateEndpoint(s.CustomEndpoint); ep != "" {
		switch env["AETHER_PROTOCOL"] {
		case "wg":
			set("AETHER_PEER", ep)
		case "gool":
			set("AETHER_WIW_OUTER_PEER", ep)
		default:
			logx.Infof("[vpn] custom endpoint %s ignored: not a WireGuard-class transport", ep)
		}
	}
	if len(s.DNSServers) > 0 && s.DNSMode != config.DNSSystem {
		set("AETHER_DNS", strings.Join(s.DNSServers, ","))
	}
	if len(s.SplitBlock) > 0 {
		set("AETHER_ROUTE_BLOCK", strings.Join(s.SplitBlock, ","))
	}
	if len(s.SplitDirect) > 0 {
		set("AETHER_ROUTE_DIRECT", strings.Join(s.SplitDirect, ","))
	}
	if s.LANAccess || s.AllowLAN {
		cur := env["AETHER_ROUTE_DIRECT"]
		if !strings.Contains(cur, "private") {
			if cur == "" {
				env["AETHER_ROUTE_DIRECT"] = "private"
			} else {
				env["AETHER_ROUTE_DIRECT"] = cur + ",private"
			}
		}
	}
	if s.ECH {
		set("AETHER_ECH", "auto")
	}
	// MASQUE H2 and MIM must survive the prober's whole 120s scan window, and
	// MIM then validates a second hop on top of it. Measured end-to-end:
	// H2 ≈126s, MIM ≈174s. The generic connect timeout (30s) makes the core
	// abandon these transports mid-scan, which shows up as "no usable MASQUE
	// gateway found" even though a gateway was reachable.
	if IsSlowMasque(s) {
		budget := s.ConnectTimeout
		if budget < 150 {
			budget = 150
		}
		set("AETHER_MASQUE_STARTUP_SECS", fmt.Sprint(budget))
	} else if s.ConnectTimeout > 0 {
		set("AETHER_MASQUE_STARTUP_SECS", fmt.Sprint(s.ConnectTimeout))
	}
	if s.ReconnectDelay >= 0 {
		set("AETHER_MASQUE_RECONNECT_SECS", fmt.Sprint(s.ReconnectDelay))
	}
	if s.Keepalive > 0 {
		set("AETHER_WG_KEEPALIVE", fmt.Sprint(s.Keepalive))
	}
	if s.MTU > 0 {
		set("AETHER_MASQUE_MTU", fmt.Sprint(s.MTU))
	}
	set("AETHER_LOG_LEVEL", s.LogLevel)
	// Extra args pass through the environment only when the core supports
	// them; the CLI appends them itself in process mode.
	for _, a := range s.CoreExtraArgs {
		if k, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(k, "AETHER_") {
			env[k] = v
		}
	}
	return env
}

// EnvFor exposes the derived environment (tests, smoke runs).
func EnvFor(s config.Settings) map[string]string { return envFor(s) }

// IsSlowMasque reports whether the selected transport needs the full MASQUE
// gateway scan plus a fragmented TLS handshake, i.e. whether the slow-path
// budgets apply. Both MASQUE H2 (TCP/443) and MASQUE-in-MASQUE run the prober,
// and MIM validates an inner hop on top of the outer one.
func IsSlowMasque(s config.Settings) bool {
	return s.Mode == config.ModeMasqueH2 || s.Protocol == "mim"
}

// IsMasqueClass reports whether the active transport is MASQUE-based, whether
// it rides HTTP/3 or HTTP/2.
func IsMasqueClass(s config.Settings) bool {
	switch s.Mode {
	case config.ModeMasqueH2, config.ModeMasqueH3:
		return true
	}
	return s.Protocol == "masque" || s.Protocol == "mim"
}

// Connect launches the core through the Core Controller.
func (m *Manager) Connect(s config.Settings) error {
	if s.Mode == config.ModeDirect {
		m.Disconnect()
		return nil
	}
	// Core must be detected & ready.
	if h := m.core.Health(); h != coremgr.HealthReady && h != coremgr.HealthRunning {
		if _, err := m.core.Detect(s.CorePath); err != nil {
			m.set(StatusFailed, func(st *State) { st.Error = err.Error() })
			return err
		}
	}
	if m.core.Running() {
		if err := m.core.Stop(); err != nil {
			logx.Warnf("[vpn] core restart: %v", err)
		}
	}
	// Fail before changing the system proxy when another client/process owns
	// the configured SOCKS port.  Without this check the core exits after its
	// bind error while the UI can still appear to be connecting.
	if err := ensureLocalPortAvailable(s.SocksPort); err != nil {
		m.set(StatusFailed, func(st *State) { st.Error = err.Error() })
		return err
	}
	// The backend's own listeners must be free as well: something else holding
	// them makes the core's psiphon fail to bind, which surfaces as a generic
	// "stopped before it was ready" instead of pointing at the real conflict.
	if IsPsiphonChain(s.ExitChain) {
		ports := []int{PsiphonSocksPort}
		if s.ExitChain != ChainPsiphonReverse {
			ports = append(ports, PsiphonHTTPPort)
		}
		for _, p := range ports {
			if err := ensureLocalPortAvailable(p); err != nil {
				m.set(StatusFailed, func(st *State) { st.Error = err.Error() })
				return err
			}
		}
	}

	if IsPsiphonChain(s.ExitChain) {
		// A leftover psiphon-tunnel-core keeps the datastore locked (the
		// openDataStore timeout that failed every post-switch connect) and its
		// listeners bound; clear both before the core spawns a new one.
		killOrphanPsiphon()
		resetPsiphonState()
	}
	env := envFor(s)
	sess, err := m.core.Start(env, config.Dir())
	if err != nil {
		m.set(StatusFailed, func(st *State) { st.Error = err.Error() })
		return err
	}
	m.mu.Lock()
	m.chain = s.ExitChain
	m.backendReady = false
	m.stopCh = make(chan struct{})
	m.st.Status = StatusConnecting
	m.st.Mode = s.Mode
	m.st.Error = ""
	m.st.Gateway = s.CachedGateway
	m.st.StartedAt = time.Now()
	m.st.Chain = s.ExitChain
	m.st.ChainRegion = ""
	// Regions are re-published by Psiphon on every chained connect; dropping
	// the stale list keeps the picker from offering exits this session has
	// not confirmed.
	m.st.ExitRegions = nil
	m.mu.Unlock()
	m.publish()
	go m.pump(sess)
	return nil
}

func ensureLocalPortAvailable(port int) error {
	if port <= 0 {
		return fmt.Errorf("invalid SOCKS port: %d", port)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("SOCKS port %s is already in use; close the other Xiaohe/aether process or choose another SOCKS port", addr)
	}
	return ln.Close()
}

// pump consumes core events into the state machine.
func (m *Manager) pump(sess coremgr.Session) {
	for ev := range sess.Events() {
		// Whatever kind it is, a listener notice is worth capturing: it is the
		// only place the core states which HTTP port the exit backend really
		// opened (see ExitHTTPPort).
		if p := parseHTTPProxyPort(ev.Line); p > 0 {
			m.mu.Lock()
			m.exitHTTPPort = p
			m.mu.Unlock()
			logx.Infof("[vpn] exit http proxy on 127.0.0.1:%d (announced by the core)", p)
		}
		switch ev.Kind {
		case "log":
			logx.Debugf("[core] %s", ev.Line)
		case "progress":
			// H2/MIM transport progress must stay visible: the MASQUE scan
			// plus fragmented TLS handshake can take 1-2 minutes, and without
			// these lines the UI log looks frozen.
			logx.Infof("[core] %s", ev.Line)
		case "connected":
			// With a chained exit the Aether hop being up is only half the
			// path: nothing leaves through Psiphon until it reports ready, so
			// claiming "Connected" here is exactly the bug that used to show
			// a working tunnel with dead browsers.
			if m.Chain() == ChainPsiphon {
				m.set(StatusAetherUp, func(st *State) { st.Error = "" })
			} else {
				m.markBackendReady(func(st *State) { st.Error = "" })
			}
		case "psiphon_waiting":
			// Psiphon is up and waiting for the Aether hop to expose SOCKS.
			if m.Chain() == ChainPsiphon {
				m.set(StatusPsiphonConnecting, nil)
			}
		case "psiphon_starting":
			m.set(StatusStartingPsiphon, nil)
		case "psiphon_ready":
			// Backend ready is a PRECONDITION, not the verdict: with a connect
			// gate installed (native exit), the orchestration decides when the
			// session is Connected. A late psiphon_ready from a cancelled
			// session used to push the UI straight back to Connected here —
			// with the native tunnel already gone.
			m.markBackendReady(func(st *State) { st.Error = "" })
		case "psiphon_regions":
			m.SetExitRegions(parseEgressRegions(ev.Line))
		case "psiphon_exit":
			if cc := parseChainRegion(ev.Line); cc != "" {
				m.mu.Lock()
				m.st.ChainRegion = cc
				m.mu.Unlock()
				m.publish()
			}
		case "psiphon_failed":
			m.set(StatusFailed, func(st *State) { st.Error = ev.Line })
		case "scanning":
			if m.State().Status == StatusConnecting {
				m.set(StatusConnecting, nil)
			}
		case "reconnect":
			m.set(StatusReconnecting, nil)
		case "failed":
			m.set(StatusFailed, func(st *State) { st.Error = ev.Line })
		case "stopped":
			// Keep a startup error visible.  Previously a fatal bind failure was
			// immediately overwritten by "disconnected", which made the UI look
			// connected even though no local proxy had started.
			prev := m.State().Status
			if prev != StatusFailed {
				m.mu.Lock()
				m.st.Status = StatusDisconnected
				m.mu.Unlock()
				m.publish()
			}
			// A session that was already carrying traffic and then lost its
			// core is a drop, not a clean stop: hand it back so the caller can
			// reconnect instead of sitting in "Disconnected" forever.
			if prev == StatusConnected || prev == StatusAetherUp ||
				prev == StatusStartingPsiphon || prev == StatusPsiphonConnecting ||
				prev == StatusTesting {
				m.mu.RLock()
				hook := m.dropHook
				m.mu.RUnlock()
				if hook != nil {
					go hook()
				}
			}
			return
		}
	}
}

// parseEgressRegions reads the core's "[*] psiphon can leave from: AT AU ..."
// notice, which carries Psiphon's own AvailableEgressRegions. The list is
// never hard-coded here: the picker shows whatever Psiphon says it can do.
func parseEgressRegions(line string) []string {
	const marker = "can leave from:"
	i := strings.Index(line, marker)
	if i < 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, tok := range strings.Fields(line[i+len(marker):]) {
		cc := strings.ToUpper(strings.Trim(tok, ",.;"))
		if len(cc) != 2 {
			continue
		}
		if cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			continue
		}
		if !seen[cc] {
			seen[cc] = true
			out = append(out, cc)
		}
	}
	return out
}

// parseChainRegion reads
// "[+] psiphon through the tunnel exit: 217.160.10.119, DE via FRA".
func parseChainRegion(line string) string {
	const marker = "exit:"
	i := strings.Index(line, marker)
	if i < 0 {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(line[i+len(marker):]), ",")
	if len(parts) < 2 {
		return ""
	}
	fields := strings.Fields(parts[1])
	if len(fields) == 0 {
		return ""
	}
	cc := strings.ToUpper(fields[0])
	if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
		return ""
	}
	return cc
}

// SetExitRegions publishes the exits the chained hop currently offers.
func (m *Manager) SetExitRegions(regions []string) {
	if len(regions) == 0 {
		return
	}
	m.mu.Lock()
	m.st.ExitRegions = regions
	m.mu.Unlock()
	m.publish()
}

// SetTrafficFailed marks a tunnel that is up but carries no traffic. A
// process that is alive is not a working connection - this is the state for
// "connected, but nothing actually goes through".
func (m *Manager) SetTrafficFailed(reason string) {
	m.set(StatusTrafficFailed, func(st *State) { st.Error = reason })
}

// SetNativeState drives the state machine for the native WireGuard backend,
// which owns its own tunnel and never touches the core. It is the manager-side
// hook the app layer uses on the nativeWG path (Connect/Disconnect there run
// wireguard-go + wintun instead of the core's SOCKS/netstack). All the usual
// subscribers still receive the transition, so the UI is identical.
func (m *Manager) SetNativeState(status Status, mode config.Mode, errMsg string) {
	m.set(status, func(st *State) {
		st.Mode = mode
		st.Error = errMsg
		// Clear any in-flight phase label when leaving the connecting state so
		// a stale "inner-handshake" can't linger after success/failure/cancel.
		// Phase is only read by the UI while Connecting/Reconnecting, so the
		// stacked "up" label that briefly precedes Connected is harmlessly
		// dropped here.
		if st.Status != StatusConnecting && st.Status != StatusReconnecting {
			st.Phase = ""
		}
	})
}

// SetPhase reports a human-readable progress label for an in-flight connect
// (e.g. "probe 37/112", "inner-handshake", "up"). It feeds the UI's connecting
// state over SSE without touching Status, so the connect/disconnect state
// machine is unaffected. Empty clears the label.
func (m *Manager) SetPhase(phase string) {
	m.mu.Lock()
	m.st.Phase = phase
	m.mu.Unlock()
	m.publish()
}

// NativeExitOnly reports which exit backend must run ON TOP of the native
// WireGuard tunnel, or "" when the tunnel is itself the exit.
//
// The native backend has no Psiphon/Tor of its own - the core runs those - so
// when the user picks a Psiphon or Tor exit while the native tunnel is the
// transport, the core is started in its documented "no tunnel underneath it"
// (only) mode: the backend dials out through the system route, which the
// native tunnel just took over. Psiphon-reverse is excluded on purpose: there
// the backend is the ENTRY and the exit is still the core's own tunnel, which
// the native backend does not have.
func NativeExitOnly(s config.Settings) string {
	switch s.ExitChain {
	case ChainPsiphon, ChainPsiphonOnly:
		return "psiphon"
	case ChainTor, ChainTorOnly:
		return "tor"
	}
	return ""
}

// OnlyChainFor maps an exit choice onto the only-mode value the core expects
// ("AETHER_PSIPHON=only" / "AETHER_TOR=only").
func OnlyChainFor(s config.Settings) string {
	switch NativeExitOnly(s) {
	case "psiphon":
		return ChainPsiphonOnly
	case "tor":
		return ChainTorOnly
	}
	return ChainNone
}

// OnlyHTTPPort is the HTTP CONNECT port the GUI asks the core to open in only
// mode. It is a REQUEST, not a measured fact: the port the core actually
// announces is published through ExitHTTPPort and is what the system proxy
// must use.
func OnlyHTTPPort(s config.Settings) int {
	switch NativeExitOnly(s) {
	case "psiphon":
		return OnlyPsiphonHTTPPort
	case "tor":
		return OnlyTorHTTPPort
	}
	return 0
}

// ExitsThroughChain reports whether the final egress is the backend's own
// listener (as opposed to the Aether hop's 1819/1820). Reverse modes keep the
// tunnel as the exit - the backend is only the entry - so health probes and
// the exit-IP lookup stay on the Aether ports there.
func ExitsThroughChain(s config.Settings) bool {
	switch s.ExitChain {
	case ChainPsiphon, ChainPsiphonOnly, ChainTor, ChainTorOnly:
		return true
	}
	return false
}

// IsPsiphonChain reports whether a Psiphon backend is in play (any mode).
func IsPsiphonChain(chain string) bool {
	switch chain {
	case ChainPsiphon, ChainPsiphonOnly, ChainPsiphonReverse:
		return true
	}
	return false
}

// ChainSocksPort is the SOCKS listener of the backend that carries the final
// egress, or 0 when the exit is the Aether hop itself.
func ChainSocksPort(s config.Settings) int {
	switch s.ExitChain {
	case ChainPsiphon, ChainPsiphonOnly:
		return PsiphonSocksPort
	case ChainTor, ChainTorOnly:
		return TorSocksPort
	}
	return 0
}

// PsiphonDir is where Psiphon keeps its datastore. The client owns the path
// (instead of leaving the core's "<config>-psiphon" default next to the
// identity file) so it can also clean it up - see resetStalePsiphonState.
func PsiphonDir() string { return filepath.Join(config.Dir(), "psiphon") }

// psiphonOverlayName is the temp overlay written by WritePsiphonOverlay. It
// lives in PsiphonDir() next to the datastore (which AETHER_PSIPHON_DIR also
// points at), so both the datastore and the overlay are cleaned together.
const psiphonOverlayName = "psiphon-overlay.json"

// tcpOnlyPsiphonProtocols is the LimitTunnelProtocols list the overlay pins.
// It keeps every protocol that honours UpstreamProxyURL and drops the QUIC ones:
// UpstreamProxyURL is NOT applied to Psiphon's UDPDial (psiphon/net.go:137), and
// the QUIC transports (QUIC-OSSH and the two FRONTED-MEEK-QUIC variants) dial
// over UDP, so they would bypass the tunnel and must not be offered.
//
// SHADOWSOCKS-OSSH stays: despite the name it is a TCP transport —
// psiphon/common/protocol/protocol.go's TunnelProtocolUsesTCP returns true for
// it and TunnelProtocolSupportsUpstreamProxy includes it, so UpstreamProxyURL
// applies. The list below is exactly the bundled core 2.1.0 protocol set (14)
// minus the 3 QUIC entries.
var tcpOnlyPsiphonProtocols = []string{
	"SSH",
	"OSSH",
	"TLS-OSSH",
	"SHADOWSOCKS-OSSH",
	"UNFRONTED-MEEK-OSSH",
	"UNFRONTED-MEEK-HTTPS-OSSH",
	"UNFRONTED-MEEK-SESSION-TICKET-OSSH",
	"FRONTED-MEEK-OSSH",
	"FRONTED-MEEK-CDN-OSSH",
	"FRONTED-MEEK-HTTP-OSSH",
	"FRONTED-MEEK-CDN-HTTP-OSSH",
}

// WritePsiphonOverlay writes a minimal psiphon config overlay that pins
// Psiphon's upstream to the tunnel-bound SOCKS server (socks5://127.0.0.1:<port>)
// and converges LimitTunnelProtocols to TCP-only. The core lays this overlay
// over its built-in config (--psiphon-config / AETHER_PSIPHON_CONFIG), so every
// TCP tunnel dials through our SOCKS while every built-in field survives. It
// returns the absolute path to hand the core as AETHER_PSIPHON_CONFIG.
func WritePsiphonOverlay(socksPort int) (string, error) {
	if socksPort <= 0 || socksPort > 65535 {
		return "", fmt.Errorf("invalid tunnel SOCKS port: %d", socksPort)
	}
	overlay := struct {
		UpstreamProxyURL     string   `json:"UpstreamProxyURL"`
		LimitTunnelProtocols []string `json:"LimitTunnelProtocols"`
	}{
		UpstreamProxyURL:     fmt.Sprintf("socks5://127.0.0.1:%d", socksPort),
		LimitTunnelProtocols: tcpOnlyPsiphonProtocols,
	}
	b, err := json.Marshal(overlay)
	if err != nil {
		return "", err
	}
	dir := PsiphonDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, psiphonOverlayName)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// RemovePsiphonOverlay removes the overlay written by WritePsiphonOverlay. It is
// idempotent and safe to call even when this session never wrote one: the
// overlay is a per-session temp artifact, so Disconnect clears it regardless.
func RemovePsiphonOverlay() {
	path := filepath.Join(PsiphonDir(), psiphonOverlayName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		logx.Warnf("[vpn] removing psiphon overlay: %v", err)
	}
}

// resetPsiphonState clears only the lock files of the Psiphon datastore.
//
// The datastore itself (downloaded server list, tactics) must SURVIVE: with a
// cold store Psiphon has to fetch its remote server list from S3 through the
// just-established tunnel, and on a slow first hop that fetch times out
// ("failed to fetch common remote server list: context deadline exceeded") -
// the chained connect then dies before it ever carried traffic. The stale
// lock, on the other hand, must go: a killed psiphon-tunnel-core leaves it
// behind and the next one times out opening the database.
//
// The orphan process is reaped before this runs (killOrphanPsiphon), so the
// lock files are guaranteed to be stale.
func resetPsiphonState() {
	dir := PsiphonDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // no datastore yet - nothing stale to clean
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".lock") {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			removed++
		}
	}
	if removed > 0 {
		logx.Debugf("[vpn] cleared %d stale psiphon lock file(s); datastore kept", removed)
	}
}

// SystemProxyPort is the HTTP listener the Windows system proxy must point at
// for traffic to actually leave through the selected backend.
func SystemProxyPort(s config.Settings) int {
	switch s.ExitChain {
	case ChainPsiphon, ChainPsiphonOnly:
		return PsiphonHTTPPort
	case ChainTor, ChainTorOnly:
		return TorHTTPPort
	}
	return s.HTTPProxyPort
}

// validateEndpoint checks a user-pasted "ip:port" (optionally a bracketed
// IPv6 "[::1]:port") and returns it trimmed, or "" when it is not usable.
func validateEndpoint(raw string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil || host == "" || port == "" {
		return ""
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return ""
	}
	return net.JoinHostPort(host, port)
}

// sanitizeExitLoc validates a user-provided exit-country policy before it is
// handed to the core. Accepted shapes: "!CN" / "!CN,HK" (deny list) and
// "US,JP" (allow list), case-insensitive. Anything malformed is dropped so a
// typo can never send the core into a re-select loop.
func sanitizeExitLoc(raw string) string {
	spec := strings.ToUpper(strings.TrimSpace(raw))
	if spec == "" || spec == "ANY" || spec == "OFF" {
		return ""
	}
	negated := strings.HasPrefix(spec, "!")
	codes := []string{}
	for _, c := range strings.Split(strings.TrimPrefix(spec, "!"), ",") {
		c = strings.TrimSpace(c)
		if len(c) == 2 && c[0] >= 'A' && c[0] <= 'Z' && c[1] >= 'A' && c[1] <= 'Z' {
			codes = append(codes, c)
		}
	}
	if len(codes) == 0 {
		return ""
	}
	joined := strings.Join(codes, ",")
	if negated {
		return "!" + joined
	}
	return joined
}

// CoreScanValue maps a UI scan mode onto the value the core understands. The
// core ships turbo|balanced|thorough|verified|ironclad - Stealth is its
// "verified" mode, so the name is translated here instead of sending a value
// the core would silently read as balanced.
func CoreScanValue(m config.ScanMode) string {
	if m == config.ScanStealth {
		return "verified"
	}
	return string(m)
}

// Disconnect stops the tunnel via the Core Controller and resets state.
func (m *Manager) Disconnect() {
	if err := m.core.Stop(); err != nil {
		logx.Warnf("[vpn] core stop: %v", err)
	}
	// The psiphon overlay is a per-session temp artifact; clear it on every
	// teardown (idempotent) so a failed or killed session never leaves a stale
	// UpstreamProxyURL pointing at a dead tunnel SOCKS.
	RemovePsiphonOverlay()
	// The core does not always reap Psiphon when it is torn down (a protocol
	// switch stops and restarts the core). An orphan holds the datastore lock
	// and the backend ports, which used to fail every later chained connect -
	// including back to the transport that had just worked.
	if IsPsiphonChain(m.chain) {
		killOrphanPsiphon()
	}
	m.mu.Lock()
	m.chain = ChainNone
	m.exitHTTPPort = 0
	m.backendReady = false
	m.connectGate = nil
	m.st.Chain = ""
	m.mu.Unlock()
	m.mu.Lock()
	m.st.Status = StatusDisconnected
	m.st.ExitIP = ""
	m.st.ExitCountry = ""
	m.st.ExitFlag = ""
	m.st.LatencyMs = 0
	m.mu.Unlock()
	m.publish()
}

// SetExitInfo updates exit IP info after a lookup.
func (m *Manager) SetExitInfo(ip, country, flag string, latencyMs int64) {
	m.set(StatusConnected, func(st *State) {
		st.ExitIP = ip
		st.ExitCountry = country
		st.ExitFlag = flag
		st.LatencyMs = latencyMs
	})
}

// SetTesting toggles the testing badge.
func (m *Manager) SetTesting(on bool) {
	if on {
		m.set(StatusTesting, nil)
	} else if m.State().Status == StatusTesting {
		m.set(StatusConnected, nil)
	}
}

// SetGateway records the active gateway (from scan events).
func (m *Manager) SetGateway(gw string) {
	m.mu.Lock()
	m.st.Gateway = gw
	m.mu.Unlock()
	m.publish()
}

// Close tears the manager down.
func (m *Manager) Close() {
	m.Disconnect()
}
