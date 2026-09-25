// Package vpn is the connection manager: it derives the AETHER_* environment
// from user settings, runs the state machine (disconnected → connecting →
// connected / failed → reconnecting) on top of the Core Controller, and
// publishes state changes to subscribers (the UI).
package vpn

import (
	"fmt"
	"net"
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
	// PsiphonRegions is the set of countries psiphon reported it can leave
	// from right now. The picker shows the client's own list, but this is the
	// authoritative one — it changes as psiphon's servers come and go.
	PsiphonRegions []string `json:"psiphon_regions"`
	Error       string      `json:"error"`
	StartedAt   time.Time   `json:"started_at"`
	CoreRunning bool        `json:"core_running"`
}

// Manager drives one active connection through the Core Controller.
type Manager struct {
	mu     sync.RWMutex
	st     State
	core   *coremgr.Manager
	subMu  sync.Mutex
	subs   []func(State)
	stopCh chan struct{}

	// lastMasqueGW is a MASQUE gateway the core already proved usable. MIM's
	// own sweep often comes back with "no clean endpoint", but handing it a
	// known-good outer edge connects in seconds (measured: ~15s vs never).
	lastMasqueGW string
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
	if IsSlowMasque(s) && s.ScanMode == "" {
		set("AETHER_SCAN", "ironclad")
	} else {
		set("AETHER_SCAN", string(s.ScanMode))
	}
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

// argsFor derives the command line arguments for the core. Only switches with
// no environment equivalent live here; everything else rides envFor.
//
// Psiphon is the reason this exists. It is exposed purely as flags, and the
// shape matters, measured against core 2.1.0:
//
//	--psiphon        chains psiphon *inside* the tunnel and serves it on its
//	                 own --psiphon-bind (1821); it needs a working WARP/MASQUE
//	                 tunnel underneath first, and 1819 is not the psiphon exit.
//	--psiphon-only   no tunnel at all; 1819 itself leaves through psiphon.
//
// The client's exit detection probes the configured SOCKS port, so only the
// second shape reports the real psiphon egress and reuses the existing
// proxy / DNS / system-proxy plumbing unchanged.
func argsFor(s config.Settings) []string {
	if !IsPsiphon(s) {
		return nil
	}
	args := []string{"--psiphon-only"}
	if r := strings.TrimSpace(s.Psiphon.Region); r != "" {
		args = append(args, "--psiphon-region", r)
	}
	// "auto" is the core's own default, so only an explicit shape is worth
	// spending a flag on.
	if m := strings.TrimSpace(s.Psiphon.Mode); m != "" && m != "auto" {
		args = append(args, "--psiphon-mode", m)
	}
	return args
}

// ArgsFor exposes the derived arguments (tests, smoke runs).
func ArgsFor(s config.Settings) []string { return argsFor(s) }

// IsPsiphon reports whether the user picked the standalone Psiphon transport.
func IsPsiphon(s config.Settings) bool {
	return s.Mode == config.ModePsiphon || s.Protocol == "psiphon"
}

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

	env := envFor(s)
	// MIM's own sweep often ends with "no clean endpoint". Handing it a gateway
	// the core already proved on a single-hop MASQUE run brings the outer hop up
	// in seconds (measured ~15s vs never); the core still rescans if it is stale.
	if s.Protocol == "mim" {
		m.mu.RLock()
		gw := m.lastMasqueGW
		m.mu.RUnlock()
		if gw != "" {
			env["AETHER_MIM_OUTER_PEER"] = gw
			logx.Infof("[vpn] MIM: reusing proven outer gateway %s", gw)
		}
	}
	args := argsFor(s)
	if IsPsiphon(s) {
		// Psiphon is a request, not a guarantee: the country is asked for,
		// and whatever psiphon actually picks is what the exit check reports.
		logx.Infof("[Psiphon] starting region=%q mode=%q", s.Psiphon.Region, s.Psiphon.Mode)
		logx.Infof("[Psiphon] args: %v", args)
	}
	sess, err := m.core.StartArgs(env, args, config.Dir())
	if err != nil {
		m.set(StatusFailed, func(st *State) { st.Error = err.Error() })
		return err
	}
	m.mu.Lock()
	m.stopCh = make(chan struct{})
	m.st.Status = StatusConnecting
	m.st.Mode = s.Mode
	m.st.Error = ""
	m.st.Gateway = s.CachedGateway
	m.st.StartedAt = time.Now()
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
		return fmt.Errorf("SOCKS port %s is already in use; close the other AetherVPN/aether process or choose another SOCKS port", addr)
	}
	return ln.Close()
}

// pump consumes core events into the state machine.
func (m *Manager) pump(sess coremgr.Session) {
	for ev := range sess.Events() {
		switch ev.Kind {
		case "log":
			logx.Debugf("[core] %s", ev.Line)
		case "progress":
			// H2/MIM transport progress must stay visible: the MASQUE scan
			// plus fragmented TLS handshake can take 1-2 minutes, and without
			// these lines the UI log looks frozen.
			logx.Infof("[core] %s", ev.Line)
		case "connected":
			m.set(StatusConnected, func(st *State) { st.Error = "" })
		case "scanning":
			if m.State().Status == StatusConnecting {
				m.set(StatusConnecting, nil)
			}
		case "reconnect":
			m.set(StatusReconnecting, nil)
		case "psiphon_regions":
			// Psiphon's own list wins over the client's static one: it is what
			// the servers can actually offer at this moment.
			if regs := coremgr.EgressRegions(ev.Line); len(regs) > 0 {
				logx.Infof("[Psiphon] available regions: %v", regs)
				m.set(m.State().Status, func(st *State) { st.PsiphonRegions = regs })
			}
		case "failed":
			m.set(StatusFailed, func(st *State) { st.Error = ev.Line })
		case "stopped":
			// Keep a startup error visible.  Previously a fatal bind failure was
			// immediately overwritten by "disconnected", which made the UI look
			// connected even though no local proxy had started.
			if m.State().Status != StatusFailed {
				m.mu.Lock()
				m.st.Status = StatusDisconnected
				m.mu.Unlock()
				m.publish()
			}
			return
		}
	}
}

// Disconnect stops the tunnel via the Core Controller and resets state.
func (m *Manager) Disconnect() {
	if err := m.core.Stop(); err != nil {
		logx.Warnf("[vpn] core stop: %v", err)
	}
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
	// Remember MASQUE-class gateways only: MIM reuses one as its outer hop,
	// and a WireGuard endpoint would be the wrong address family for that.
	if gw != "" {
		switch m.st.Mode {
		case config.ModeMasqueH2, config.ModeMasqueH3:
			m.lastMasqueGW = gw
		}
	}
	m.mu.Unlock()
	m.publish()
}

// Close tears the manager down.
func (m *Manager) Close() {
	m.Disconnect()
}
