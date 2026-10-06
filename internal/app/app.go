// Package app wires every subsystem together: Core Controller, VPN manager,
// node pool, system proxy, kill switch, watchguard, and settings. The GUI
// calls into App only; nothing in the UI touches subsystems directly.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/coremgr"
	"github.com/aethergui/aethergui/internal/killswitch"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/node"
	"github.com/aethergui/aethergui/internal/sysproxy"
	"github.com/aethergui/aethergui/internal/vpn"
	"github.com/aethergui/aethergui/internal/watchguard"
)

// App is the composed application.
type App struct {
	Settings config.Settings
	Core     *coremgr.Manager
	VPN      *vpn.Manager
	Pool     *node.Pool
	Guard    *watchguard.Watch
	Traffic  *TrafficSampler

	// nativeWG holds the native WireGuard session (wireguard-go + wintun). It
	// is a no-op type unless built with the "wgtun" tag - see nativewg.go and
	// nativewg_stub.go.
	nativeWG nativeWGHandle

	// nativeStacked holds the warp-in-warp session (outer WARP tunnel carrying
	// an inner WARP tunnel). Mutually exclusive with nativeWG: StackedWireGuard
	// picks which one Connect() drives. Same build-tag story as nativeWG.
	nativeStacked nativeStackedHandle

	subMu   sync.Mutex
	onState []func(vpn.State)
	onNodes []func()
	onCore  []func()

	// connecting is a CAS guard: set true at the entry of Connect() and reset
	// (false) on every exit via a deferred Store. It lets a second concurrent
	// Connect() fail fast with ErrAlreadyConnecting instead of blocking behind
	// connMu for the whole probe (worst case ~224s). connMu still serializes
	// connect/disconnect; this flag only rejects re-entrancy.
	connecting atomic.Bool

	// connMu serializes connect/disconnect of the native (incl. stacked) backend
	// so a connect and a disconnect (or two connects) can never interleave. The
	// dangerous case was two stacked connects racing through the probe loop and
	// building two wintun stacks; this lock makes the second wait for the first
	// to finish. disconnectNative* run under this lock; the connect* functions
	// take it themselves.
	connMu sync.Mutex
	// cancelMu guards connectCancel, written by Connect and read by CancelConnect.
	// Kept separate from connMu so a cancel never blocks on an in-progress
	// connect (which holds connMu for the whole probe).
	cancelMu      sync.Mutex
	connectCancel context.CancelFunc

	// Native Exit session bookkeeping (Psiphon / Tor exits ONLY — see
	// vpn.NativeExitOnly). The DEFAULT exit never touches any of this.
	//
	// exitGen is bumped on every native-exit connect. Invalidating a
	// generation is what makes that session's late core events ignorable: a
	// psiphon_ready that arrives after the user cancelled (or after the
	// transport died) must not push the UI back to Connected. A plain bool
	// cannot express "this event belongs to an older attempt", which is
	// exactly how the old code ended up green while Psiphon left through
	// WLAN with the native tunnel already gone.
	exitMu        sync.Mutex
	exitGen       uint64
	exitActive    bool
	exitBackend   string // "psiphon" | "tor"
	exitTransport string // "awg" | "wg"
}

// ErrAlreadyConnecting is returned by Connect() when a connect is already in
// progress. The caller must not retry until the in-flight connect finishes
// (success, failure, or cancel). It replaces the old "block behind connMu for
// the whole probe" behavior so a second click fails fast instead of waiting.
var ErrAlreadyConnecting = errors.New("aether: connect already in progress")

// pickBackend chooses the core driver per settings: an explicit kind wins;
// otherwise library when the dll is present, else process. All local checks.
func pickBackend(s config.Settings) (coremgr.Backend, string) {
	switch s.CoreKind {
	case "process":
		return coremgr.NewProcessBackend(), "process"
	case "library":
		return coremgr.NewLibraryBackend(), "library"
	}
	// Prefer the library if its dll is already on disk.
	if lb := coremgr.NewLibraryBackend(); lb != nil {
		if _, err := lb.Locate(s.CorePath); err == nil {
			return lb, "library"
		}
	}
	return coremgr.NewProcessBackend(), "process"
}

// New builds the app: load settings, assemble the Core Controller (detect the
// core, no network access), seed the node pool, start the watchguard.
func New() (*App, error) {
	s, err := config.Load()
	if err != nil {
		return nil, err
	}
	logx.Init(s.LogLevel, config.Dir())

	// Repair whatever an unclean exit (crash / kill) left behind: a system
	// proxy still pointing at a listener that no longer exists bricks the
	// machine's internet access until someone fixes it by hand.
	sysproxy.SetDataDir(config.Dir())
	if sysproxy.RecoverStale(config.Dir()) {
		logx.Warnf("[app] restored the system proxy left over by a previous unclean exit")
	}

	backend, kind := pickBackend(s)
	core := coremgr.NewManager(backend)
	core.SetLogSink(func(ev coremgr.CoreEvent) {
		if ev.Kind == "log" {
			logx.Debugf("[core] %s", ev.Line)
		} else {
			logx.Infof("[core] %s %s", ev.Kind, ev.Line)
		}
	})
	// Detect the core: local search only, no downloads.
	if _, err := core.Detect(s.CorePath); err != nil {
		logx.Warnf("[app] core detect failed: %v", err)
	} else {
		logx.Infof("[app] core ready: %s v%s (%s)", core.Path(), core.Version(), kind)
	}

	pool := node.NewPool()
	pool.Seed()

	a := &App{
		Settings: s,
		Core:     core,
		VPN:      vpn.New(core),
		Pool:     pool,
	}
	a.VPN.Subscribe(func(st vpn.State) {
		a.subMu.Lock()
		subs := append([]func(vpn.State){}, a.onState...)
		a.subMu.Unlock()
		for _, fn := range subs {
			fn(st)
		}
	})
	// A pinned gateway that the core cannot use must not brick every later
	// attempt: on failure, drop the pin and retry once with automatic scanning.
	a.VPN.Subscribe(func(st vpn.State) { a.recoverFromFailedPin(st) })
	// MIM first tries H3; on failure it retries once over H2 (--mim --h2).
	a.VPN.Subscribe(func(st vpn.State) { a.mimH2Fallback(st) })

	// The exit IP can only be queried once the tunnel is actually up. Firing it
	// from Connect() races the gateway scan: the core may need a minute before
	// SOCKS listens, so the lookup used to die with "connection refused" and
	// the home screen never showed a country or flag.
	// Guarding on ExitIP == "" also stops SetExitInfo from re-triggering it.
	a.VPN.Subscribe(func(st vpn.State) {
		if st.Status == vpn.StatusConnected && st.ExitIP == "" {
			go a.RefreshExitInfo()
		}
	})
	pool.Subscribe(func() {
		a.subMu.Lock()
		subs := append([]func(){}, a.onNodes...)
		a.subMu.Unlock()
		for _, fn := range subs {
			fn()
		}
	})

	// The health probe has to travel the tunnel, otherwise it measures the
	// local line and reports "healthy" while the tunnel is dead. It is built
	// per call so it always follows the current SOCKS port and the active
	// exit chain (a chained session leaves through Psiphon's listener).
	a.Guard = watchguard.New(watchguard.Config{
		IgnoreIfnames: watchguardIgnoreIfnames(),
	}, a,
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			port := a.Settings.SocksPort
			// Once the session is fully up and the backend carries the final
			// egress, health-check the whole path (backend listener), not just
			// the Aether hop. Before that, and for reverse backends, the
			// Aether hop is the thing to watch.
			if a.VPN.State().Status == vpn.StatusConnected && vpn.ExitsThroughChain(a.Settings) {
				port = vpn.ChainSocksPort(a.Settings)
			}
			d, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil, proxy.Direct)
			if err != nil {
				return nil, err
			}
			cd, ok := d.(proxy.ContextDialer)
			if !ok {
				return nil, fmt.Errorf("socks dialer lacks DialContext")
			}
			return cd.DialContext(ctx, network, addr)
		})
	// The core exiting on its own used to end in a silent "Disconnected"
	// with nobody picking it up; route it to the normal reconnect path.
	a.VPN.SetDropHook(a.TunnelDown)
	a.Traffic = NewTrafficSampler(a)

	// Start-up self-check for native-WG residue. Must not block: a non-elevated
	// process with leftover routes/metric would otherwise be stuck. On failure
	// we keep the program running; the residue warning is derived on demand by
	// NativeResidue() (which checks the state file), so it always reflects the
	// disk's real state.
	if err := recoverNativeWGState(); err != nil {
		logx.Warnf("[wgtun] residue: %v", err)
	}
	return a, nil
}

// watchguardIgnoreIfnames returns the interface-name prefixes watchguard should
// ignore. With the native WireGuard backend it ignores the wintun virtual
// interface (by prefix, since pool reuse suffixes it as "Xiaohe 1", ...);
// without it the list is empty and nothing is ignored.
func watchguardIgnoreIfnames() []string {
	if nativeWGInterfaceName == "" {
		return nil
	}
	return []string{nativeWGInterfaceName}
}

// NativeResidue reports the stable residue code for the current state (empty
// means clean). It is derived on demand by checking the crash-recovery state
// file, so it always reflects the disk's real state — a successful recovery
// (which deletes the file) clears the warning on the next read without any
// manual field sync. It is never a raw error.
func (a *App) NativeResidue() string {
	if nativeWGResiduePresent() {
		return residueCode
	}
	return ""
}

// residueCode is the stable UI code for "previous unclean exit left residue".
// The raw recovery error stays in the log; the UI maps this code to a localized
// prompt (see the web UI i18n "wgtun_residue" key).
const residueCode = "wgtun_residue"

// OnState registers a UI state callback (multiple listeners supported).
func (a *App) OnState(fn func(vpn.State)) {
	a.subMu.Lock()
	a.onState = append(a.onState, fn)
	a.subMu.Unlock()
}

// OnNodes registers a UI node-list callback (multiple listeners supported).
func (a *App) OnNodes(fn func()) {
	a.subMu.Lock()
	a.onNodes = append(a.onNodes, fn)
	a.subMu.Unlock()
}

// OnCore registers a UI core-health callback (multiple listeners supported).
func (a *App) OnCore(fn func()) {
	a.subMu.Lock()
	a.onCore = append(a.onCore, fn)
	a.subMu.Unlock()
}

// notifyCore fans out to core listeners.
func (a *App) notifyCore() {
	a.subMu.Lock()
	subs := append([]func(){}, a.onCore...)
	a.subMu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

// notifyNodes fans out to node-list listeners (used when a sweep finishes).
func (a *App) notifyNodes() {
	a.subMu.Lock()
	subs := append([]func(){}, a.onNodes...)
	a.subMu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

// NotifyTick re-publishes the current state; the UI bridge uses it to keep
// slow-changing values (durations, core health) fresh.
func (a *App) NotifyTick() {
	a.VPN.Publish()
	a.notifyCore()
}

// Redetect re-runs core detection (after the user changed the path).
func (a *App) Redetect() {
	h, err := a.Core.Detect(a.Settings.CorePath)
	if err != nil {
		logx.Warnf("[app] core detect: %v", err)
	} else {
		logx.Infof("[app] core: %s v%s (%s)", a.Core.Path(), a.Core.Version(), a.Core.Health())
	}
	_ = h
	a.notifyCore()
}

// RestartCore stops and restarts the core session with current settings.
func (a *App) RestartCore() error {
	if !a.Core.Running() {
		return nil
	}
	env := vpn.EnvFor(a.Settings)
	_, err := a.Core.Restart(env, config.Dir())
	if err != nil {
		return err
	}
	logx.Infof("[app] core restarted")
	a.notifyCore()
	return nil
}

// StopCore stops the core session without touching the rest.
func (a *App) StopCore() error {
	err := a.Core.Stop()
	a.notifyCore()
	return err
}

// watchguard.Notifier implementation.
func (a *App) NetworkChanged() {
	st := a.VPN.State()
	if st.Status == vpn.StatusConnected || st.Status == vpn.StatusReconnecting {
		logx.Infof("[app] network changed while up: reconnecting")
		a.Reconnect()
	}
}

func (a *App) TunnelDown() {
	// The guard starts probing the moment a connect begins, but the listeners
	// only exist after the core validates the tunnel - and with a chained exit
	// Psiphon needs another 1-3 minutes on top. Treating probe failures from
	// that window as a dead tunnel reconnected every attempt mid-scan, which
	// is why chained connects never survived and plain connects kept churning.
	if st := a.VPN.State().Status; st != vpn.StatusConnected && st != vpn.StatusTrafficFailed {
		logx.Debugf("[app] tunnel probe failed while %s; ignored (session is still coming up)", st)
		return
	}
	logx.Warnf("[app] tunnel down")
	if a.Settings.AutoReconnect {
		a.Reconnect()
	}
}

// recoverFromFailedPin clears a pinned gateway that the core could not use and
// retries once with automatic scanning. Without this, a stale pin persisted in
// config.json (forced on the core via AETHER_PEER) makes every later attempt
// fail with "verify timeout" — across restarts and protocol switches alike.
func (a *App) recoverFromFailedPin(st vpn.State) {
	if st.Status != vpn.StatusFailed {
		return
	}
	s := a.Settings
	if s.CachedGateway == "" || s.AutoScan {
		return // nothing pinned; the failure has another cause
	}
	pin := s.CachedGateway
	// Drop the pin before retrying so a second failure cannot loop here.
	s.CachedGateway = ""
	s.AutoScan = true
	s.LastNode = ""
	if err := a.SaveSettings(s); err != nil {
		logx.Warnf("[app] clearing failed gateway pin: %v", err)
		return
	}
	logx.Warnf("[app] pinned gateway %s failed; cleared the pin and rescanning", pin)
	go func() {
		time.Sleep(1 * time.Second)
		if a.VPN.State().Status == vpn.StatusFailed {
			_ = a.Connect()
		}
	}()
}

// mimH2Fallback retries MIM over HTTP/2 when the default H3 (QUIC) path fails.
// The core supports --mim --h2; this gives MIM a second chance on networks
// where QUIC is blocked but TCP 443 gets through.
func (a *App) mimH2Fallback(st vpn.State) {
	if st.Status != vpn.StatusFailed {
		return
	}
	s := a.Settings
	// Only applies to MIM that was running on H3.
	if s.Protocol != "mim" || s.Mode != config.ModeMasqueH3 || s.UseH2 {
		return
	}
	logx.Warnf("[app] MIM over H3 failed; retrying with H2 transport")
	s.UseH2 = true
	if err := a.SaveSettings(s); err != nil {
		logx.Warnf("[app] MIM H2 fallback save failed: %v", err)
		return
	}
	go func() {
		time.Sleep(1 * time.Second)
		if a.VPN.State().Status == vpn.StatusFailed {
			_ = a.Connect()
		}
	}()
}

func (a *App) GatewayUnhealthy() {
	// Same gate as TunnelDown: a probe failure during Connecting is the
	// normal "listeners are not up yet", not a broken gateway.
	if st := a.VPN.State().Status; st != vpn.StatusConnected && st != vpn.StatusTrafficFailed {
		logx.Debugf("[app] gateway probe failed while %s; ignored", st)
		return
	}
	logx.Warnf("[app] gateway unhealthy: rescanning")
	a.Settings.AutoScan = true
	a.Reconnect()
}

// Connect starts the VPN honoring the current settings and mode.
func (a *App) Connect() error {
	// Reject re-entrancy immediately (no blocking): a second Connect while one
	// is probing must fail fast, not wait behind connMu for up to ~224s. The
	// deferred Store resets the flag on every exit (success, failure, cancel).
	if !a.connecting.CompareAndSwap(false, true) {
		return ErrAlreadyConnecting
	}
	defer a.connecting.Store(false)
	s := a.Settings
	// A fresh, user-initiated connect starts the gool exit search over. The
	// guard's own retries must not reset the counter, or it would loop forever.
	if s.Mode == config.ModeDirect {
		a.Disconnect()
		return nil
	}
	// The connect's context is cancelled by CancelConnect (GUI cancel button,
	// 2b) or on return; it threads into the probe loop so a cancel stops a long
	// endpoint sweep instead of waiting it out.
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelMu.Lock()
	a.connectCancel = cancel
	a.cancelMu.Unlock()
	defer func() {
		a.cancelMu.Lock()
		a.connectCancel = nil
		a.cancelMu.Unlock()
		cancel()
	}()

	// EXIT DISPATCH. The exit choice — not the protocol toggle — decides
	// whether the native transport is involved at all:
	//
	//	exit=default  -> the original core path, untouched (no native AWG/WG,
	//	                 no Psiphon, no Tor, no only mode)
	//	exit=psiphon  -> native AWG/WG transport + core Psiphon in only mode
	//	exit=tor      -> native AWG/WG transport + core Tor in only mode
	//
	// The native backend is NOT a shared underlay for every exit: it exists
	// here only to carry the Psiphon/Tor backend's own traffic. Routing the
	// default exit through it (which is what `useNativeWG` alone used to do,
	// since it only looks at Mode) is explicitly wrong.
	if a.useNativeWG(s) {
		exit := vpn.NativeExitOnly(s)
		logx.Infof("[app] exit=%s (native transport + core %s only)", exit, exit)
		return a.connectNativeExit(ctx, s)
	}
	// Default exit: no native transport, no Psiphon, no Tor, no only mode —
	// the original core-driven path, untouched.
	logx.Infof("[app] exit=default (core path)")

	if err := a.VPN.Connect(s); err != nil {
		return err
	}
	a.Guard.SetUp(true)

	switch s.Mode {
	case config.ModeSplit:
		cfg := sysproxy.SplitConfig{
			DirectDomains: s.SplitDirect,
			BlockDomains:  s.SplitBlock,
		}
		pacURL, err := sysproxy.WritePAC(config.Dir(), "127.0.0.1", s.HTTPProxyPort, cfg)
		if err != nil {
			logx.Warnf("[app] PAC generation failed: %v", err)
		} else if err := sysproxy.TakePAC(pacURL, nil); err != nil {
			logx.Warnf("[app] PAC install failed: %v", err)
		} else {
			logx.Infof("[app] split PAC installed (%s)", pacURL)
		}
	default:
		// Every tunneled mode (auto/full_vpn/proxy/warp/gool/masque_*) takes
		// over the system proxy so browsers route through the tunnel.
		//
		// With the chained exit the system must be pointed at Psiphon's HTTP
		// listener, not the Aether hop's: the core's own HTTP proxy still
		// leaves through the Aether edge (often a mainland-CN address), which
		// is exactly the "connected, but the browser is dead" failure this
		// chain exists to fix.
		port := vpn.SystemProxyPort(s)
		if port > 0 {
			if err := sysproxy.Take(sysproxy.Options{
				Server: fmt.Sprintf("127.0.0.1:%d", port),
			}); err != nil {
				logx.Warnf("[app] system proxy takeover failed: %v", err)
			} else {
				logx.Infof("[app] system proxy -> 127.0.0.1:%d (chain=%q)", port, s.ExitChain)
			}
		}
	}

	if s.KillSwitch {
		if path := a.Core.Path(); path != "" && a.Core.Backend().Kind() == "process" {
			if err := killswitch.Enable(path); err != nil {
				logx.Warnf("[app] kill switch failed: %v", err)
			}
		} else {
			logx.Warnf("[app] kill switch needs the process core (library mode has no exe path)")
		}
	}

	go a.connectWatchdog()
	return nil
}

// connectWatchdog guards against the UI showing "connecting" forever: if the
// core never reaches Connected within the scan budget (ConnectTimeout plus
// headroom for a full gateway sweep), it stops the attempt with a clear log
// line instead of spinning indefinitely.
func (a *App) connectWatchdog() {
	timeout := 150 * time.Second
	if s := a.Settings; s.ConnectTimeout > 0 {
		timeout = time.Duration(s.ConnectTimeout)*time.Second + 120*time.Second
	}
	// MASQUE commits to a gateway only after the prober has swept its budget,
	// then handshakes on top (measured: a balanced sweep ≈120s to select, H2
	// ≈126s, MIM ≈174s). The generic budget can therefore cut a connect off
	// moments before it would come up — which looks exactly like "this protocol
	// is broken". Every MASQUE transport gets real headroom, not just H2/MIM.
	if timeout < 300*time.Second && vpn.IsMasqueClass(a.Settings) {
		timeout = 300 * time.Second
	}
	// A chained exit adds a second hop on top of the tunnel: Psiphon only
	// starts once the tunnel exposes its SOCKS port and may take up to its
	// own 180s budget to establish. Without this the watchdog stops the
	// attempt right before the chain would come up.
	if vpn.ExitsThroughChain(a.Settings) {
		timeout += 180 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		switch a.VPN.State().Status {
		case vpn.StatusConnected, vpn.StatusFailed, vpn.StatusDisconnected:
			return
		}
	}
	if st := a.VPN.State().Status; st == vpn.StatusConnecting || st == vpn.StatusReconnecting {
		logx.Warnf("[app] connect watchdog fired (%v); stopping the attempt", timeout)
		a.Disconnect()
	}
}

// Disconnect stops everything and restores the system state.
func (a *App) Disconnect() {
	// Invalidate any live Native Exit session FIRST: from here on, a late
	// core event of that session (a psiphon_ready that lands after this call)
	// must be ignored instead of reviving the UI. The gate coming off with it
	// is what makes the ignore effective.
	a.exitMu.Lock()
	if a.exitActive {
		logx.Infof("[app] native exit session #%d invalidated by disconnect", a.exitGen)
	}
	a.exitActive = false
	a.exitMu.Unlock()
	a.VPN.SetConnectGate(nil)
	// Defensive reset of the connect guard: a connect in flight is being torn
	// down here, so any flag it left must not leak into the next Connect (e.g.
	// a Reconnect's Connect). The authoritative reset is the deferred Store in
	// Connect(); this is belt-and-suspenders against a stale true.
	a.connecting.Store(false)
	a.connMu.Lock()
	defer a.connMu.Unlock()
	// The system proxy goes FIRST: with a chained/only-mode exit it points at
	// the backend's HTTP listener (1822), and every step below kills that
	// listener. Releasing up front means no request is ever aimed at a proxy
	// that is on its way down.
	if err := sysproxy.Release(); err != nil {
		logx.Warnf("[app] system proxy release failed: %v", err)
	}
	// The native tunnel must be torn down (routes + DNS reverted) before the
	// rest of the cleanup, so its default route never shadows the other steps.
	a.disconnectNativeStacked()
	a.disconnectNativeWG()
	a.Guard.SetUp(false)
	// Core stop + orphan-psiphon reaping: on the native path the core is the
	// thing running Psiphon/Tor, so this is what actually ends them.
	a.VPN.Disconnect()
	a.Pool.ClearStatus()
	if killswitch.Enabled() {
		if err := killswitch.Disable(); err != nil {
			logx.Warnf("[app] kill switch disable failed: %v", err)
		}
	}
}

// CancelConnect aborts an in-progress connect by cancelling its context. The
// probe loop checks the context at each candidate boundary, so a long sweep
// stops promptly rather than running to completion. Safe to call when no connect
// is running (no-op). This is the mechanism behind the GUI cancel button (2b)
// and a future watchdog stop path.
//
// Native failover fallback: the GUI's power button sends /api/cancel while the
// UI shows Reconnecting — but a native session in failover has NO connect
// context to cancel, so the button used to be a silent no-op (failover can run
// for tens of seconds). When no connect is in flight and a native session is
// live, treat the press as "stop trying and disconnect".
func (a *App) CancelConnect() {
	a.cancelMu.Lock()
	cancel := a.connectCancel
	a.cancelMu.Unlock()
	if cancel != nil {
		cancel()
		return
	}
	// No connect in flight: is a native session alive? (Reading the native
	// fields requires connMu; it is released BEFORE Disconnect() re-takes it,
	// so the call below cannot deadlock on itself.)
	a.connMu.Lock()
	nativeAlive := a.nativeSessionAlive()
	a.connMu.Unlock()
	if nativeAlive {
		a.Disconnect()
	}
}

// beginNativeExit opens a new Native Exit session and returns its generation.
// Any session already running is invalidated by the bump: its events can no
// longer reach the state machine.
func (a *App) beginNativeExit(backend, transport string) uint64 {
	a.exitMu.Lock()
	defer a.exitMu.Unlock()
	a.exitGen++
	a.exitActive = true
	a.exitBackend = backend
	a.exitTransport = transport
	return a.exitGen
}

// nativeExitValid reports whether gen is still the live Native Exit session.
func (a *App) nativeExitValid(gen uint64) bool {
	a.exitMu.Lock()
	defer a.exitMu.Unlock()
	return a.exitActive && a.exitGen == gen
}

// endNativeExit invalidates the given Native Exit session. It reports whether
// the caller owns the teardown: false means the session was already ended (or
// superseded by a newer one), so a rollback must NOT tear anything down —
// that is what makes rollbackNativeExit idempotent and staleness-safe.
func (a *App) endNativeExit(gen uint64) bool {
	a.exitMu.Lock()
	defer a.exitMu.Unlock()
	if !a.exitActive || a.exitGen != gen {
		return false
	}
	a.exitActive = false
	return true
}

// Reconnect = disconnect + connect.
func (a *App) Reconnect() {
	a.Disconnect()
	_ = a.Connect()
}

// RefreshExitInfo queries the exit IP through the tunnel (SOCKS5) and updates
// state + the connected node row. Failures never touch the connection.
func (a *App) RefreshExitInfo() {
	// NATIVE backend branch: there is no core and therefore no SOCKS listener,
	// so the lookup below used to dial 127.0.0.1:<core port> and die with
	// "connection refused" — exit IP / country / flag / latency stayed empty
	// for the whole session and the UI fell back to showing the tunnel's own
	// inner address (172.16.0.2) as the exit IP. The native tunnel owns the
	// default route by the time we get here, so its exit info is fetched
	// directly: a plain request already egresses through the tunnel.
	a.connMu.Lock()
	native := a.nativeSessionAlive()
	a.connMu.Unlock()
	if native {
		a.refreshNativeExitInfo()
		return
	}

	deadline := time.Now().Add(20 * time.Second)
	// With the chained exit the probe has to go through Psiphon's own SOCKS
	// listener: the Aether hop's port would happily answer while the final
	// egress is dead, which is how "connected" used to be reported.
	socksPort := a.Settings.SocksPort
	if vpn.ExitsThroughChain(a.Settings) {
		socksPort = vpn.ChainSocksPort(a.Settings)
	}
	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", socksAddr, time.Second)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		logx.Warnf("[app] socks dialer: %v", err)
		return
	}
	// The first request through a fresh MASQUE tunnel has to do DNS, TCP and
	// TLS inside the tunnel's netstack, which is far slower than a warm
	// connection — 12s was not enough and the exit country/flag stayed empty.
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext},
	}
	// The first request through a fresh MASQUE tunnel has to do DNS, TCP and
	// TLS inside the tunnel's netstack, which is far slower than a warm
	// connection. Retry before giving up: this lookup is what feeds the exit
	// country and flag in the UI, so a single cold-start timeout would leave
	// the home screen showing a globe instead of the real location.
	fetchExitIP := func() (string, int64, error) {
		var lastErr error
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(3 * time.Second)
			}
			start := time.Now()
			for _, u := range []string{
				"https://api.ipify.org?format=json",
				"https://api64.ipify.org?format=json",
			} {
				resp, err := client.Get(u)
				if err != nil {
					lastErr = err
					continue
				}
				var out struct {
					IP string `json:"ip"`
				}
				err = jsonDecode(resp, &out)
				resp.Body.Close()
				if err != nil {
					lastErr = err
					continue
				}
				if out.IP != "" {
					return out.IP, time.Since(start).Milliseconds(), nil
				}
			}
		}
		return "", 0, lastErr
	}

	ipv4, _, ipErr := fetchExitIP()
	var ipv6 string
	if ipv4 == "" && a.Settings.IPStack != config.IPv4Only {
		ipv6 = node.IPv6Lookup(context.Background(), client)
	}
	if ipv4 == "" && ipv6 == "" {
		if ipErr != nil {
			logx.Warnf("[app] exit IP lookup failed (%v); connection stays up", ipErr)
		} else {
			logx.Warnf("[app] exit IP lookup failed (connection stays up)")
		}
		// A chained exit that answers nothing is broken even though the
		// tunnel is up. Say so instead of leaving a green "Connected" on a
		// dead path - that is the failure mode this chain was added for.
		if a.Settings.ExitChain == vpn.ChainPsiphon {
			a.VPN.SetTrafficFailed(fmt.Sprintf("出口链无流量：经 Psiphon 出口 (127.0.0.1:%d) 的 HTTP 请求失败 %v", socksPort, ipErr))
		}
		return
	}
	ip := ipv4
	if ip == "" {
		ip = ipv6
	}
	// Geo enrichment is a plain database lookup for an IP we already obtained
	// through the tunnel: it goes direct, not through SOCKS. During protocol
	// switches the core restarts and the SOCKS listener is briefly down, which
	// used to fail the geo query and leave the UI without country/flag.
	geoClient := &http.Client{Timeout: 8 * time.Second}
	info, err := node.GeoLookup(context.Background(), geoClient, ip)
	if err != nil {
		// One retry: geo enrichment must never break the connection, but a
		// transient ip-api hiccup should not leave the country empty either.
		time.Sleep(2 * time.Second)
		info, err = node.GeoLookup(context.Background(), geoClient, ip)
	}
	if err != nil {
		logx.Warnf("[app] geo lookup failed: %v", err)
		info = node.GeoInfo{IP: ip}
	}
	// Latency is a real round trip through the tunnel, NOT the duration of the
	// HTTPS exit-IP lookup above. That number bundled DNS + TCP + TLS + the
	// response on a cold tunnel and read 812 ms where the actual RTT was a
	// fraction of it — and the UI labels the field "节点延迟". A TCP handshake
	// is exactly one round trip, measured through the same SOCKS dialer, i.e.
	// through the tunnel rather than the local line.
	rttCtx, rttCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer rttCancel()
	rttMs := measureRTT(rttCtx, dialer.(proxy.ContextDialer).DialContext, rttTarget, 3)
	if rttMs <= 0 {
		logx.Warnf("[app] tunnel RTT unavailable (latency stays unset)")
	}
	st := a.VPN.State()
	a.VPN.SetExitInfo(info.IP, info.Country, info.Flag, rttMs)
	if gw := st.Gateway; gw != "" {
		a.Pool.UpdateExit(gw, info.IP, info.Country, info.Flag)
	}
	logx.Infof("[app] exit: %s %s %s", info.Flag, info.Country, info.IP)
}

// rttTarget is the address the latency probe completes a TCP handshake with.
// Cloudflare's anycast address answers from the edge the tunnel egresses
// through, so the measured round trip is the tunnel's, not the local line's.
const rttTarget = "1.1.1.1:443"

// measureRTT returns the fastest of samples TCP handshakes to addr, in ms.
// dial is the SOCKS dialer on the core path (traffic rides the tunnel) and nil
// on the native path, where the tunnel already owns the default route. A TCP
// handshake is one round trip, so unlike "time to finish an HTTPS request"
// this is a genuine RTT and is what the UI's latency field now shows.
// Returns 0 when every sample failed.
func measureRTT(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), addr string, samples int) int64 {
	var best int64
	for i := 0; i < samples; i++ {
		start := time.Now()
		var (
			c   net.Conn
			err error
		)
		if dial != nil {
			c, err = dial(ctx, "tcp", addr)
		} else {
			d := &net.Dialer{Timeout: 5 * time.Second}
			c, err = d.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			continue
		}
		c.Close()
		if ms := time.Since(start).Milliseconds(); best == 0 || ms < best {
			best = ms
		}
	}
	return best
}

func publicIP(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var out struct {
		IP string `json:"ip"`
	}
	_ = jsonDecode(resp, &out)
	return out.IP
}

// RescanGateways clears the cached gateway and forces a fresh scan on next
// connect.
func (a *App) RescanGateways() {
	a.Settings.AutoScan = true
	a.Settings.CachedGateway = ""
	_ = config.Save(a.Settings)
	logx.Infof("[app] gateway cache cleared; next connect rescans")
}

// Close tears the app down.
func (a *App) Close() {
	a.Disconnect()
	a.Guard.Close()
	a.Traffic.Close()
	a.Core.Stop()
}
