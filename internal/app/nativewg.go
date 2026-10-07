//go:build wgtun

package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/node"
	"github.com/aethergui/aethergui/internal/sysproxy"
	"github.com/aethergui/aethergui/internal/vpn"
	"github.com/aethergui/aethergui/internal/wgtun"
)

// nativeWGHandle is the concrete native-WireGuard session holder in wgtun
// builds. The same field exists in non-wgtun builds as a no-op type, so the
// App struct keeps one shape across build tags.
type nativeWGHandle = *wgtun.Manager

// nativeStackedHandle is the warp-in-warp session holder in wgtun builds
// (no-op type in non-wgtun builds, like nativeWGHandle).
type nativeStackedHandle = *wgtun.StackedTunnel

// nativeWGInterfaceName is the wintun interface name the native backend uses;
// watchguard ignores it (by prefix) so the virtual adapter's create/destroy
// never triggers a reconnect loop.
const nativeWGInterfaceName = wgtun.DefaultInterfaceName

// recoverNativeWGState checks for and cleans up residue left by a previous
// unclean native-WG exit. It must not block start-up (a non-elevated process
// with residue would otherwise be stuck), so callers only log/prompt on error.
func recoverNativeWGState() error {
	return wgtun.RecoverState()
}

// nativeWGResiduePresent reports (read-only) whether native-WG residue exists,
// so the UI warning always reflects the disk's real state rather than a value
// cached at start-up.
func nativeWGResiduePresent() bool {
	return wgtun.ResiduePresent()
}

// NativeAvailable reports whether this build ships the native backend. AWG
// needs it (only the native device sends AmneziaWG junk), so a build without
// it must flag the entry rather than silently running plain WireGuard.
func NativeAvailable() bool { return true }

// useNativeWG reports whether this connect is carried by the native WireGuard
// transport. It is driven by the EXIT, not by the protocol toggle: the native
// backend is the transport of the Psiphon / Tor exits (the core runs those
// backends on top of it, in its "no tunnel underneath it" mode) and is never a
// shared underlay for the default exit. Deciding this from Mode alone is what
// used to route the default exit through native WG/AWG — and what made the
// toggle look like a per-protocol setting when it is really about the exit.
//
// StackedWireGuard (warp-in-warp) is a variant of the same transport and is
// picked inside connectNativeExit.
func (a *App) useNativeWG(s config.Settings) bool {
	return vpn.NativeExitOnly(s) != ""
}

// nativeSessionAlive reports whether any native backend session is up. The
// caller must hold connMu. Used by CancelConnect's fallback: a native session
// in failover has no connect context to cancel, so a /api/cancel press means
// "stop trying and disconnect" instead of being a silent no-op.
func (a *App) nativeSessionAlive() bool {
	return (a.nativeWG != nil && a.nativeWG.Running()) ||
		(a.nativeStacked != nil)
}

// connectNativeWG starts the native WireGuard tunnel (wintun + wireguard-go +
// routes + DNS) and drives the shared state machine to Connected. It bypasses
// the core entirely: the WARP identity the core provisioned is run at kernel
// speed. Requires elevation (the wintun driver and the HKLM DNS write).
func (a *App) connectNativeWG(ctx context.Context, s config.Settings) error {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	if a.nativeWG != nil && a.nativeWG.Running() {
		return nil
	}
	a.VPN.SetNativeState(vpn.StatusConnecting, s.Mode, "")
	cfg, err := wgtun.LoadIdentity(config.Dir(), s.CustomEndpoint)
	if err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}
	// AWG (AmneziaWG junk decoys) is decided by the UI switch, not by
	// wgtun-override.conf: a protocol picker that silently disagreed with the
	// file would make every "is junk on?" answer unfalsifiable. Junk ON takes
	// the settings' numbers (or the defaults); junk OFF is the plain
	// WireGuard baseline, whatever the identity file said.
	if s.AWGJunk {
		if s.JunkCount > 0 {
			cfg.JunkCount, cfg.JunkMinSize, cfg.JunkMaxSize = s.JunkCount, s.JunkMinSize, s.JunkMaxSize
		} else {
			cfg.JunkCount = config.DefaultJunkCount
			cfg.JunkMinSize = config.DefaultJunkMinSize
			cfg.JunkMaxSize = config.DefaultJunkMaxSize
		}
		logx.Infof("[app] native WireGuard: AWG junk ON (jc=%d jmin=%d jmax=%d)", cfg.JunkCount, cfg.JunkMinSize, cfg.JunkMaxSize)
	} else {
		cfg.JunkCount, cfg.JunkMinSize, cfg.JunkMaxSize = 0, 0, 0
	}
	// Fake first packet (I1). A profile name is expanded here; raw hex (an
	// externally generated packet) goes through verbatim. A bad value is
	// logged and skipped — it must not turn into a failed connect.
	if s.AWGI1 != "" {
		pkt, err := wgtun.ParseI1(s.AWGI1, s.AWGI1SNI, nil)
		if err != nil {
			logx.Errorf("[app] native WireGuard: I1 %q: %v (continuing without it)", s.AWGI1, err)
		} else if len(pkt) > 0 {
			cfg.JunkI1 = pkt
			logx.Infof("[app] native WireGuard: I1 fake first packet ON (%s, %d bytes)", s.AWGI1, len(pkt))
		}
	}

	m := &wgtun.Manager{}
	// Bridge wgtun's session-state transitions onto the shared state machine so
	// the UI reflects a dying/failing-over endpoint. Guarded on BOTH sides:
	// the callback can race a user Disconnect (it fires from the health
	// goroutine, outside connMu), and a late "connected" must never overwrite
	// the Disconnected that Disconnect() just set. Only sane transitions are
	// applied; anything else (Failed, Disconnected, a fresh Connecting) wins.
	m.OnState = func(state string) {
		switch state {
		case wgtun.StateReconnecting:
			if cur := a.VPN.State().Status; cur == vpn.StatusConnected {
				a.VPN.SetNativeState(vpn.StatusReconnecting, s.Mode, "")
			}
		case wgtun.StateConnected:
			if cur := a.VPN.State().Status; cur == vpn.StatusReconnecting {
				a.VPN.SetNativeState(vpn.StatusConnected, s.Mode, "")
			}
		case wgtun.StateFailed:
			// Failover gave up: wgtun already tore the dead session down
			// (routes/DNS reverted, physical network restored), so this only
			// moves the UI to an explicit signal instead of spinning
			// "Reconnecting" forever on a network that is down.
			if cur := a.VPN.State().Status; cur == vpn.StatusReconnecting || cur == vpn.StatusConnected {
				a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, "网络不通，请手动重连")
			}
			// A native exit MUST NOT survive the loss of its transport: with
			// the tunnel gone, the core's backend would keep working through
			// the physical link (WLAN) — a green UI whose traffic is not
			// going anywhere near the tunnel. Fail the whole session instead.
			if vpn.NativeExitOnly(s) != "" {
				a.exitMu.Lock()
				gen, active := a.exitGen, a.exitActive
				a.exitMu.Unlock()
				if active {
					logx.Errorf("[app] native transport lost while exit=%s session #%d was live; rolling back", vpn.NativeExitOnly(s), gen)
					a.rollbackNativeExit(gen, s, "传输层中断（Native 隧道已失效）")
				}
			}
		}
	}
	if err := m.Start(ctx, cfg, nil); err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}
	a.nativeWG = m
	logx.Infof("[app] native %s up (endpoint %s, mtu %d)", a.transportLabel(s), m.Current(), cfg.MTU)

	// The transport is READY here — but it is not the EXIT. On a Psiphon/Tor
	// exit this tunnel only carries the backend's traffic, so claiming
	// Connected now would be exactly the "green UI, dead browser" failure:
	// the backend has not even started. connectNativeExit owns the Connected
	// transition in that case (and runs outside connMu, held here, so a
	// Disconnect can interrupt a minutes-long bootstrap).
	if vpn.NativeExitOnly(s) != "" {
		return nil
	}
	a.VPN.SetNativeState(vpn.StatusConnected, s.Mode, "")
	return nil
}

// transportLabel names the transport this session actually runs, for logs —
// "AWG" when the AmneziaWG obfuscation is on, "WG" for the plain baseline.
func (a *App) transportLabel(s config.Settings) string {
	if s.AWGJunk || (s.AWGI1 != "" && !strings.EqualFold(s.AWGI1, "none")) {
		return "AWG"
	}
	return "WG"
}

// nativeExitReadyTimeout bounds the wait for the exit backend. Psiphon's own
// budget in the core is AETHER_PSIPHON_READY_SECS (180) and Tor bootstraps on
// its own clock (it fell back to bridges after 75s here), so this must be
// generous — and it is only ever a ceiling: Disconnect aborts the wait.
const nativeExitReadyTimeout = 240 * time.Second

// connectNativeExit runs the core's documented "no tunnel underneath it"
// backend on top of an already-established native WireGuard tunnel: the
// backend dials out through the system route, which is now the tunnel.
//
// Order is load-bearing:
//
//	native WG ready -> core (only mode) -> backend ready -> system proxy -> Connected
//
// Every failure rolls the whole stack back (proxy released, core stopped,
// orphan Psiphon reaped, native WG torn down) and returns Failed, so a half-up
// chain can never look connected.
func (a *App) connectNativeExit(ctx context.Context, s config.Settings) error {
	backend := vpn.NativeExitOnly(s)
	if backend == "" {
		// Guard rail: the default exit must never reach this path.
		return fmt.Errorf("internal: connectNativeExit called for the default exit")
	}
	transport := a.nativeTransportChoice(s)
	// 1. Open the session FIRST, so everything after it (transport, core,
	//    events) is attributable to one generation and can be invalidated.
	gen := a.beginNativeExit(backend, transport)
	logx.Infof("[app] exit=%s native_transport=%s (session #%d)", backend, transport, gen)

	// 2. Native transport. AWG first: plain WireGuard is measurably easier to
	//    block on this network, AmneziaWG is not. A single WG retry keeps the
	//    plain transport available, and only that — no loop.
	a.VPN.SetNativeState(vpn.StatusConnecting, s.Mode, "启动 "+strings.ToUpper(transport)+" 传输层")
	if err := a.startNativeTransport(ctx, s, transport); err != nil {
		if transport == nativeTransportAWG {
			logx.Warnf("[app] exit=%s native_transport=awg failed (%v); falling back to wg once", backend, err)
			transport = nativeTransportWG
			a.exitMu.Lock()
			a.exitTransport = transport
			a.exitMu.Unlock()
			if err2 := a.startNativeTransport(ctx, s, transport); err2 != nil {
				a.rollbackNativeExit(gen, s, fmt.Sprintf("AWG 与 WG 传输层均失败：%v", err2))
				return err2
			}
		} else {
			a.rollbackNativeExit(gen, s, fmt.Sprintf("WG 传输层失败：%v", err))
			return err
		}
	}
	logx.Infof("[app] native %s up (exit=%s session #%d)", transport, backend, gen)

	// 2.5 Tunnel SOCKS + Psiphon overlay: point Psiphon's upstream at the
	// tunnel-bound SOCKS (socks5://127.0.0.1:<port>) so its TCP tunnels dial
	// through the tunnel explicitly instead of trusting the system route. The
	// SOCKS server is a child of the Manager and is closed by tunnel teardown
	// (disconnectNativeWG -> Manager.Stop), so a failure below needs no extra
	// close. The stacked transport exposes no Manager, so it keeps the
	// route-based only mode.
	var psiphonOverlay string
	if backend == "psiphon" {
		a.connMu.Lock()
		wg := a.nativeWG
		a.connMu.Unlock()
		if wg != nil {
			_, port, err := wg.StartTunnelSocks()
			if err != nil {
				a.rollbackNativeExit(gen, s, fmt.Sprintf("隧道 SOCKS 启动失败：%v", err))
				return err
			}
			psiphonOverlay, err = vpn.WritePsiphonOverlay(port)
			if err != nil {
				a.rollbackNativeExit(gen, s, fmt.Sprintf("Psiphon overlay 生成失败：%v", err))
				return err
			}
			logx.Infof("[app] exit=psiphon: tunnel SOCKS on 127.0.0.1:%d, overlay %s", port, psiphonOverlay)
		}
	}

	// 3. Only start the core while the session is still wanted: starting it
	//    and then aborting is what left Psiphon bootstrapping on its own
	//    (through WLAN, with the tunnel already gone).
	if a.nativeExitAborted(gen) {
		a.rollbackNativeExit(gen, s, "连接已取消（传输层就绪后、核心启动前）")
		return fmt.Errorf("连接已取消（出口后端 %s 启动前）", backend)
	}

	// 4. Core in only mode. While this session is live, core events must NOT
	//    promote it to Connected by themselves — the orchestration here owns
	//    that transition (backend ready is only one of its preconditions).
	a.VPN.SetConnectGate(func() bool { return a.nativeExitValid(gen) })
	es := s
	es.ExitChain = vpn.OnlyChainFor(s)
	if psiphonOverlay != "" {
		// Hand the overlay to the core as AETHER_PSIPHON_CONFIG. Copy the slice
		// first: es shares s's CoreExtraArgs backing array, and an in-place
		// append could mutate the user's stored settings.
		es.CoreExtraArgs = append(append([]string(nil), es.CoreExtraArgs...), "AETHER_PSIPHON_CONFIG="+psiphonOverlay)
	}
	if err := a.VPN.Connect(es); err != nil {
		err = fmt.Errorf("出口后端 %s 启动失败：%w", backend, err)
		a.rollbackNativeExit(gen, s, err.Error())
		return err
	}

	// 5. Wait for the backend AND for the HTTP port the core announced.
	port, err := a.waitNativeExit(ctx, gen, backend)
	if err != nil {
		a.rollbackNativeExit(gen, s, err.Error())
		return err
	}
	if a.nativeExitAborted(gen) {
		a.rollbackNativeExit(gen, s, "连接已取消（后端就绪后）")
		return fmt.Errorf("连接已取消（出口后端 %s）", backend)
	}
	if !portListening(port) {
		err := fmt.Errorf("出口后端 %s 的 HTTP 代理 127.0.0.1:%d 未监听", backend, port)
		a.rollbackNativeExit(gen, s, err.Error())
		return err
	}

	// 6. System proxy LAST, only now that traffic can actually leave.
	//    Windows speaks HTTP CONNECT here — the backend's HTTP port, never
	//    the SOCKS port (1819) and never the chain ports (1821/1823).
	if err := sysproxy.Take(sysproxy.Options{Server: fmt.Sprintf("127.0.0.1:%d", port)}); err != nil {
		err = fmt.Errorf("系统代理接管失败：%w", err)
		a.rollbackNativeExit(gen, s, err.Error())
		return err
	}
	if a.nativeExitAborted(gen) {
		a.rollbackNativeExit(gen, s, "连接已取消（系统代理设置后）")
		return fmt.Errorf("连接已取消（出口后端 %s）", backend)
	}
	// 7. Connected — and only here.
	a.VPN.SetNativeState(vpn.StatusConnected, s.Mode, "")
	logx.Infof("[app] exit=%s native_transport=%s ready: system proxy -> 127.0.0.1:%d (session #%d)", backend, transport, port, gen)
	return nil
}

// nativeTransport* are the two native transports. They are the SAME wintun
// tunnel; they differ only in whether the AmneziaWG obfuscation is on.
const (
	nativeTransportAWG = "awg"
	nativeTransportWG  = "wg"
)

// nativeTransportChoice picks the transport a native exit (Psiphon/Tor) rides.
//
// It reads ExitNativeTransport — a dedicated transport preference — and NOT
// AWGJunk/AWGI1. Those two are the AmneziaWG obfuscation PARAMETERS (junk
// decoys and the fake first packet); using them as a transport selector
// conflated the I1 packet layer with the transport layer and left the UI no
// way to express "Psiphon should use plain WireGuard" (the switcher could only
// write AWGI1="" which had to mean "not configured", so it always fell back to
// AWG and silently added junk + I1 the user had not asked for).
//
// "" (auto) and "awg" both mean AmneziaWG: plain WireGuard is measurably
// easier to block on this network, so auto keeps the obfuscated transport.
// "wg" is an explicit user choice and is honoured as-is.
func (a *App) nativeTransportChoice(s config.Settings) string {
	switch strings.ToLower(strings.TrimSpace(s.ExitNativeTransport)) {
	case nativeTransportWG:
		return nativeTransportWG
	case nativeTransportAWG:
		return nativeTransportAWG
	}
	// "" / unrecognised -> auto -> AWG.
	return nativeTransportAWG
}

// startNativeTransport brings the native transport up for a native exit, with
// the chosen obfuscation applied. AWG reuses the existing wgtun AmneziaWG
// support (junk + I1) — there is no second tunnel implementation.
func (a *App) startNativeTransport(ctx context.Context, s config.Settings, transport string) error {
	ts := s
	switch transport {
	case nativeTransportAWG:
		// AWG on: junk + a QUIC-shaped first packet (warpscout's documented
		// "start here" profile). Only fills in what the user left unset.
		ts.AWGJunk = true
		if ts.JunkCount <= 0 {
			ts.JunkCount, ts.JunkMinSize, ts.JunkMaxSize = config.DefaultJunkCount, config.DefaultJunkMinSize, config.DefaultJunkMaxSize
		}
		if strings.TrimSpace(ts.AWGI1) == "" {
			ts.AWGI1 = config.DefaultAWGI1
		}
	case nativeTransportWG:
		// Plain WireGuard baseline: no junk, no fake first packet.
		ts.AWGJunk = false
		ts.AWGI1 = ""
	}
	if s.StackedWireGuard {
		return a.connectNativeStacked(ctx, ts)
	}
	return a.connectNativeWG(ctx, ts)
}

// waitNativeExit waits until the exit backend reports ready AND has announced
// the HTTP port the system proxy must use. It returns that port, or an error
// when the backend failed, the wait was cancelled, or the budget ran out.
func (a *App) waitNativeExit(ctx context.Context, gen uint64, backend string) (int, error) {
	deadline := time.Now().Add(nativeExitReadyTimeout)
	for time.Now().Before(deadline) {
		if !a.nativeExitValid(gen) {
			return 0, fmt.Errorf("会话 #%d 已失效（出口后端 %s 启动中）", gen, backend)
		}
		if a.nativeExitAborted(gen) {
			// Disconnect landed mid-bootstrap: rollback (below) stops the
			// core, so nothing keeps bootstrapping in the background.
			return 0, fmt.Errorf("连接已取消（出口后端 %s 启动中）", backend)
		}
		switch a.VPN.State().Status {
		case vpn.StatusFailed:
			return 0, fmt.Errorf("出口后端 %s 未就绪：%s", backend, a.VPN.State().Error)
		default:
			// backend ready is a state, not the status: with the gate in
			// place the core's own ready event only sets BackendReady, and
			// the HTTP port it announced is what the proxy must use. Tor's
			// port in particular is NEVER assumed (1824 was never measured).
			if a.VPN.BackendReady() {
				if port := a.VPN.ExitHTTPPort(); port > 0 {
					return port, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("出口后端 %s 启动被取消", backend)
		case <-time.After(500 * time.Millisecond):
		}
	}
	return 0, fmt.Errorf("出口后端 %s 在 %v 内未就绪（未报告 HTTP 代理端口）", backend, nativeExitReadyTimeout)
}

// rollbackNativeExit tears the whole native exit stack down:
//
//	invalidate session -> release system proxy -> stop core (+ reap orphan
//	Psiphon/Tor) -> stop native transport -> Failed
//
// It is idempotent AND staleness-safe: endNativeExit(gen) returns false when
// the session was already ended or superseded, in which case nothing is torn
// down — a late rollback must never dismantle a newer session, and calling it
// twice must not double-release or panic.
//
// Stopping the core is the part that matters most: the previous version only
// tore down the tunnel on the abort path, which is exactly how Psiphon ended
// up finishing its bootstrap and leaving through WLAN with no tunnel under it.
func (a *App) rollbackNativeExit(gen uint64, s config.Settings, reason string) {
	if !a.endNativeExit(gen) {
		logx.Infof("[app] native exit session #%d already ended (rollback skipped): %s", gen, reason)
		return
	}
	logx.Errorf("[app] native exit session #%d failed (%s); rolling the whole stack back", gen, reason)
	// The gate must go before the core stops, so no event of this session can
	// promote anything while teardown runs.
	a.VPN.SetConnectGate(nil)
	if err := sysproxy.Release(); err != nil {
		logx.Warnf("[app] system proxy release failed: %v", err)
	}
	a.VPN.Disconnect() // core stop + killOrphanPsiphon/Tor + state reset
	a.disconnectNativeWG()
	a.disconnectNativeStacked()
	a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, reason)
}

// nativeExitAborted reports whether the user (or a Disconnect) has abandoned
// this session: if so every remaining step must stop and roll back.
func (a *App) nativeExitAborted(gen uint64) bool {
	if !a.nativeExitValid(gen) {
		return true
	}
	a.connMu.Lock()
	wg := a.nativeWG
	a.connMu.Unlock()
	if wg == nil && !a.stackedAlive() {
		return true // the transport was already torn down
	}
	if !a.connecting.Load() {
		return true // Disconnect resets the connect guard
	}
	switch a.VPN.State().Status {
	case vpn.StatusDisconnected:
		return true
	}
	return false
}

// stackedAlive reports whether a stacked (warp-in-warp) session is up.
func (a *App) stackedAlive() bool {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	return a.nativeStacked != nil
}

// portListening reports whether 127.0.0.1:port accepts a TCP connection.
func portListening(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// refreshNativeExitInfo fills exit IP / country / flag / latency for the NATIVE
// backend — the fields that used to stay empty because the shared
// RefreshExitInfo only knows how to ask the core's SOCKS listener (which does
// not exist here).
//
// It deliberately goes DIRECT (no SOCKS, no proxy): by the time this runs the
// native tunnel has taken over the default route, so an ordinary HTTPS request
// already egresses through the tunnel. That is also why Cloudflare's trace
// endpoint is the first choice — one request yields the egress IP (ip=), the
// egress country (loc=) and the datacentre (colo=).
func (a *App) refreshNativeExitInfo() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// With no exit backend the request rides the system routing table, which
	// the native backend just flipped onto the tunnel (so Proxy: nil is the
	// tunnel). With a Psiphon/Tor backend on top, the tunnel is only the
	// transport: the EXIT is the backend, and the only way to see it is to go
	// through the HTTP port the core announced — otherwise we would report the
	// WARP egress while the browser leaves through Psiphon/Tor.
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	if port := a.VPN.ExitHTTPPort(); port > 0 {
		proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
		if err == nil {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			logx.Infof("[app] native exit info via backend proxy 127.0.0.1:%d", port)
		}
	}

	ip, loc, colo := traceExit(ctx, client)
	if ip == "" {
		ip = publicIP(client, "https://api.ipify.org?format=json")
	}
	if ip == "" {
		ip = publicIP(client, "https://api64.ipify.org?format=json")
	}
	if ip == "" {
		logx.Warnf("[app] native exit IP lookup failed (connection stays up)")
		return
	}
	rttMs := measureRTT(ctx, nil, rttTarget, 3)
	country, flag := "", ""
	// Geo enrichment is a plain lookup for an IP we already obtained through
	// the tunnel, so it goes direct too.
	if info, err := node.GeoLookup(ctx, client, ip); err == nil {
		country, flag = info.Country, info.Flag
	} else {
		logx.Warnf("[app] native geo lookup failed: %v", err)
	}
	// ip-api can answer with Cloudflare's registration country for an anycast
	// edge; the trace's loc= is where THIS traffic actually landed, so it wins
	// as the fallback.
	if country == "" && loc != "" {
		country, flag = node.CountryName(loc), node.FlagFromCode(loc)
	}
	a.VPN.SetExitInfo(ip, country, flag, rttMs)
	logx.Infof("[app] native exit: %s %s %s (rtt %d ms, colo %s)", flag, country, ip, rttMs, colo)
}

// traceExit reads Cloudflare's /cdn-cgi/trace and returns ip / loc / colo.
// Empty strings on any failure: callers fall back to ipify + ip-api.
func traceExit(ctx context.Context, client *http.Client) (ip, loc, colo string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if err != nil {
		return "", "", ""
	}
	resp, err := client.Do(req)
	if err != nil {
		logx.Warnf("[app] native trace: %v", err)
		return "", "", ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", "", ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "ip":
			ip = strings.TrimSpace(v)
		case "loc":
			loc = strings.TrimSpace(v)
		case "colo":
			colo = strings.TrimSpace(v)
		}
	}
	return ip, loc, colo
}

// disconnectNativeWG tears down the native tunnel and restores routes/DNS.
func (a *App) disconnectNativeWG() {
	if a.nativeWG != nil {
		if err := a.nativeWG.Stop(); err != nil {
			logx.Warnf("[app] native WireGuard stop: %v", err)
		}
		a.nativeWG = nil
	}
}

// newestInnerAccount picks the warp-accounts/*.json file with the most recent
// mtime, so a freshly minted inner account wins over stale ones. Errors are
// returned (not swallowed) — the caller surfaces them as a failed connect.
func newestInnerAccount(dir string) (string, error) {
	dirPath := filepath.Join(dir, "warp-accounts")
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return "", fmt.Errorf("warp-accounts: %w (run aetherregister to mint an inner account)", err)
	}
	type cand struct {
		path string
		mod  int64
	}
	var cands []cand
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cands = append(cands, cand{path: filepath.Join(dirPath, e.Name()), mod: info.ModTime().UnixNano()})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("warp-accounts: no account JSON in %s (run aetherregister to mint an inner account)", dirPath)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod > cands[j].mod })
	return cands[0].path, nil
}

// connectNativeStacked brings up warp-in-warp: outer WARP identity from
// aether.toml, inner from the newest registered account, inner endpoint routed
// through the outer adapter. Drives the same shared state machine the single
// native tunnel uses, so the UI needs no special casing.
// connectEnterHook is a test seam: if non-nil it runs at the very start of the
// native (including stacked) connect, under the connect lock, so tests can
// observe/serialize concurrent connects. Production leaves it nil.
var connectEnterHook func()

func (a *App) connectNativeStacked(ctx context.Context, s config.Settings) error {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	if connectEnterHook != nil {
		connectEnterHook()
	}
	if a.nativeStacked != nil {
		return nil // already up (Up() is idempotent-safe; a second connect is a no-op)
	}
	a.VPN.SetNativeState(vpn.StatusConnecting, s.Mode, "")
	onPhase := func(p string) { a.VPN.SetPhase(p) }

	account, err := newestInnerAccount(config.Dir())
	if err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}
	// Honest about the gap: the stacked path builds the outer device from
	// BuildStacked, which does not carry the junk settings, so "AWG selected"
	// and "stacked on" together would silently be plain WireGuard-in-WireGuard.
	if s.AWGJunk {
		logx.Warnf("[app] AWG junk is not applied in stacked mode (the outer device is built from BuildStacked)")
	}

	outerCfg, innerCfg, err := wgtun.BuildStacked(config.Dir(), account)
	if err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}
	st, err := wgtun.NewStackedTunnel(ctx, outerCfg, innerCfg, onPhase)
	if err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}
	a.nativeStacked = st
	a.VPN.SetNativeState(vpn.StatusConnected, s.Mode, "")
	logx.Infof("[app] stacked warp-in-warp up (outer=%s inner=%s, account %s)",
		st.OuterEndpoint(), innerCfg.Endpoint, filepath.Base(account))
	return nil
}

// disconnectNativeStacked tears the stack down in the reverse order of its
// setup (inner routes/metric/DNS revert → inner device → outer revert).
func (a *App) disconnectNativeStacked() {
	if a.nativeStacked != nil {
		if err := a.nativeStacked.Down(); err != nil {
			logx.Warnf("[app] stacked down: %v", err)
		}
		a.nativeStacked = nil
	}
}
