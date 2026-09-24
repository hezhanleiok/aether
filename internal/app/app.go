// Package app wires every subsystem together: Core Controller, VPN manager,
// node pool, system proxy, kill switch, watchguard, and settings. The GUI
// calls into App only; nothing in the UI touches subsystems directly.
package app

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
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

	subMu   sync.Mutex
	onState []func(vpn.State)
	onNodes []func()
	onCore  []func()

}

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

	a.Guard = watchguard.New(watchguard.Config{}, a, nil)
	a.Traffic = NewTrafficSampler(a)
	return a, nil
}

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
	logx.Warnf("[app] gateway unhealthy: rescanning")
	a.Settings.AutoScan = true
	a.Reconnect()
}

// Connect starts the VPN honoring the current settings and mode.
func (a *App) Connect() error {
	s := a.Settings
	// A fresh, user-initiated connect starts the gool exit search over. The
	// guard's own retries must not reset the counter, or it would loop forever.
	if s.Mode == config.ModeDirect {
		a.Disconnect()
		return nil
	}
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
		if s.HTTPProxyPort > 0 {
			if err := sysproxy.Take(sysproxy.Options{
				Server: fmt.Sprintf("127.0.0.1:%d", s.HTTPProxyPort),
			}); err != nil {
				logx.Warnf("[app] system proxy takeover failed: %v", err)
			} else {
				logx.Infof("[app] system proxy -> 127.0.0.1:%d", s.HTTPProxyPort)
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
	// MASQUE H2 and MIM need the prober's whole 120s scan plus a fragmented TLS
	// handshake per hop (measured: H2 ≈126s, MIM ≈174s). The generic budget
	// stops them moments before they would come up, so give them real headroom.
	if vpn.IsSlowMasque(a.Settings) && timeout < 300*time.Second {
		timeout = 300 * time.Second
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
	a.Guard.SetUp(false)
	a.VPN.Disconnect()
	a.Pool.ClearStatus()
	if err := sysproxy.Release(); err != nil {
		logx.Warnf("[app] system proxy release failed: %v", err)
	}
	if killswitch.Enabled() {
		if err := killswitch.Disable(); err != nil {
			logx.Warnf("[app] kill switch disable failed: %v", err)
		}
	}
}

// Reconnect = disconnect + connect.
func (a *App) Reconnect() {
	a.Disconnect()
	_ = a.Connect()
}

// RefreshExitInfo queries the exit IP through the tunnel (SOCKS5) and updates
// state + the connected node row. Failures never touch the connection.
func (a *App) RefreshExitInfo() {
	deadline := time.Now().Add(20 * time.Second)
	socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(a.Settings.SocksPort))
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

	ipv4, latencyMs, ipErr := fetchExitIP()
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
	st := a.VPN.State()
	a.VPN.SetExitInfo(info.IP, info.Country, info.Flag, latencyMs)
	if gw := st.Gateway; gw != "" {
		a.Pool.UpdateExit(gw, info.IP, info.Country, info.Flag)
	}
	logx.Infof("[app] exit: %s %s %s", info.Flag, info.Country, info.IP)
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
