//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
)

// Manager owns a running native WireGuard session end to end: the wintun
// adapter, the wireguard-go device, and the Windows routing/DNS takeover.
// It is the single entry point the app layer
// uses; Start/Stop are safe to call repeatedly and serialize internally.
type Manager struct {
	mu     sync.Mutex
	tunnel *tunnel
	routes *routeManager

	// current is the endpoint the live session is using. It moves when failover
	// succeeds, and is what failover picks the next candidate relative to.
	current string

	// OnState reports liveness transitions of a LIVE session:
	// StateReconnecting when the endpoint dies and the first failover attempt
	// begins, StateConnected when a failover completed and the session carries
	// traffic again. Nil-safe. Set BEFORE Start, read-only afterwards. Invoked
	// from the health-monitor goroutine, outside m.mu — handlers must be quick
	// and must not call back into blocking Manager methods.
	OnState func(state string)

	// notified is the last state pushed via OnState, so a transition fires
	// exactly once (a session stuck failing over must not re-push
	// "reconnecting" on every health tick). Reset at Start entry.
	notified string

	// gen is the session generation, bumped at Start entry. The delayed speed
	// sample compares it after waking, so a disconnect+reconnect during the
	// sample delay cannot mislabel the new session's measurement.
	gen uint64

	// healthStop closes the health-monitor goroutine of the live session.
	healthStop chan struct{}

	// link is the physical-link metric guard for the CURRENT session. It is
	// restored in Stop, not only in Start: the drift it protects against was
	// observed to happen WHILE the tunnel is up (WLAN IPv4 left with
	// AutomaticMetric=Disabled and no metric after a 2-minute session, 2026-10-04),
	// i.e. after Start had already returned.
	link *linkMetricGuard
}

// Running reports whether a native session is currently up.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tunnel != nil
}

// Start creates the adapter, applies the WARP identity, brings the device up,
// and installs routes + DNS. It requires elevation (wintun driver + HKLM).
// On any failure it tears down whatever it already created, so a failed Start
// leaves the machine exactly as it was.
func (m *Manager) Start(ctx context.Context, cfg Config, onPhase func(string)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnel != nil {
		return fmt.Errorf("wgtun: already running")
	}
	// Session-scoped bookkeeping must start from a clean slate even when this
	// Manager is being reused: a previous session may have died with
	// notified=StateReconnecting (or never reset it after a failed Start), and
	// letting that leak would suppress the new session's first transition.
	m.notified = ""
	m.gen++

	// Self-check (connect-time): recover any route/metric/DNS left behind by a
	// previous unclean exit before touching the system again. Unlike the
	// start-up check (which must not block), a connect already implies
	// elevation, so a failed recovery here DOES block — layering a fresh
	// takeover on top of unrecovered residue would only compound the mess.
	if err := recoverFromState(); err != nil {
		return fmt.Errorf("wgtun: recovery from previous unclean exit failed: %w", err)
	}

	// Physical-link metric guard: snapshot the adapter that carries the default
	// route (WLAN/Ethernet, both families) and restore it on EVERY exit path —
	// cancel, error, or success. The probe below is stateless UDP and never
	// touches a metric, but the 2026-10-04 incident (WLAN metric left altered
	// after an interrupted probe, whole machine black-holed) must be impossible
	// by construction, not merely unlikely. Restore is a no-op while the link
	// is healthy; it only writes when the value actually drifted.
	link := newLinkMetricGuard()
	m.link = link // also restored by Stop, see the field's note
	defer func() {
		if err := link.restore(); err != nil {
			logx.Errorf("[wgtun] link metric guard: %v", err)
		}
	}()

	// Build the candidate list: cached/seed endpoints first (fast path, no UDP
	// burst). The real tunnel is created once and then hot-switches its peer
	// endpoint across candidates — no throwaway devices, no adapter rebuild per
	// candidate. Concurrent dummy-device handshakes were dropped deliberately:
	// they completed handshakes the real tunnel could not reproduce, and their
	// devices competed with it for the same UDP 5-tuple/Cloudflare session.
	// Out-of-pool cache sweep, at most once per pruneInterval: cached addresses
	// this build's pool can no longer generate get probed on every connect and
	// can never be proposed by a sweep, so they are pure dead weight.
	if removed, ran := pruneStaleCache(cfg.Endpoint); ran && removed > 0 {
		logx.Infof("[wgtun] dropped %d cached endpoints the current pool no longer generates", removed)
	}

	cands, fromSweep, err := probeCandidates(ctx, cfg, "", false, onPhase)
	if err != nil {
		return err
	}
	cfg.Endpoint = cands[0].Addr

	// Create the wintun adapter + device against the first candidate.
	t, err := New(cfg)
	if err != nil {
		return err
	}
	if err := t.Up(); err != nil {
		_ = t.Down()
		return err
	}

	// HARD GATE: the real tunnel must complete its own handshake before the
	// default route flips. If it cannot (endpoint drifted during the adapter
	// build, or Cloudflare rejected it), hot-switch to the next candidate and
	// retry — then, only if every candidate failed, do a full-pool UDP sweep
	// and retry those too. Taking over the default route without a completed
	// handshake black-holes every packet on the machine (the "connected then
	// whole link died" failure: DUMP-TUN showed traffic entering the TUN while
	// every send hit "no usable keypair").
	// Cached endpoints get a short deadline (6s covers WireGuard's 5s retransmit
	// plus a slow RTT): a stale cache entry should fail fast so the sweep starts
	// sooner. Swept endpoints are known-live, so they get the full deadline.
	//
	// fromSweep — not the call site — decides which one applies: when the fast
	// path finds no survivors, probeCandidates falls through and runs the sweep
	// INTERNALLY, so its results are swept candidates even though this is the
	// "fast path" call. Passing them the 6s deadline meant for stale cache
	// entries was silently killing endpoints that only needed WireGuard's 5s
	// retransmit to land (observed 2026-10-05: three swept candidates each
	// failed at exactly 6s, the fourth connected).
	deadline := 6 * time.Second
	if fromSweep {
		deadline = handshakeTimeout
	}
	connected, err := handshakeAcross(t, cands, deadline)
	if err != nil && ctx.Err() == nil {
		logx.Infof("[wgtun] cached/seed candidates all failed (%v); running full sweep", err)
		swept, _, serr := probeCandidates(ctx, cfg, "", true, onPhase)
		if serr == nil {
			connected, err = handshakeAcross(t, swept, handshakeTimeout)
		}
	}
	if err != nil {
		_ = t.Down()
		return fmt.Errorf("wgtun: no endpoint completed a real-tunnel handshake: %w", err)
	}

	// Only now touch routing/DNS, against the endpoint that actually worked.
	rm := newRouteManager(t.luid(), cfg.DNS)
	// Defensive metric/route/DNS restore: every failure path below must leave
	// the machine exactly as it was. The explicit branches call Revert, but a
	// single deferred Revert makes it impossible for a future added path (or a
	// panic) to leak a lowered interface metric, a default route, or tunnel DNS
	// into the next run. Revert is idempotent, so the overlap is a no-op. This
	// is the IPv4+IPv6 metric-restore guarantee the earlier "probe interrupted,
	// WLAN metric left altered" bug needed — now enforced structurally.
	keep := false
	defer func() {
		if !keep {
			_ = rm.Revert()
		}
	}()

	if err := rm.ApplyEndpointRoute(connected); err != nil {
		_ = t.Down()
		return err
	}
	if err := rm.ApplyDefaultRoutes(); err != nil {
		_ = t.Down()
		return err
	}
	if err := rm.ApplyDNS(); err != nil {
		_ = t.Down()
		return err
	}

	// Data-plane gate, through the now-live tunnel. The handshake proves the
	// control plane only: WARP can complete a handshake and still black-hole
	// transport (drifted endpoint, wrong inner source address). A failed probe
	// returns an error, which trips the deferred Revert above and restores the
	// machine — the user never sees a dead link.
	//
	// The probe deliberately targets a bare IP, not a hostname: the tunnel DNS
	// (1.1.1.1) itself rides the tunnel, so a DNS-based probe would deadlock
	// against the very thing it is testing and report "data plane dead" for
	// what is really a name-resolution stall.
	if err := probeTunnelDataPlane(5 * time.Second); err != nil {
		_ = t.Down()
		return fmt.Errorf("wgtun: tunnel handshake ok but data plane dead (reverted): %w", err)
	}
	logx.Infof("[wgtun] data plane verified (IP reachability through %s)", connected)

	// Speed sample is best-effort: it needs a hostname (DNS through the tunnel),
	// so a DNS hiccup must not fail a connect that can otherwise carry traffic.
	//
	// Sampling runs DELAYED and ASYNCHRONOUSLY: right after a connect the TCP
	// flow is deep in slow-start, which is what made the old immediate 3s
	// sample read 2.6 Mbps on a link doing 63 (2026-10-04 logs). Waiting 10s
	// lets the route settle and the flow ramp; sampling then lasts
	// speedSampleDuration instead of the old hardcoded 3s. Async because Start
	// holds m.mu and the UI's Connected transition waits on Start — a
	// synchronous 10s sleep would pin every connect in "Connecting".
	//
	// ConnectSpeedSample turns it off for survival runs: a 20 MB download fired
	// right before "how long until this flow is blocked" is measured is exactly
	// the kind of traffic that can trip a volume-based DPI, i.e. a confound.
	if ConnectSpeedSample {
		m.scheduleSpeedSample()
	}

	keep = true

	// The winning endpoint is already persisted by handshakeAcross, which owns
	// attempt accounting (SuccessCount AND Attempts). Recording it again here
	// would count one success without its attempt, inflating the success rate a
	// little more on every connect until the number stopped being a ratio at
	// all. It becomes the next connect's first candidate through the ordered
	// cache in buildCandidates.

	m.tunnel = t
	m.routes = rm
	m.current = connected
	logx.Infof("[wgtun] connected via %s", connected)

	// Endpoints die on their own (DPI, drift, blocked port), so a connect that
	// succeeded once is not a session that stays up: watch it and fail over to
	// the next endpoint when it stops carrying traffic. This is the gap the
	// 2026-10-04 runs exposed — the tunnel simply died and nothing recovered it.
	// HealthMonitor lets tools measure one endpoint's survival without recovery.
	if HealthMonitor {
		m.startHealthMonitor()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Endpoint liveness + failover.
//
// A WARP endpoint can die minutes after a perfectly good connect: the port gets
// blocked, the anycast IP drifts, or DPI latches onto the flow (observed
// 2026-10-04 — the session just went quiet and nothing recovered it). Recovery
// is the missing half of endpoint selection, so the manager watches the live
// session and hot-switches the peer to the next candidate when it goes dead.
// ---------------------------------------------------------------------------

// Session states reported through Manager.OnState. Wgtun cannot import the
// vpn package (that would be a reverse dependency), so the app layer maps
// these onto its own state machine.
const (
	// StateConnected: the session is carrying traffic (initial connect or a
	// completed failover).
	StateConnected = "connected"
	// StateReconnecting: the endpoint died and failover is in progress. The
	// monitor keeps running, so a later round can still recover.
	StateReconnecting = "reconnecting"
)

// notifyState pushes a session-state transition through OnState. mu is held
// only to read the fields; the callback itself runs OUTSIDE mu so a handler
// that drives the app layer's state machine can never deadlock against us.
// Duplicate transitions are suppressed via m.notified; a session that is
// already down suppresses late notifications — Stop/Disconnect owns that
// transition, and a late "connected" must not overwrite "Disconnected".
func (m *Manager) notifyState(s string) {
	m.mu.Lock()
	if m.tunnel == nil || m.OnState == nil || s == m.notified {
		m.mu.Unlock()
		return
	}
	m.notified = s
	cb := m.OnState
	m.mu.Unlock()
	cb(s)
}

var (
	// healthInterval is how often the live session is checked. A var (not a
	// const) so tests can shrink it instead of waiting 15s per tick.
	healthInterval = healthIntervalDefault
)

const (
	// healthProbeTimeout bounds ONE liveness probe (a bare-IP HTTP request).
	// The monitor deliberately uses a single attempt: the connect gate's retry
	// loop costs up to ~18s, which is longer than the check interval and made
	// the monitor unable to react inside a test window.
	healthProbeTimeout = 4 * time.Second
	// failoverHandshakeTimeout is the per-candidate handshake deadline during a
	// failover. Short because candidates are cached/pool endpoints (a stale one
	// should fail fast so the next is tried), and because the session is already
	// degraded while this runs.
	failoverHandshakeTimeout = 6 * time.Second
	// healthInterval is how often the live session is checked.
	healthIntervalDefault = 10 * time.Second
	// healthFailStreak is how many consecutive bad checks trigger a failover.
	// Two, not one: a single dropped probe on a lossy link is not a dead
	// endpoint, and failing over on noise would churn the session.
	healthFailStreak = 2
	// handshakeStaleAfter: a peer that has not rekeyed for this long has lost
	// its endpoint. Keepalive is 25s and rekey 120s, so 3 minutes is well past
	// "quiet" and into "gone".
	handshakeStaleAfter = 3 * time.Minute
	// failoverBatch is how many candidates one failover attempt walks before
	// giving up (and re-deriving a fresh list on the next round).
	failoverBatch = 4
	// failoverRounds is how many batches one failover tries before declaring
	// the endpoint dead for now. The monitor keeps running, so a later round
	// can still recover if the network comes back.
	failoverRounds = 2
)

// startHealthMonitor watches the live session and fails over when it dies.
func (m *Manager) startHealthMonitor() {
	stop := make(chan struct{})
	m.healthStop = stop
	logx.Infof("[wgtun] health monitor started (interval=%v, endpoint=%s)", healthInterval, m.current)
	go func() {
		ticker := time.NewTicker(healthInterval)
		defer ticker.Stop()
		streak := 0
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if !m.Running() {
					return
				}
				if m.healthy() {
					streak = 0
					continue
				}
				streak++
				if streak < healthFailStreak {
					logx.Warnf("[wgtun] health check %d/%d failed on %s", streak, healthFailStreak, m.Current())
					continue
				}
				logx.Warnf("[wgtun] endpoint %s looks dead (%d failed checks); failing over", m.Current(), streak)
				// Per-tick dedup reset (Step 2.5): the app-side bridge GUARDS its
				// transitions (a Reconnecting push is only applied while the UI is
				// Connected), so a push can be legitimately swallowed — e.g. by a
				// node speed-test holding StatusTesting, after which SetTesting(false)
				// restores a stale "Connected". With whole-outage dedup the swallowed
				// push never re-fired and the UI lied for the entire outage. Clearing
				// notified at the start of EVERY failover round re-arms the push, so
				// the UI self-heals within one health interval; within a round
				// notifyState still dedups.
				m.mu.Lock()
				m.notified = ""
				m.mu.Unlock()
				// State push (failover START): the UI must stop showing a stale
				// "connected" while every candidate is failing — that was the
				// 01:11 incident, where failover burned through the whole list
				// with the UI still green. Duplicate-safe via notifyState.
				m.notifyState(StateReconnecting)
				if m.failover() {
					// State push (failover SUCCESS): back to connected.
					m.notifyState(StateConnected)
					streak = 0
				}
				// Failover exhausted: stay in StateReconnecting and keep monitoring;
				// the next tick clears notified again, so the push re-fires until the
				// session recovers or the user disconnects. A later round can still
				// recover if the network comes back.
			}
		}
	}()
}

// healthy reports whether the live session still carries traffic AND still has
// a fresh handshake. Both matter: traffic alone can go quiet because the user
// is idle, and a fresh handshake alone does not prove packets get through.
func (m *Manager) healthy() bool {
	m.mu.Lock()
	t := m.tunnel
	m.mu.Unlock()
	if t == nil {
		return false
	}
	if age, ok := t.lastHandshakeAge(); ok && age > handshakeStaleAfter {
		logx.Warnf("[wgtun] last handshake %v ago (stale)", age.Truncate(time.Second))
		return false
	}
	if err := probeOnce(healthProbeTimeout); err != nil {
		logx.Debugf("[wgtun] health probe: %v", err)
		return false
	}
	return true
}

// failover hot-switches the peer to the next usable endpoint. It installs the
// candidate's host route BEFORE re-handshaking and only drops the old route
// after the switch succeeded, so a failed attempt never strands the session
// without a route. Returns true when the session is healthy again.
func (m *Manager) failover() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnel == nil || m.routes == nil {
		return false
	}

	skip := map[string]bool{}
	tried := 0
	for round := 0; round < failoverRounds; round++ {
		cands := failoverCandidates(m.current, skip, failoverBatch)
		if len(cands) == 0 {
			break
		}
		for _, next := range cands {
			skip[next] = true
			tried++
			logx.Infof("[wgtun] failover %s -> %s", m.current, next)

			// Route first: without it the candidate's handshake would leave via
			// the default route, i.e. into the current (dead) tunnel.
			if err := m.routes.addEndpointRouteFor(next); err != nil {
				logx.Warnf("[wgtun] failover: route for %s: %v", next, err)
				// Judged dead, not just unlucky: this candidate got a real
				// handshake (or an attempted one) on the live tunnel, so evict
				// it now instead of banking another strike toward
				// failThreshold — a stale entry must not be able to win the
				// fast path on the next connect.
				cache := loadCache()
				cache.evict(next)
				cache.save()
				continue
			}
			if err := m.tunnel.setEndpoint(next); err != nil {
				logx.Warnf("[wgtun] failover: set endpoint %s: %v", next, err)
				_ = m.routes.dropEndpointRoute(next)
				// Judged dead, not just unlucky: this candidate got a real
				// handshake (or an attempted one) on the live tunnel, so evict
				// it now instead of banking another strike toward
				// failThreshold — a stale entry must not be able to win the
				// fast path on the next connect.
				cache := loadCache()
				cache.evict(next)
				cache.save()
				continue
			}
			if err := m.tunnel.WaitHandshake(failoverHandshakeTimeout); err != nil {
				logx.Warnf("[wgtun] failover: handshake %s: %v", next, err)
				_ = m.routes.dropEndpointRoute(next)
				// Judged dead, not just unlucky: this candidate got a real
				// handshake (or an attempted one) on the live tunnel, so evict
				// it now instead of banking another strike toward
				// failThreshold — a stale entry must not be able to win the
				// fast path on the next connect.
				cache := loadCache()
				cache.evict(next)
				cache.save()
				continue
			}
			if err := probeOnce(healthProbeTimeout); err != nil {
				logx.Warnf("[wgtun] failover: data plane via %s: %v", next, err)
				_ = m.routes.dropEndpointRoute(next)
				// Judged dead, not just unlucky: this candidate got a real
				// handshake (or an attempted one) on the live tunnel, so evict
				// it now instead of banking another strike toward
				// failThreshold — a stale entry must not be able to win the
				// fast path on the next connect.
				cache := loadCache()
				cache.evict(next)
				cache.save()
				continue
			}

			// Success: drop the old endpoint's route only now.
			old := m.current
			if err := m.routes.dropEndpointRoute(old); err != nil {
				logx.Warnf("[wgtun] failover: dropping old route %s: %v", old, err)
			}
			m.current = next
			cache := loadCache()
			// The endpoint we just left was declared dead by the health monitor
			// (consecutive failed checks), so drop it immediately: leaving it
			// cached makes the next connect's fast path start from a known-bad
			// endpoint and pay another full 6s handshake timeout before falling
			// through to the sweep — the 2-4 minute connect this is about.
			cache.evict(old)
			cache.recordSuccess(next, 0)
			cache.save()
			logx.Infof("[wgtun] failover complete: %s -> %s", old, next)
			return true
		}
	}
	logx.Errorf("[wgtun] failover: %d candidates tried, none usable; endpoint %s still dead", tried, m.current)
	return false
}

// BreakEndpoint is a TEST SEAM (used by cmd/wgbench -break-after): it simulates
// the current endpoint dying by removing its host route on the physical link,
// which is exactly what "the endpoint stopped answering" looks like from the
// tunnel's side — handshake packets leave via the default route, i.e. into their
// own tunnel, and nothing comes back. It does NOT touch the peer or the device;
// only the health monitor's failover can recover the session.
func (m *Manager) BreakEndpoint() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.routes == nil || m.current == "" {
		return fmt.Errorf("wgtun: no live session to break")
	}
	logx.Warnf("[wgtun] TEST: breaking endpoint %s (dropping its host route)", m.current)
	return m.routes.dropEndpointRoute(m.current)
}

// Current returns the endpoint the live session is using (empty when down).
func (m *Manager) Current() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// probeTunnelDataPlane proves the tunnel can actually carry IP traffic by
// reaching a bare address across it. Any HTTP response counts as success — the
// point is round-trip reachability, not a specific payload — and the target is
// an IP so the check never depends on the tunnel's own DNS.
// dataPlaneAttempts is how many times the post-connect reachability probe is
// retried before the connect is declared dead. It is >1 because the probe runs
// within a second or two of the route flip, and Windows can answer
// WSAENETUNREACH ("unreachable host") for that brief window even on a tunnel
// that then carries traffic perfectly (observed 2026-10-04 on 8.35.211.174:500,
// where a single probe killed an otherwise healthy connect). A transient must
// never revert a working tunnel.
const dataPlaneAttempts = 3

func probeTunnelDataPlane(timeout time.Duration) error {
	client := &http.Client{
		Timeout: timeout,
		// Do NOT follow redirects: 1.1.1.1 answers plain HTTP with a 301 to
		// HTTPS, and timing the redirect target instead would report "data
		// plane dead" for a tunnel that already carried a response — the first
		// hop is the evidence we want.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		// No proxy: the request must ride the system routing table, which the
		// routeManager just flipped onto the tunnel. A system proxy would
		// detour the probe and measure the wrong path.
		Transport: &http.Transport{Proxy: nil},
	}
	var lastErr error
	for attempt := 1; attempt <= dataPlaneAttempts; attempt++ {
		if err := probeOnceWith(client, timeout); err == nil {
			if attempt > 1 {
				logx.Infof("[wgtun] data plane verified on attempt %d/%d", attempt, dataPlaneAttempts)
			}
			return nil
		} else {
			lastErr = err
			logx.Warnf("[wgtun] data plane probe attempt %d/%d failed: %v", attempt, dataPlaneAttempts, err)
		}
		if attempt < dataPlaneAttempts {
			time.Sleep(1500 * time.Millisecond)
		}
	}
	return lastErr
}

// probeOnce is the single-shot form of the data-plane probe, used by the health
// monitor and by failover verification, where a slow retry loop would cost more
// than the reaction budget.
func probeOnce(timeout time.Duration) error {
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return probeOnceWith(client, timeout)
}

// probeOnceWith performs one reachability request with a prepared client.
func probeOnceWith(client *http.Client, timeout time.Duration) error {
	resp, err := client.Get("http://1.1.1.1/")
	if err != nil {
		return fmt.Errorf("data-plane probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode <= 0 {
		return fmt.Errorf("data-plane probe: no HTTP response")
	}
	return nil
}

// handshakeAcross drives the real tunnel's handshake across a ranked candidate
// list: the first candidate is already being tried (Up started it), and each
// failure hot-switches the peer to the next via UAPI — a millisecond remove+add,
// no adapter rebuild. It returns the first endpoint whose handshake completed.
func handshakeAcross(t *tunnel, cands []liveEndpoint, timeout time.Duration) (string, error) {
	var lastErr error
	// One load/save for the whole loop: each save rewrites endpoints.json, and
	// iterating up to maxHandshakeCandidates endpoints must not become that many
	// file round-trips.
	cache := loadCache()
	defer cache.save()
	for i, c := range cands {
		if i > 0 {
			if err := t.setEndpoint(c.Addr); err != nil {
				lastErr = err
				logx.Warnf("[wgtun] endpoint %s set failed: %v", c.Addr, err)
				continue
			}
		}
		logx.Infof("[wgtun] real-tunnel handshake %d/%d: %s", i+1, len(cands), c.Addr)
		err := t.WaitHandshake(timeout)
		// Learn from EVERY attempt — including the failures. This is what makes
		// the next connect start from endpoints that historically handshake
		// instead of re-running the same 8 timeouts in the same order. Failures
		// are recorded, not evicted: see endpointCache.recordAttempt.
		cache.recordAttempt(c.Addr, err == nil)
		if err != nil {
			lastErr = err
			continue
		}
		return c.Addr, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no candidates")
	}
	return "", fmt.Errorf("no endpoint completed a handshake among %d candidates: %w", len(cands), lastErr)
}

// speedSampleDelay is how long the speed sample waits after a connect before
// measuring. Right after the route flip the TCP flow is in slow-start and the
// sample reads a fraction of the real rate (2.6 vs 63 Mbps observed
// 2026-10-04); 10s lets the flow ramp before the measurement starts.
const speedSampleDelay = 10 * time.Second

// speedSampleDuration is how long the sample itself runs. The old code broke
// out of the read loop after a hardcoded 3s, so the window covered almost
// nothing but slow-start; 10s reaches steady state at WARP speeds.
const speedSampleDuration = 10 * time.Second

// scheduleSpeedSample launches the delayed, generation-guarded speed sample
// for the session being started. Callers hold m.mu; the goroutine re-takes it
// after the delay.
func (m *Manager) scheduleSpeedSample() {
	gen := m.gen
	ep := m.current
	go func() {
		time.Sleep(speedSampleDelay)
		// Generation guard: if the session this sample was scheduled for is
		// gone (user disconnected / reconnected while we slept), skip — a
		// naive Running() check would happily sample the NEW session and
		// mislabel it as the old one.
		m.mu.Lock()
		t := m.tunnel
		mine := m.gen == gen
		m.mu.Unlock()
		if t == nil || !mine {
			return
		}
		if mbps, err := measureTunnelSpeed(speedSampleDuration); err != nil {
			logx.Warnf("[wgtun] speed sample unavailable: %v", err)
		} else {
			logx.Infof("[wgtun] speed: %.1f Mbps through %s", mbps, ep)
		}
	}()
}

// measureTunnelSpeed verifies the data plane through the just-installed
// default route and reports the download rate. It fetches a fixed-size probe
// from speed.cloudflare.com (WARP's own speed host, reachable through the
// tunnel) and samples until either the body ends or the sample window closes.
// Any HTTP error, connect timeout, or <50 KB transferred in the window counts
// as a dead data plane — a handshake that cannot carry bytes must fail the
// connect so the route takeover is reverted (the machine must never be left
// routing into a silent tunnel).
func measureTunnelSpeed(window time.Duration) (float64, error) {
	client := &http.Client{
		Timeout: window,
		// No proxy: the request must ride the system routing table, which the
		// routeManager just flipped onto the tunnel. A system proxy would
		// detour the probe and measure the wrong path.
		Transport: &http.Transport{Proxy: nil},
	}
	// 20 MB is plenty for a multi-second sample at WARP speeds and keeps the
	// request inside the window; 100 MB only made the deadline the binding
	// constraint instead of the link.
	resp, err := client.Get("https://speed.cloudflare.com/__down?bytes=20000000")
	if err != nil {
		return 0, fmt.Errorf("data-plane probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("data-plane probe: status %d", resp.StatusCode)
	}

	buf := make([]byte, 32*1024)
	var total int64
	// Clock starts at the FIRST BODY byte: everything before it (DNS, TCP, TLS,
	// headers) is setup, not throughput, and counting it understated the link.
	// The loop ends when the sample duration elapses (steady-state window), or
	// the body ends, or the whole-request deadline (window) closes — whichever
	// comes first. There is deliberately no early "3s is enough" break: that
	// was the slow-start trap that read 2.6 Mbps on a 63 Mbps link.
	start := time.Now()
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 && total == 0 {
			start = time.Now()
		}
		total += int64(n)
		if err != nil {
			break
		}
		if time.Since(start) > window {
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	// Always log the raw numbers: even a rejected sample is evidence.
	logx.Infof("[wgtun] speed sample: %d bytes in %.2fs", total, elapsed)
	if elapsed < 0.5 || total < 200*1024 {
		return 0, fmt.Errorf("data-plane probe: only %d bytes in %.1fs", total, elapsed)
	}
	return float64(total) * 8 / (elapsed * 1_000_000), nil
}

// HealthMonitor enables the background liveness watch and automatic failover of
// a live session. Tools that want to measure a single endpoint's survival (the
// anti-DPI A/B) turn it off, so a dying endpoint is observed rather than
// silently replaced.
var HealthMonitor = true

// ConnectSpeedSample controls the best-effort throughput sample Manager.Start
// takes immediately after a successful connect. Survival runs (wgbench -hold,
// the anti-DPI A/B) set it to false: a 20 MB download fired right before
// measuring "how long until this flow is blocked" is a confound, not a
// measurement.
var ConnectSpeedSample = true

// speedSampleWindow is the throughput sample budget. It covers DNS + TLS +
// headers + body, because http.Client.Timeout is a whole-request deadline; the
// rate itself is computed from first body byte to last, so a slow TLS handshake
// no longer eats the measurement window.
const speedSampleWindow = 15 * time.Second

// MeasureSpeed samples the LIVE tunnel's download throughput and reports Mbps.
// It is the exported form of measureTunnelSpeed, for the wgbench tool and for
// anyone who needs a number after the connect has completed.
//
// CALIBRATION NOTE (2026-10-05): the effective sampling window changed today —
// the hardcoded 3s early-break was removed, so a window of W now really
// samples W (previously ~3s). Numbers from wgbench runs before 2026-10-05 are
// NOT comparable to later ones at the same -window flag.
func MeasureSpeed(window time.Duration) (float64, error) {
	return measureTunnelSpeed(window)
}

// revertTimeout is the hard ceiling on how long Stop will wait for Revert
// before giving up and continuing to tear down the device. Revert must never
// block process exit: past this point we log a marker and move on.
const revertTimeout = 5 * time.Second

// Stop reverts routes/DNS and tears the adapter down. It is idempotent.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Stop the health monitor FIRST: otherwise it can start a failover against a
	// session that is being torn down, re-adding a route Revert just deleted.
	if m.healthStop != nil {
		close(m.healthStop)
		m.healthStop = nil
	}
	var errs []error
	if m.routes != nil {
		if err := m.revertWithTimeout(m.routes); err != nil {
			errs = append(errs, err)
		}
		m.routes = nil
	}
	if m.tunnel != nil {
		if err := m.tunnel.Down(); err != nil {
			errs = append(errs, err)
		}
		m.tunnel = nil
	}
	m.current = ""
	// Physical-link metric: restore LAST, after the adapter is gone, so a drift
	// that happened while the session was up is caught too (the Start-time
	// deferred guard only covers the connect phase).
	if m.link != nil {
		if err := m.link.restore(); err != nil {
			errs = append(errs, err)
		}
		m.link = nil
	}
	return errors.Join(errs...)
}

// revertWithTimeout runs Revert under a hard timeout. On timeout it logs a
// marker and returns; the in-flight Revert goroutine is intentionally left to
// finish (or not) in the background so process exit is never blocked.
//
// Race note: after the timeout the goroutine may still be mutating rm's fields
// (ifMetric/added/dnsPath) while Stop has already set m.routes = nil. That is
// not a data race — the goroutine holds the rm pointer and Stop only reassigns
// the Manager.routes field (a different memory location). It is, however, a
// deliberate goroutine leak: the process is about to exit, the leaked Revert's
// syscalls (DeleteIpForwardEntry2 / SetIpInterfaceEntry) return quickly, and at
// worst the unfinished Revert is reaped by process teardown. Acceptable.
//
// Timeout fallout chain (understood & intended): on timeout Stop returns and
// sets m.routes = nil while the goroutine may still be mid-Revert. If the
// process then exits, that leaked Revert may never reach its clearState() call,
// so wgtun-state.json is left behind — that residue is exactly what the
// start-up RecoverState() and the connect-time recoverFromState() clean up on
// the next run. This is why recovery is checked on every launch, not only on
// connect.
func (m *Manager) revertWithTimeout(rm *routeManager) error {
	done := make(chan error, 1)
	go func() { done <- rm.Revert() }()
	select {
	case err := <-done:
		return err
	case <-time.After(revertTimeout):
		logx.Errorf("[wgtun] FORCE REVERT TIMEOUT (%v); continuing teardown", revertTimeout)
		return fmt.Errorf("revert timeout after %v", revertTimeout)
	}
}
