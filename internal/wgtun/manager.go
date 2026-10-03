//go:build wgtun

package wgtun

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
)

// Manager owns a running native WireGuard session end to end: the wintun
// adapter, the wireguard-go device (with WARP reserved bytes), and the
// Windows routing/DNS takeover. It is the single entry point the app layer
// uses; Start/Stop are safe to call repeatedly and serialize internally.
type Manager struct {
	mu     sync.Mutex
	tunnel *tunnel
	routes *routeManager
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
func (m *Manager) Start(cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunnel != nil {
		return fmt.Errorf("wgtun: already running")
	}

	// Self-check (connect-time): recover any route/metric/DNS left behind by a
	// previous unclean exit before touching the system again. Unlike the
	// start-up check (which must not block), a connect already implies
	// elevation, so a failed recovery here DOES block — layering a fresh
	// takeover on top of unrecovered residue would only compound the mess.
	if err := recoverFromState(); err != nil {
		return fmt.Errorf("wgtun: recovery from previous unclean exit failed: %w", err)
	}

	// Build the candidate list up front. If the pinned endpoint is empty, seed
	// the device's initial endpoint with the first candidate so Up() has a real
	// value to configure.
	candidates := buildCandidates(cfg.Endpoint)
	if cfg.Endpoint == "" && len(candidates) > 0 {
		cfg.Endpoint = candidates[0]
	}

	// Create the wintun adapter + device ONCE. The endpoint probe below only
	// switches the peer endpoint via UAPI (millisecond scale) — it must never
	// tear the adapter down, or every candidate pays the 3-4s adapter rebuild
	// cost and briefly flaps routes/DNS/metric (the exact outage window seen in
	// the first sweep).
	t, err := New(cfg)
	if err != nil {
		return err
	}
	if err := t.Up(); err != nil {
		_ = t.Down()
		return err
	}

	connected, err := m.probeEndpoint(t, candidates)
	if err != nil {
		_ = t.Down()
		return err
	}

	// Only now touch routing/DNS, against the endpoint that actually worked.
	rm := newRouteManager(t.luid(), cfg.DNS)
	if err := rm.ApplyEndpointRoute(connected); err != nil {
		_ = t.Down()
		return err
	}
	if err := rm.ApplyDefaultRoutes(); err != nil {
		_ = rm.Revert()
		_ = t.Down()
		return err
	}
	if err := rm.ApplyDNS(); err != nil {
		_ = rm.Revert()
		_ = t.Down()
		return err
	}

	m.tunnel = t
	m.routes = rm
	logx.Infof("[wgtun] connected via %s", connected)
	return nil
}

// probeEndpoint walks the candidates in order and returns the FIRST endpoint
// that completes a handshake. It deliberately does not probe a whole batch and
// then switch back to the fastest: Cloudflare rate-limits handshakes from the
// same account when they fire in quick succession, so the first success is
// followed by a run of rate-limited failures — and switching back to the winner
// re-triggers the limit and kills the one good keypair. Cached endpoints sort
// first (fastest last-RTT first), so the previously-fastest endpoint gets the
// first chance, which is the practical "speed preference" under rate limiting.
// The wintun adapter stays up the whole time; each switch is a UAPI
// remove+recreate of the peer.
func (m *Manager) probeEndpoint(t *tunnel, candidates []string) (string, error) {
	return probeEndpoints(t, candidates)
}

// probeEndpoints is the endpoint-probe loop shared by the single tunnel
// (Manager.Start) and the stacked outer layer: walk candidates, hot-switch the
// peer endpoint via UAPI, and return the first one whose handshake completes.
func probeEndpoints(t *tunnel, candidates []string) (string, error) {
	cache := loadCache()
	defer cache.save()

	var lastErr error
	for i, ep := range candidates {
		logx.Infof("[wgtun] probing endpoint %d/%d: %s", i+1, len(candidates), ep)
		// The first candidate is already configured by Up(); switching to it
		// again would be churn.
		if i > 0 {
			if err := t.setEndpoint(ep); err != nil {
				cache.recordFailure(ep)
				lastErr = err
				logx.Warnf("[wgtun] endpoint %s set failed: %v", ep, err)
				continue
			}
		}
		start := time.Now()
		if err := t.WaitHandshake(probeTimeout); err != nil {
			cache.recordFailure(ep)
			lastErr = err
			continue
		}
		rtt := time.Since(start)
		cache.recordSuccess(ep, rtt.Milliseconds())
		logx.Infof("[wgtun] connected via %s (handshake %v)", ep, rtt)
		return ep, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no candidate endpoints")
	}
	return "", fmt.Errorf("no endpoint worked after %d candidates: %w", len(candidates), lastErr)
}

// probeTimeout is how long probeEndpoint waits for the handshake on a single
// candidate endpoint before switching to the next. 1s proved too tight in
// testing (healthy endpoints flapped into fallback), so 2s gives slow/jittery
// handshakes room while keeping a full batch sweep bounded (~16s worst case).
const probeTimeout = 2 * time.Second

// revertTimeout is the hard ceiling on how long Stop will wait for Revert
// before giving up and continuing to tear down the device. Revert must never
// block process exit: past this point we log a marker and move on.
const revertTimeout = 5 * time.Second

// Stop reverts routes/DNS and tears the adapter down. It is idempotent.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
