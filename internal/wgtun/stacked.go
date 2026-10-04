//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
	"golang.org/x/sys/windows"
)

// StackedTunnel is a minimal warp-in-warp (double WARP) tunnel, "route B": the
// OUTER layer stays a real wintun adapter, and the INNER layer's endpoint is
// reached by a /32 on-link route pinned onto the OUTER adapter. The inner
// WireGuard UDP packets therefore travel inside the outer tunnel via the system
// routing table — no custom conn.Bind, no netstack rewrite.
//
// TEMP-VERIFY: this whole file is a feasibility check. The clean production
// path (warpscout's tunnelBind / a netstack outer layer) replaces it later; see
// the coupling notes below. Known gaps:
//   - the inner adapter's metric/DNS are NOT persisted to the state file (only
//     its endpoint route is), so a hard-kill mid-connect recovers the inner
//     endpoint route but not the inner metric/DNS;
//   - outer and inner both write the single global state file, so a re-entrant
//     connect could interleave; the app only ever runs one stacked connect.
// stackedHandshakeTimeout is the inner layer's handshake deadline. It is longer
// than probeTimeout because the inner handshake travels through two tunnels
// (inner → outer → WARP → back), and the outer layer may still be finishing
// its own fallback probing / re-handshake when the inner device comes up.
// Real-world runs showed the inner handshake completing ~20s after "stacked
// configs" (11:41:20 → 11:41:40 in the first fully-successful session), so 5s
// was far too tight; 30s covers a full 112-candidate outer probe worst case.
const stackedHandshakeTimeout = 30 * time.Second

type StackedTunnel struct {
	outer *tunnel
	inner *tunnel

	outerRoutes *routeManager
	innerRoutes *routeManager

	// innerEpRow is the inner endpoint's /32 on-link route onto the OUTER
	// adapter — the one route that couples the two layers (see notes).
	innerEpRow windows.MibIpForwardRow2

	// link is the physical-link metric guard, restored by Down (like
	// Manager.Stop): drift can happen while the stack is up, after
	// NewStackedTunnel has returned.
	link *linkMetricGuard
}

// NewStackedTunnel brings up the outer tunnel first, then the inner tunnel whose
// endpoint is routed through the outer wintun adapter. outerCfg/innerCfg must
// use different WARP accounts and different InterfaceNames.
func NewStackedTunnel(ctx context.Context, outerCfg, innerCfg Config, onPhase func(string)) (*StackedTunnel, error) {
	// phase reports progress to the UI; nil-safe so callers may pass nil.
	phase := func(p string) {
		if onPhase != nil {
			onPhase(p)
		}
	}
	// MTU: defaults already set by BuildStacked (outer 1440 / inner 1360).
	// Only patch the inner up if a caller injected a custom outer MTU without
	// deriving its own inner value (inner must fit inside the outer: wire
	// overhead 60 + headroom 20).
	if innerCfg.MTU == 0 || innerCfg.MTU > outerCfg.MTU-80 {
		innerCfg.MTU = outerCfg.MTU - 80
	}
	if innerCfg.InterfaceName == "" {
		innerCfg.InterfaceName = "Xiaohe-inner"
	}

	// Physical-link metric guard, same as Manager.Start: snapshot the default-
	// route adapter's per-family metric and restore it on every exit path, so an
	// interrupted stacked connect can never leave the WLAN metric altered.
	link := newLinkMetricGuard()
	defer func() {
		if err := link.restore(); err != nil {
			logx.Errorf("[wgtun] link metric guard: %v", err)
		}
	}()

	s := &StackedTunnel{link: link}

	// ---- outer layer: one real adapter, endpoint hot-switched across candidates ----
	// Same architecture as Manager.Start (see the note there): the candidate
	// list comes first (cached/seed, no UDP burst), the wintun adapter is
	// created once, and the peer endpoint is hot-switched via UAPI. Concurrent
	// dummy-device handshakes are NOT used here either — they completed
	// handshakes the real tunnel could not reproduce, and their devices
	// competed with it for the same UDP 5-tuple/Cloudflare session.
	//
	// The OUTER layer only pins its endpoint onto the physical link. It must NOT
	// lower its metric, install a default route, or set DNS — otherwise its
	// default route would compete with the inner layer's. The inner endpoint's
	// /32 route (added below) is the only thing the outer adapter carries.
	//
	// The inner endpoint MUST be excluded from the outer pool: if both layers
	// land on the same UDP 5-tuple, every packet the inner layer sends to its
	// endpoint is captured by the outer /32 host route and loops inside the
	// outer tunnel (observed as mass "Failed to send data packets: short
	// buffer" on the outer peer and an inner handshake that never completes).
	cands, err := probeCandidates(ctx, outerCfg, innerCfg.Endpoint, false, phase)
	if err != nil {
		return nil, fmt.Errorf("wgtun: outer candidates: %w", err)
	}
	outerCfg.Endpoint = cands[0].Addr

	outer, err := New(outerCfg)
	if err != nil {
		return nil, fmt.Errorf("wgtun: outer tunnel: %w", err)
	}
	if err := outer.Up(); err != nil {
		_ = outer.Down()
		return nil, fmt.Errorf("wgtun: outer up: %w", err)
	}
	s.outer = outer
	phase("outer-handshake")

	// HARD GATE: the outer layer must complete its own handshake before the
	// inner endpoint's /32 route is pinned onto it — pinning onto a dead outer
	// tunnel black-holes the inner handshake. If every cached/seed candidate
	// fails, widen to the full-pool UDP sweep (known-live only) and retry those
	// on the same adapter.
	connectedOuter, err := handshakeAcross(outer, cands, handshakeTimeout)
	if err != nil && ctx.Err() == nil {
		logx.Infof("[wgtun] stacked: cached/seed outer candidates all failed (%v); running full sweep", err)
		swept, serr := probeCandidates(ctx, outerCfg, innerCfg.Endpoint, true, phase)
		if serr == nil {
			connectedOuter, err = handshakeAcross(outer, swept, handshakeTimeout)
		}
	}
	if err != nil {
		_ = outer.Down()
		return nil, fmt.Errorf("wgtun: outer handshake: %w", err)
	}
	outerCfg.Endpoint = connectedOuter

	outerRM := newRouteManager(outer.luid(), outerCfg.DNS)
	if err := outerRM.applyHostRouteOnly(connectedOuter); err != nil {
		_ = outer.Down()
		return nil, fmt.Errorf("wgtun: outer endpoint route: %w", err)
	}
	logOuterMetric(outer.luid())
	s.outerRoutes = outerRM

	// ---- inner layer: endpoint routed through the outer adapter ----
	inner, err := New(innerCfg)
	if err != nil {
		s.teardownOuter()
		return nil, fmt.Errorf("wgtun: inner tunnel: %w", err)
	}
	s.inner = inner

	innerRM := newRouteManager(inner.luid(), innerCfg.DNS)
	s.innerRoutes = innerRM // assign early so teardownInner reverts any route added below

	// Lower the inner adapter's metric so its default route (added later) wins.
	if err := innerRM.setInterfaceMetric(1); err != nil {
		_ = inner.Down()
		s.teardownOuter()
		return nil, fmt.Errorf("wgtun: inner metric: %w", err)
	}

	// Pin the inner endpoint onto the OUTER adapter. The next hop is the OUTER
	// adapter's own wintun address (outerCfg.IPv4), NOT on-link zero: an on-link
	// /32 to a point-to-point adapter has no neighbour for the destination, so
	// Windows won't route it. A concrete next hop (the outer wintun address)
	// pushes the inner endpoint's packets into the outer tunnel.
	innerEpIP, innerFamily, err := parseEndpointIP(innerCfg.Endpoint)
	if err != nil {
		_ = inner.Down()
		s.teardownOuter()
		return nil, err
	}
	prefixLen := uint8(32)
	if innerFamily == windows.AF_INET6 {
		prefixLen = 128
	}
	gwIP := net.ParseIP(outerCfg.IPv4)
	if innerFamily == windows.AF_INET6 {
		gwIP = net.ParseIP(outerCfg.IPv6)
	}
	if gwIP == nil {
		_ = inner.Down()
		s.teardownOuter()
		return nil, fmt.Errorf("wgtun: outer %s address missing for inner endpoint", familyName(innerFamily))
	}
	var nextHop windows.RawSockaddrInet
	if innerFamily == windows.AF_INET {
		nextHop = sockaddrInet4(gwIP.To4())
	} else {
		nextHop = sockaddrInet6(gwIP.To16())
	}
	innerEpRow := makeRoute(epSockaddr(innerEpIP, innerFamily), prefixLen, nextHop, outer.luid(), 0)
	if err := innerRM.add(innerEpRow); err != nil {
		_ = inner.Down()
		s.teardownOuter()
		return nil, fmt.Errorf("wgtun: inner endpoint route: %w", err)
	}
	s.innerEpRow = innerEpRow

	// Persist the stacked marker + inner endpoint route for crash recovery.
	ifIndex, _ := convertInterfaceLuidToIndex(outer.luid())
	if err := markStackedState(innerEpState{
		Dst:     innerEpIP.String(),
		Gateway: gwIP.String(),
		LUID:    outer.luid(),
		IfIndex: ifIndex,
		Family:  innerFamily,
	}); err != nil {
		logx.Warnf("[wgtun] state: mark stacked failed: %v", err)
	}

	// Bring the inner device up ONLY AFTER its endpoint route is installed, so
	// the very first handshake packet already travels inside the outer tunnel
	// (up-before-route leaked the first packet out the physical NIC and the
	// handshake never completed).
	if err := inner.Up(); err != nil {
		s.teardownInner()
		s.teardownOuter()
		return nil, fmt.Errorf("wgtun: inner up: %w", err)
	}

	phase("inner-handshake")
	if err := inner.WaitHandshake(stackedHandshakeTimeout); err != nil {
		s.teardownInner()
		s.teardownOuter()
		return nil, fmt.Errorf("wgtun: inner handshake: %w", err)
	}
	phase("route-flip")
	if err := innerRM.ApplyDefaultRoutes(); err != nil {
		s.teardownInner()
		s.teardownOuter()
		return nil, err
	}
	if err := innerRM.ApplyDNS(); err != nil {
		s.teardownInner()
		s.teardownOuter()
		return nil, err
	}

	phase("up")
	logx.Infof("[wgtun] stacked up: outer=%s inner=%s (inner endpoint via outer ifIndex %d)",
		outerCfg.Endpoint, innerCfg.Endpoint, ifIndex)
	return s, nil
}

// Down tears the inner layer down first (revert its routes/metric/DNS, close the
// inner device), then the outer layer via the existing Revert. Idempotent: Revert
// treats already-absent routes as success, so a second Down is a no-op.
func (s *StackedTunnel) Down() error {
	var errs []error

	if s.innerRoutes != nil {
		if err := s.innerRoutes.Revert(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.inner != nil {
		if err := s.inner.Down(); err != nil {
			errs = append(errs, err)
		}
	}

	if s.outerRoutes != nil {
		if err := s.outerRoutes.Revert(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.outer != nil {
		if err := s.outer.Down(); err != nil {
			errs = append(errs, err)
		}
	}

	// Physical-link metric last, for the same reason as Manager.Stop.
	if s.link != nil {
		if err := s.link.restore(); err != nil {
			errs = append(errs, err)
		}
		s.link = nil
	}

	return errors.Join(errs...)
}

// Stats returns per-layer transmit/receive byte counters, so the data plane can
// be proven to move on BOTH layers (handshake success alone is not proof).
func (s *StackedTunnel) Stats() (outerTx, outerRx, innerTx, innerRx uint64) {
	if s.outer != nil {
		outerTx, outerRx = s.outer.stats()
	}
	if s.inner != nil {
		innerTx, innerRx = s.inner.stats()
	}
	return
}

// teardownInner reverts the inner layer only (best-effort, used on partial setup).
func (s *StackedTunnel) teardownInner() {
	if s.innerRoutes != nil {
		_ = s.innerRoutes.Revert()
	}
	if s.inner != nil {
		_ = s.inner.Down()
	}
}

// teardownOuter reverts the outer layer only (best-effort, used on partial setup).
func (s *StackedTunnel) teardownOuter() {
	if s.outerRoutes != nil {
		_ = s.outerRoutes.Revert()
	}
	if s.outer != nil {
		_ = s.outer.Down()
	}
}

// markStackedState flags the on-disk state file as stacked and records the inner
// endpoint route, so recoverFromState can clear it first after a hard kill.
func markStackedState(ep innerEpState) error {
	st, err := readStateFile()
	if err != nil {
		return err
	}
	st.Stacked = true
	st.InnerEp = ep
	return writeStateFile(st)
}

// logOuterMetric prints the OUTER adapter's current per-family interface metric,
// to prove the outer layer did NOT lower it (it must stay at the adapter default
// so it never competes with the inner layer's metric=1 default route).
func logOuterMetric(luid uint64) {
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		var cur windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&cur)
		cur.Family = family
		cur.InterfaceLuid = luid
		if err := getIpInterfaceEntry(&cur); err == nil {
			logx.Infof("[wgtun] outer metric family=%d metric=%d auto=%d", family, cur.Metric, cur.UseAutomaticMetric)
		} else {
			logx.Infof("[wgtun] outer metric family=%d: no entry (%v)", family, err)
		}
	}
}

// fastestCachedEndpoint returns the cached endpoint with the smallest lastRttMs,
// falling back to the first pooled candidate when the cache is empty.
func fastestCachedEndpoint() string {
	if addrs := loadCache().orderedAddrs(); len(addrs) > 0 {
		return addrs[0]
	}
	if c := buildCandidates(""); len(c) > 0 {
		return c[0]
	}
	return ""
}

// BuildStacked assembles the two Configs for warp-in-warp: the OUTER identity
// comes from aether.toml (LoadIdentity), the INNER from a freshly registered
// account file (LoadAccount). The outer endpoint is the fastest cached one; the
// inner endpoint is the first pooled candidate that differs from it. Purely
// offline (reads files only, no system mutation), so it is unit-testable.
func BuildStacked(configDir, accountPath string) (outerCfg, innerCfg Config, err error) {
	outerCfg, err = LoadIdentity(configDir, "")
	if err != nil {
		return Config{}, Config{}, fmt.Errorf("wgtun: outer identity: %w", err)
	}

	outerCfg.Endpoint = fastestCachedEndpoint()
	if outerCfg.Endpoint == "" {
		return Config{}, Config{}, fmt.Errorf("wgtun: no outer endpoint (cache empty and no pool)")
	}

	acc, err := LoadAccount(accountPath)
	if err != nil {
		return Config{}, Config{}, fmt.Errorf("wgtun: inner account: %w", err)
	}
	innerCfg = acc.toConfig("")
	innerCfg.Endpoint = innerEndpoint(outerCfg.Endpoint)
	innerCfg.InterfaceName = "Xiaohe-inner"
	// MTU: outer rides the wire at 1440 (physical 1500 - 60 outer WG/UDP/IP
	// overhead; DF-verified), inner rides inside the outer at 1440 - 80.
	if outerCfg.MTU <= 1280 {
		outerCfg.MTU = 1440
	}
	innerCfg.MTU = outerCfg.MTU - 80

	logx.Infof("[wgtun] stacked configs: outer=%s (account from aether.toml) inner=%s (account %s)",
		outerCfg.Endpoint, innerCfg.Endpoint, AccountFingerprint(acc))
	return outerCfg, innerCfg, nil
}

// innerEndpoint picks a pooled endpoint that differs from the outer one, so the
// two layers land on different Cloudflare anycast IPs.
func innerEndpoint(outerEp string) string {
	for _, ep := range buildCandidates("") {
		if ep != outerEp {
			return ep
		}
	}
	return "162.159.192.7:2408"
}

// excludeEndpoint filters ep out of cands, preserving order. Used to keep the
// outer probe pool from selecting the inner layer's endpoint, which would put
// both wireguard layers on one UDP 5-tuple (routing loop, see runStacked).
func excludeEndpoint(cands []string, ep string) []string {
	if ep == "" {
		return cands
	}
	out := make([]string, 0, len(cands))
	for _, c := range cands {
		if c != ep {
			out = append(out, c)
		}
	}
	return out
}
