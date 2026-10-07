//go:build wgtun

package wgtun

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
)

// cfIPv4Prefixes are the WARP /24 prefixes the reference scanner (E:\warp) probes
// with full /24 coverage and which it has proven live on this host (96 Mbps
// connects). It deliberately omits the 8.x segments that warpscout's pools.go
// listed — those drifted out of the live WARP pool, while 162.159.x / 188.114.x
// still carry the endpoints that both the Aether core and the reference scanner
// connect through.
var cfIPv4Prefixes = []string{
	"162.159.192", "162.159.193", "162.159.195",
	"188.114.96", "188.114.97", "188.114.98", "188.114.99",
}

// warpPorts is the set of official WARP UDP ports (same 54-port set as the
// reference's all54OfficialPorts). It is the pool used for host%54 sampling: each
// /24's 254 hosts get a spread of all 54 ports instead of a single fixed port.
// Ordering only matters for the seed/cache-priority tail; the live probe walks
// the full pool via the UDP liveness pre-probe, not serially.
var warpPorts = []int{
	4500, 2408, 500, 1701, // original 4, priority order preserved
	// remaining official ports (same set as reference all54OfficialPorts):
	854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
	943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074,
	1180, 1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233,
	5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
}

// cfProbePacket is Cloudflare WARP's stateless endpoint liveness probe (64
// bytes). A live WARP endpoint answers it with a 5-byte marker
// (0xcf 00 00 00 00) regardless of account/key, so it separates live endpoints
// from dead/drifted ones without a WireGuard device, key, or reserved bytes.
var cfProbePacket = []byte{
	0x04, 0x67, 0x27, 0x31, 0x72, 0x3f, 0x14, 0x62, 0xbc, 0xf5, 0xb7, 0x28, 0xae, 0xca, 0x31, 0x13,
	0x63, 0xf8, 0xd0, 0xc3, 0x49, 0x97, 0x4a, 0x6c, 0x70, 0x48, 0x11, 0xbe, 0x99, 0x70, 0x19, 0x1d,
	0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0xed, 0x1b,
	0xed, 0x21, 0x65, 0x69, 0x02, 0xb9, 0xd8, 0xf3, 0xc2, 0xbd, 0x7d, 0x98, 0xda,
}

// liveEndpoint is an endpoint that passed the strict UDP liveness probe. Speed is
// the RTT-derived estimate used only to order the handshake sweep (fastest
// first); the real throughput is measured later once the tunnel is up.
type liveEndpoint struct {
	Addr    string
	Latency int64
	Speed   float64
}

// buildCandidates returns the ordered endpoint candidate list for a connect: the
// seed (.conf pinned endpoint) first, then the cached endpoints (fastest first),
// then the full WARP pool — every host of every /24 prefix, each host mapped to
// one of the 54 ports by host%54 (the reference scanner's strategy). Probing is
// "first handshake wins", but the live probe screens this whole pool with a cheap
// concurrent UDP liveness pre-probe before any handshake, so the serial cost of
// enumerating ~2032 candidates is borne by stateless UDP, not by handshakes.
func buildCandidates(seed string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(ep string) {
		if ep == "" || seen[ep] {
			return
		}
		seen[ep] = true
		out = append(out, ep)
	}

	if seed != "" {
		add(seed)
	}

	// Cached endpoints (fastest first) jump ahead of the cold pool probe. They
	// are still handshake-verified — this only sets priority.
	for _, ep := range loadCache().orderedAddrs() {
		add(ep)
	}

	for _, ep := range poolAddresses() {
		add(ep)
	}
	return out
}

// poolAddresses returns the endpoints this build's candidate pool GENERATES:
// every host of every /24 prefix at its host%54 port. It is what buildCandidates
// draws on, minus the seed and the cache-injected entries — i.e. exactly the set
// a sweep can ever propose. endpointCache.pruneOutOfPool uses it to tell "an
// endpoint the pool still reaches" from "an address from an older prefix list or
// an older port mapping, which no sweep will ever offer again".
func poolAddresses() []string {
	portCount := len(warpPorts)
	out := make([]string, 0, len(cfIPv4Prefixes)*254)
	for _, prefix := range cfIPv4Prefixes {
		for host := 1; host <= 254; host++ {
			out = append(out, fmt.Sprintf("%s.%d:%d", prefix, host, warpPorts[host%portCount]))
		}
	}
	return out
}

// udpProbeTimeout is the per-round deadline for a single UDP liveness probe. A
// dead endpoint fails the first round and returns immediately; a live endpoint
// answers in ~100-200ms, so three rounds complete well under this.
const udpProbeTimeout = 800 * time.Millisecond

// probeEndpointStrict runs the strict 3-round, 0-loss liveness probe against one
// endpoint. It returns the average RTT (ms), an RTT-derived speed estimate, and
// ok=true only if all three rounds got the 0xcf marker back. This is the same
// gate the reference scanner uses: a single dropped probe round rejects the
// endpoint, which filters out the "fake-live" endpoints a handshake would waste
// its timeout on.
func probeEndpointStrict(addr string, timeout time.Duration) (int64, float64, bool) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, 0, false
	}
	conn, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		return 0, 0, false
	}
	defer conn.Close()

	const rounds = 3
	var total, min, max int64
	min = 9999
	for i := 0; i < rounds; i++ {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		start := time.Now()
		if _, err := conn.Write(cfProbePacket); err != nil {
			return 0, 0, false
		}
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil || n < 5 || buf[0] != 0xcf || buf[1] != 0 || buf[2] != 0 || buf[3] != 0 || buf[4] != 0 {
			return 0, 0, false
		}
		rtt := time.Since(start).Milliseconds()
		if rtt == 0 {
			rtt = 1
		}
		total += rtt
		if rtt < min {
			min = rtt
		}
		if rtt > max {
			max = rtt
		}
		time.Sleep(15 * time.Millisecond)
	}

	avg := total / rounds
	jitter := max - min
	speed := (1000.0/float64(avg))*14.8 - float64(jitter)*0.35
	if speed < 15.0 {
		speed = 18.0 + float64(time.Now().UnixNano()%10)
	}
	if speed > 180.0 {
		speed = 180.0
	}
	return avg, speed, true
}

// udpProbeWorkers bounds the concurrent UDP liveness probes. 24 workers sweep a
// ~2032-endpoint pool in well under a minute because each probe is a single
// stateless round-trip (a dead endpoint costs one 800ms timeout, not a full
// handshake). It was lowered from 50: 50 concurrent 3-round UDP probes produced
// a burst heavy enough to trip consumer router/ISP UDP rate-limiting and drop
// the user's whole link mid-connect (observed 2026-10-04), while 24 keeps the
// sweep fast enough to beat WARP endpoint drift without saturating the link.
const udpProbeWorkers = 24

// fastPathProbeWorkers bounds concurrency for the fast-path (cached/seed)
// liveness pre-screen. Deliberately far below udpProbeWorkers: this runs on
// EVERY reconnect, so it has to stay indistinguishable from idle background
// chatter — the 2026-10-04 incident (a 24-worker sweep visibly rate-limiting
// the user's whole link mid-connect) must not be reproducible by something
// this frequent. With typically ≤10 cached candidates the cap rarely binds.
const fastPathProbeWorkers = 8

// fastPathRetryDelay is how long the fast path waits before re-probing the same
// cached/seed endpoints when ALL of them came back dead. The probe demands three
// rounds with ZERO loss, so one short loss spike condemns the whole batch at
// once — and that happens most often right at connect start, immediately after a
// disconnect or an app restart (observed 2026-10-05: an all-dead fast path was
// followed ~1s later by a sweep finding 934/1781 alive, and an endpoint the fast
// path had just declared dead went on to handshake successfully). 2s is nothing
// against the ~57s a full sweep costs, and it is skipped entirely when the
// connect has been cancelled.
const fastPathRetryDelay = 2 * time.Second

// failoverPorts are the ports tried against the SAME host when an endpoint
// dies. Port matters as much as host: observed 2026-10-04, one host was stable
// for 24 minutes at 250 Mbps on :2408 while its neighbours on :500 died within
// a minute. 2408 first (the observed-stable one), then 500, then the two
// remaining "classic" WARP ports.
var failoverPorts = []int{2408, 500, 4500, 1701}

// portVariants returns the same host on the failover ports, dropping the
// current address and anything in avoid. It is the cheapest failover move: same
// IP, different port, no new host to find.
func portVariants(current string, avoid map[string]bool) []string {
	host, _, err := net.SplitHostPort(current)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(failoverPorts))
	for _, p := range failoverPorts {
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		if addr == current || avoid[addr] {
			continue
		}
		out = append(out, addr)
	}
	return out
}

// failoverCandidates builds the ordered list of endpoints to try when the
// current one dies. Cheapest and most likely first:
//
//  1. the same host on the other failover ports (the host is known reachable,
//     only its port got blocked);
//  2. cached endpoints, fastest first (proven on this machine);
//  3. a spread sample of the cold pool, so a failover never has to wait for a
//     full sweep.
//
// It never returns current, and skip lists everything already tried this cycle.
func failoverCandidates(current string, skip map[string]bool, limit int) []string {
	seen := map[string]bool{current: true}
	for k := range skip {
		seen[k] = true
	}
	var out []string
	add := func(ep string) {
		if ep == "" || seen[ep] || (limit > 0 && len(out) >= limit) {
			return
		}
		seen[ep] = true
		out = append(out, ep)
	}

	for _, ep := range portVariants(current, seen) {
		add(ep)
	}
	for _, ep := range loadCache().orderedAddrs() {
		add(ep)
	}
	if limit > 0 && len(out) >= limit {
		return out
	}
	// Stride-sample the pool so the sample spans every /24 instead of the first
	// prefix only.
	pool := buildCandidates("")
	if len(pool) == 0 {
		return out
	}
	stride := len(pool) / (limit + 1)
	if stride < 1 {
		stride = 1
	}
	for i := 0; i < len(pool) && (limit <= 0 || len(out) < limit); i += stride {
		add(pool[i])
	}
	return out
}

// handshakeTimeout is the per-endpoint handshake deadline on the real tunnel.
// 14s matches the reference scanner: WireGuard's first initiation can be
// dropped, and the peer only answers the retry at RekeyTimeout=5s; 6s was
// observed to kill good endpoints before that retry fired (30/30 loss on a
// high-loss network) — but 6s is still used for cached/seed candidates on
// purpose, where failing fast is worth more than a marginal hit rate, because
// a stale cache entry should hand over to the sweep as soon as possible.
const handshakeTimeout = 14 * time.Second

// maxHandshakeCandidates caps how many endpoints are tried per connect. The
// reference verifies its top 12; more is diminishing returns because a connect
// that found 20+ live endpoints almost always handshakes within the top
// handful.
const maxHandshakeCandidates = 12

// cachedCandidates returns the seed plus cached endpoints, fastest-cache-first:
// endpoints that proved good on a previous run are tried before anything else,
// so a normal reconnect never emits the full-pool UDP sweep (whose burst
// rate-limited the user's whole link on 2026-10-04).
func cachedCandidates(seed, exclude string) []liveEndpoint {
	seen := make(map[string]bool)
	var out []liveEndpoint
	// Priority: the operator's pinned seed, then the last-known-good endpoint
	// (the one that just carried a full verified session — handshake AND
	// data-plane), then the remaining cached endpoints by historical handshake
	// success. LastGood leads because it is the ONLY candidate whose data plane
	// is known to have worked recently; the rest are handshake-ranked only.
	c := loadCache()
	ordered := append([]string{seed, c.LastGood}, c.orderedAddrs()...)
	for _, ep := range ordered {
		if ep == "" || seen[ep] || (exclude != "" && ep == exclude) {
			continue
		}
		seen[ep] = true
		out = append(out, liveEndpoint{Addr: ep})
	}
	return out
}

// probeCandidates ranks endpoints WITHOUT handshaking: cached/seed endpoints
// first (fast path, zero UDP burst), and only when the caller reports those all
// failed does it fall back to the strict full-pool UDP liveness sweep.
// Handshaking is left to the real tunnel (single WireGuard device, hot-switched
// endpoints): running several throwaway devices concurrently was observed to
// complete handshakes the real tunnel then could not reproduce.
// probeCandidates returns (candidates, fromSweep, error). fromSweep tells the
// caller whether the list came from the cheap cached/seed pre-screen or from the
// full-pool UDP sweep — the caller needs that to pick a handshake deadline:
// cached/seed entries get the short one (a stale entry should fail fast and hand
// over to the sweep), swept entries are already known-live and get the full one.
// Conflating the two is how swept candidates ended up with the 6s deadline meant
// for stale cache entries (2026-10-05).
func probeCandidates(ctx context.Context, cfg Config, exclude string, useSweep bool, onPhase func(string)) ([]liveEndpoint, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if !useSweep {
		quick := cachedCandidates(cfg.Endpoint, exclude)
		if len(quick) > 0 {
			// Cheap pre-screen BEFORE paying handshake timeouts. The fast path
			// used to hand these candidates straight to handshakeAcross, so a
			// stale cache cost a full 6s timeout per dead candidate — 6-10
			// entries meant 36-60s of nothing before the full sweep even
			// started (the "2-4 minute connect"). WARP answers the stateless
			// liveness probe regardless of account or key, so filtering costs
			// one 3-round exchange per candidate instead of a handshake
			// timeout (~150ms when live, one 800ms timeout when dead — and in
			// parallel), and it comes back RANKED, so the handshake starts
			// with the best candidate rather than the oldest cache entry.
			//
			// No survivors must fall THROUGH to the sweep below, not return an
			// error: Start treats an error from here as fatal and would skip
			// the sweep entirely, turning a stale cache into a dead connect.
			addrs := make([]string, 0, len(quick))
			for _, ep := range quick {
				addrs = append(addrs, ep.Addr)
			}
			// No onPhase labels here: the pre-screen is sub-second and the
			// UI's "scan n/total" wording is the full-sweep's progress. Silence
			// keeps a healthy reconnect looking exactly like it used to.
			live := filterLiveStrictFn(ctx, addrs, fastPathProbeWorkers, nil)
			// P5.3: the 2s retry only earns its keep when the Healthy Pool is non-empty
			// (a verified endpoint going quiet is plausibly one loss spike). When the
			// pool holds only Fresh/Suspect entries, a dead liveness is more likely a
			// genuinely dead endpoint — skip the retry and go straight to discovery.
			if len(live) == 0 && ctx.Err() == nil && !loadCache().needsDiscovery() {
				// Everything dead at once is far more likely one loss spike than
				// eight simultaneous deaths, and the probe rejects on a single
				// lost round. Pay 2s and re-ask before paying ~57s for a sweep.
				select {
				case <-time.After(fastPathRetryDelay):
				case <-ctx.Done():
					return nil, false, ctx.Err()
				}
				live = filterLiveStrictFn(ctx, addrs, fastPathProbeWorkers, nil)
				if len(live) > 0 {
					logx.Infof("[wgtun] fast path: retry after %v recovered %d/%d cached/seed endpoints",
						fastPathRetryDelay, len(live), len(quick))
				}
			}
			if len(live) > 0 {
				logx.Infof("[wgtun] fast path: %d/%d cached/seed endpoints answered the liveness probe", len(live), len(quick))
				// P4.2: LastGood is the absolute-first real handshake candidate on the
				// warm path. orderHandshakeCandidates ranks by historical successRate,
				// which would otherwise let a longer-track-record endpoint handshake
				// ahead of the one that most recently carried a full verified session.
				return lastGoodFirst(orderHandshakeCandidates(live)), false, nil
			}
			logx.Infof("[wgtun] fast path: none of the %d cached/seed endpoints answered; falling through to the full sweep", len(quick))
		}
	}
	candidates := buildCandidates(cfg.Endpoint)
	if exclude != "" {
		candidates = excludeEndpoint(candidates, exclude)
	}
	live := filterLiveStrictFn(ctx, candidates, udpProbeWorkers, onPhase)
	if len(live) == 0 {
		return nil, true, fmt.Errorf("no endpoint answered the liveness probe (checked %d candidates)", len(candidates))
	}
	logx.Infof("[wgtun] %d/%d endpoints answered the liveness probe", len(live), len(candidates))
	// Order BEFORE truncating: the top-N must be the N most likely to handshake,
	// not merely the N fastest to answer a probe.
	live = orderHandshakeCandidates(live)
	if len(live) > maxHandshakeCandidates {
		live = live[:maxHandshakeCandidates]
	}
	return live, true, nil
}

// probeCandidatesFn is the injectable seam for endpoint discovery (overridden in
// tests so the full sweep can be faked without hitting the network).
var probeCandidatesFn = probeCandidates

// filterLiveStrictFn is the injectable seam for the liveness pre-screen
// (overridden in tests so the P5.3 sweep-trigger logic — "Healthy Pool empty →
// skip the 2s fast-path retry" — can be exercised offline without UDP).
var filterLiveStrictFn = filterLiveStrict

// orderHandshakeCandidates ranks candidate endpoints for the real-tunnel
// handshake. The UDP liveness probe says an endpoint ANSWERS; it says nothing
// about whether it will accept THIS identity's handshake — on 2026-10-05 every
// one of 12 probe-live candidates was tried, the first 8 timed out, and only
// the 9th (a historically proven one) connected. So historical handshake
// outcome leads, and the probe's own measurements (speed, then latency) only
// break ties, followed by the cached RTT. Endpoints absent from the cache get
// the neutral prior via a zero-value entry, and Addr is the final tie-break so
// the order is deterministic (stable logs, testable).
func orderHandshakeCandidates(eps []liveEndpoint) []liveEndpoint {
	if len(eps) < 2 {
		return eps
	}
	cache := loadCache()
	hist := make(map[string]endpointEntry, len(cache.Endpoints))
	for _, e := range cache.Endpoints {
		hist[e.Addr] = e
	}
	// P5.2: the Healthy Pool sorts by adaptive quality (stability + freshness +
	// validation + reliability + latency + speed), not by successRate alone. The
	// liveness probe's own speed/latency remain tie-breaks below the quality key.
	now := time.Now()
	sort.Slice(eps, func(i, j int) bool {
		hi, hj := hist[eps[i].Addr], hist[eps[j].Addr]
		if si, sj := hi.qualityScore(now), hj.qualityScore(now); si != sj {
			return si > sj
		}
		if eps[i].Speed != eps[j].Speed {
			return eps[i].Speed > eps[j].Speed
		}
		if eps[i].Latency != eps[j].Latency {
			return eps[i].Latency < eps[j].Latency
		}
		if hi.LastRttMs != hj.LastRttMs {
			return hi.LastRttMs < hj.LastRttMs
		}
		return eps[i].Addr < eps[j].Addr
	})
	return eps
}

// lastGoodFirst moves the persisted last-known-good endpoint to the FRONT of a
// ranked candidate list, so the real tunnel handshakes it FIRST regardless of
// its historical successRate. This is P4.2: before, LastGood only led the
// liveness pre-screen (cachedCandidates) and then lost that lead to
// orderHandshakeCandidates' successRate sort — an endpoint with a longer good
// track record could handshake ahead of the one that most recently carried a
// full verified session.
//
// It is a pure reorder, not a promotion of an unverified address: the endpoint
// must already be in the list (it survived liveness), and everything else keeps
// its relative order. If LastGood is absent (excluded, dead on liveness, or not
// yet cached) or already first, the list is returned unchanged.
func lastGoodFirst(eps []liveEndpoint) []liveEndpoint {
	lg := loadCache().LastGood
	if lg == "" || len(eps) < 2 {
		return eps
	}
	for i, e := range eps {
		if e.Addr != lg {
			continue
		}
		if i == 0 {
			return eps // already first
		}
		out := make([]liveEndpoint, 0, len(eps))
		out = append(out, e)
		out = append(out, eps[:i]...)
		out = append(out, eps[i+1:]...)
		return out
	}
	return eps
}

// filterLiveStrict screens the candidate pool with the strict UDP liveness probe,
// returning the surviving endpoints sorted by speed estimate descending (fastest
// first). It is concurrent (bounded by workers) and checks ctx at the enqueue
// boundary, so a cancelled connect stops scheduling and returns whatever is
// already known. Callers pick the concurrency — the full-pool sweep wants
// udpProbeWorkers for speed, the per-reconnect fast-path pre-screen wants the
// much smaller fastPathProbeWorkers. onPhase, when non-nil, receives throttled
// progress labels.
func filterLiveStrict(ctx context.Context, candidates []string, workers int, onPhase func(string)) []liveEndpoint {
	if len(candidates) == 0 {
		return nil
	}
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	results := make([]liveEndpoint, 0, len(candidates)/10)
	var mu sync.Mutex
	var done int64
	total := int64(len(candidates))
	var wg sync.WaitGroup

	for _, ep := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ep string) {
			defer wg.Done()
			defer func() { <-sem }()
			lat, speed, ok := probeEndpointStrict(ep, udpProbeTimeout)
			if ok {
				mu.Lock()
				results = append(results, liveEndpoint{Addr: ep, Latency: lat, Speed: speed})
				mu.Unlock()
			}
			n := atomic.AddInt64(&done, 1)
			if onPhase != nil && (n == 1 || n == total || n%200 == 0) {
				onPhase(fmt.Sprintf("scan %d/%d", n, total))
			}
		}(ep)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Speed == results[j].Speed {
			return results[i].Latency < results[j].Latency
		}
		return results[i].Speed > results[j].Speed
	})
	return results
}
