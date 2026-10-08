//go:build wgtun

package wgtun

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// endpointCache persists which endpoints worked and how fast they were, so the
// next connect can try the proven-fast endpoints first instead of re-probing the
// whole pool cold. Cached endpoints are still handshake-probed every time (they
// just get top priority) — the cache is a hint, never a blind trust.
type endpointCache struct {
	Version   int             `json:"version"`
	Endpoints []endpointEntry `json:"endpoints"`
	// LastPruned is when the out-of-pool sweep last ran (see pruneOutOfPool).
	// Zero value means "never", so an existing cache file gets one prune pass
	// on the next connect and then at most one per pruneInterval.
	LastPruned time.Time `json:"lastPruned"`
	// LastGood is the single most recent endpoint that carried a REAL
	// production session all the way to Connected — real handshake, route
	// takeover, AND data-plane verification all succeeded (recordLastGood).
	// It is distinct from SuccessCount: a handshake success that then
	// black-holes transport (drifted endpoint) still bumps SuccessCount via
	// recordAttempt, but it must NEVER become LastGood, or the next connect
	// would fast-path onto a tunnel that cannot carry traffic.
	LastGood   string    `json:"lastGood,omitempty"`
	LastGoodAt time.Time `json:"lastGoodAt,omitempty"`
}

// pruneInterval is the minimum gap between two out-of-pool cache sweeps. The
// sweep has to materialise the whole generated pool (~2032 addresses), which is
// fine once a day at connect time and wasteful on every lookup.
const pruneInterval = 24 * time.Hour

// pruneOutOfPool drops cached endpoints that this build's candidate pool can no
// longer generate, reporting how many went and whether it actually ran (the
// caller must save when it did, so the timestamp persists).
//
// Why this exists: the pool is derived from cfIPv4Prefixes with a host%54 port,
// so any address cached under an older prefix list or an older port mapping can
// never be proposed by a sweep again — it just sits in the cache and gets
// probed on every single connect. On 2026-10-05 five of the eight fast-path
// candidates were exactly that (three 8.x addresses from before those segments
// drifted out of the pool, plus two whose port no longer matches their host).
//
// The seed is always kept: it is the operator's pinned endpoint, it does not
// have to be in the generated pool to be worth trying.
func (c *endpointCache) pruneOutOfPool(seed string) (removed int, ran bool) {
	if time.Since(c.LastPruned) < pruneInterval {
		return 0, false
	}
	c.LastPruned = time.Now()
	reachable := make(map[string]bool, len(cfIPv4Prefixes)*254+1)
	if seed != "" {
		reachable[seed] = true
	}
	for _, ep := range poolAddresses() {
		reachable[ep] = true
	}
	out := c.Endpoints[:0]
	for _, e := range c.Endpoints {
		if reachable[e.Addr] {
			out = append(out, e)
			continue
		}
		removed++
	}
	if removed > 0 {
		c.Endpoints = out
	}
	return removed, true
}

type endpointEntry struct {
	Addr         string    `json:"addr"`
	LastRttMs    int64     `json:"lastRttMs"`
	SuccessCount int       `json:"successCount"`
	FailCount    int       `json:"failCount"`
	LastUsed     time.Time `json:"lastUsed"`
	// Attempts: real-tunnel handshake attempts recorded against this endpoint,
	// successes INCLUDED — the denominator of successRate. Added 2026-10-05, so
	// entries written by older builds have no value here and JSON-decode to 0;
	// successRate falls back to SuccessCount for those, i.e. "every attempt we
	// know of worked", which is exactly what those builds recorded.
	Attempts int `json:"attempts"`

	// P5.1 quality fields. All omitempty + zero-value on legacy decode, so a
	// version-1 cache loads losslessly and none of these are forged. They are
	// COLLECTED here but NOT yet consulted by any ordering/selection code (see
	// the P5.1 freeze note in endpoints.go): the candidate order is unchanged.
	FirstSeen        time.Time `json:"firstSeen,omitempty"`        // first time this addr entered the cache
	LastHandshakeMs  int64     `json:"lastHandshakeMs,omitempty"`  // last REAL handshake elapsed (ms)
	DataPlaneSuccess int       `json:"dataPlaneSuccess,omitempty"` // data-plane verified count
	DataPlaneFail    int       `json:"dataPlaneFail,omitempty"`    // data-plane failure count
	ConsecDPFail     int       `json:"consecDPFail,omitempty"`     // consecutive data-plane failures
	LastSpeedMbps    float64   `json:"lastSpeedMbps,omitempty"`    // last measured throughput
	SpeedSampleAt    time.Time `json:"speedSampleAt,omitempty"`    // when LastSpeedMbps was last sampled
	LastDataPlaneOK  time.Time `json:"lastDataPlaneOK,omitempty"`  // last data-plane success time
	LastSeen         time.Time `json:"lastSeen,omitempty"`         // last liveness/verification observation
}

const (
	cacheFileVersion = 2
	// failThreshold is how many consecutive failures it takes to evict an
	// endpoint from the cache.
	failThreshold = 3
)

func cacheFilePath() string {
	return filepath.Join(stateDir, "endpoints.json")
}

func loadCache() endpointCache {
	raw, err := os.ReadFile(cacheFilePath())
	if err != nil {
		return endpointCache{Version: cacheFileVersion}
	}
	var c endpointCache
	if err := json.Unmarshal(raw, &c); err != nil {
		return endpointCache{Version: cacheFileVersion}
	}
	return c
}

func (c *endpointCache) save() {
	c.Version = cacheFileVersion
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(cacheFilePath(), raw, 0o600)
}

// successRate is the Laplace-smoothed ratio of past handshake successes to
// attempts: (successes+1)/(attempts+2).
//
// Smoothing is what makes this usable as a RANKING instead of a coin flip:
//   - a never-tried endpoint scores 0.5 (neutral prior) rather than 0, so an
//     unproven endpoint is not treated as a known-bad one;
//   - an endpoint that succeeded once scores 0.67, not 1.0, so it cannot
//     outrank an endpoint with a long good track record forever;
//   - conversely one failure (0.33) demotes without banning.
//
// This metric exists because probe liveness and handshake success turned out to
// be DIFFERENT things: on 2026-10-05 all 12 probe-live candidates were tried
// and the first 8 timed out; the 9th — which had worked before — connected.
// RTT cannot predict that, past outcomes can.
func (e endpointEntry) successRate() float64 {
	attempts := e.Attempts
	if attempts < e.SuccessCount {
		attempts = e.SuccessCount // legacy entry: only successes were recorded
	}
	return float64(e.SuccessCount+1) / float64(attempts+2)
}

// ---------------------------------------------------------------------------
// P5.2 endpoint quality model.
//
// A deterministic, explainable 0-100 score decomposed into six weighted
// components. It REPLACES the successRate-only ordering of the Healthy Pool, but
// it NEVER overrides LastGood absolute-first (lastGoodFirst runs after ordering)
// and it NEVER evicts or judges an endpoint dead — those stay P5.3's job.
//
// Weighting order of importance: stability (long-term) and validation
// (data-plane proven) dominate; freshness, handshake reliability, latency and
// finally speed fill in the rest. Speed is deliberately the smallest weight so a
// fast-but-short-lived node can never outrank a long-stable one.
// ---------------------------------------------------------------------------

// The speed weight is the highest a verified-throughput score can reach while
// still keeping the core P5 invariant (TestStableBeatsFastShortLived): a
// long-stable but slow endpoint must outrank a fast but just-created one. The
// stability side (validation + stability + reliability) must outweigh a full
// speed score by enough margin — raising speed above ~15 lets a one-sample
// fast-but-short-lived node flip the ordering, which is exactly the failure the
// 2026-10-05 quality model was built to prevent.
const (
	qualityValidationWeight  = 25.0 // data-plane verified vs handshake-only vs liveness-only
	qualityStabilityWeight   = 25.0 // long-term stability (repeated data-plane success + lifetime)
	qualityFreshnessWeight   = 12.0 // recency of last data-plane success (half-life decay)
	qualityReliabilityWeight = 12.0 // Laplace-smoothed handshake success rate
	qualityLatencyWeight     = 6.0  // real handshake latency
	qualitySpeedWeight       = 15.0 // measured throughput (log-scaled; dominant among verified peers)
)

// endpointQualityHalfLife is the freshness half-life: a data-plane success ages
// to half its freshness contribution after this long.
const endpointQualityHalfLife = 24 * time.Hour

// Reference points that map a quality field to the bottom/top of its component.
const (
	qualityLatencyRefMs = 6000.0 // LastHandshakeMs at which latencyScore → 0
	// Speed is mapped on a LOG scale between two reference points, so a 20x
	// throughput gap (10 vs 200 Mbps) is not collapsed into a single linear
	// clamp the way a flat Mbps/50 did (which made every 50+ Mbps endpoint
	// score identical). Low/high anchor the curve: at or below Low → 0, at or
	// above High → full component weight.
	qualitySpeedRefLowMbps  = 5.0
	qualitySpeedRefHighMbps = 200.0
)

// validationScore rewards an endpoint whose DATA PLANE was actually verified,
// distinctly above one that only handshaked, and above one only seen by liveness.
// It never zeroes an unproven endpoint: a fresh node must be allowed to enter the
// observation pool.
func (e endpointEntry) validationScore() float64 {
	if e.DataPlaneSuccess > 0 {
		return qualityValidationWeight
	}
	if e.SuccessCount > 0 {
		return qualityValidationWeight * 0.5
	}
	return qualityValidationWeight / 6 // ≈5, liveness-only observation pool
}

// stabilityScore is the core of P5: long-term stability. Repeated data-plane
// success builds it; the observed lifetime (LastDataPlaneOK - FirstSeen) adds up
// to 6 more once the endpoint has survived a full half-life; consecutive
// data-plane failures pull it down. Missing FirstSeen/LastDataPlaneOK contribute
// zero lifetime (never NaN, never a windfall high).
func (e endpointEntry) stabilityScore(now time.Time) float64 {
	s := float64(min(e.DataPlaneSuccess, 3)) * 8.0 // up to 24
	if !e.FirstSeen.IsZero() && !e.LastDataPlaneOK.IsZero() && e.LastDataPlaneOK.After(e.FirstSeen) {
		lifetime := e.LastDataPlaneOK.Sub(e.FirstSeen).Hours()
		s += 6.0 * clamp01(lifetime/endpointQualityHalfLife.Hours())
	}
	s -= float64(min(e.ConsecDPFail, 3)) * 8.0 // down to -24
	return clamp(s, 0, qualityStabilityWeight)
}

// freshnessScore decays with the age of the last data-plane success (falling back
// to LastSeen when the endpoint never carried a verified session). Half-life
// decay (never a hard expiry) means old successes fade instead of persisting
// forever. Zero timestamps yield zero freshness; future timestamps clamp to age 0.
func (e endpointEntry) freshnessScore(now time.Time) float64 {
	ref := e.LastDataPlaneOK
	if ref.IsZero() {
		ref = e.LastSeen
	}
	if ref.IsZero() {
		return 0
	}
	age := now.Sub(ref).Hours()
	if age < 0 {
		age = 0
	}
	return qualityFreshnessWeight * math.Exp(-age/endpointQualityHalfLife.Hours())
}

// reliabilityScore keeps the Laplace-smoothed handshake success rate, scaled to
// its component weight. Smoothing already distinguishes 1/1 (0.67) from
// 100/100 (0.99), so a one-hit wonder cannot equal a long-reliable node.
func (e endpointEntry) reliabilityScore() float64 {
	return qualityReliabilityWeight * e.successRate()
}

// latencyScore rewards a low REAL handshake latency. A missing latency is NEUTRAL
// (half the component), never a floor, so a newly observed node is not punished
// for data it has not produced yet.
func (e endpointEntry) latencyScore() float64 {
	if e.LastHandshakeMs <= 0 {
		return qualityLatencyWeight * 0.5
	}
	return qualityLatencyWeight * clamp01(1-float64(e.LastHandshakeMs)/qualityLatencyRefMs)
}

// speedScore maps measured throughput (LastSpeedMbps) into its component on a
// LOG scale. Linear Mbps/ref collapsed everything above 50 Mbps to the same
// score; log scaling keeps 10/30/100/200 Mbps visibly distinct while still
// saturating (so a one-off 500 Mbps reading does not dominate forever). Missing
// speed is neutral, so a newly observed node is not punished for data it has
// not produced yet.
func (e endpointEntry) speedScore() float64 {
	if e.LastSpeedMbps <= 0 {
		return qualitySpeedWeight * 0.5
	}
	if e.LastSpeedMbps <= qualitySpeedRefLowMbps {
		return 0
	}
	lo := math.Log2(qualitySpeedRefLowMbps)
	hi := math.Log2(qualitySpeedRefHighMbps)
	return qualitySpeedWeight * clamp01((math.Log2(e.LastSpeedMbps)-lo)/(hi-lo))
}

// qualityScore is the total 0-100 endpoint quality, the P5.2 Healthy Pool sort
// key. All inputs are pure and `now` is injectable for deterministic tests.
func (e endpointEntry) qualityScore(now time.Time) float64 {
	return e.validationScore() +
		e.stabilityScore(now) +
		e.freshnessScore(now) +
		e.reliabilityScore() +
		e.latencyScore() +
		e.speedScore()
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func clamp(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

// ---------------------------------------------------------------------------
// P5.3 endpoint lifecycle state.
//
// The state is DERIVED from the P5.1 quality fields — it is never persisted and
// it is NOT a second scoring system (P5.2's qualityScore is the only ranking
// key). It exists so the Healthy Pool and the Observation Pool can be told apart
// explicitly: a Healthy endpoint participates in the pool, an Observation
// endpoint (Fresh/Degraded/Suspect) is watched, never evicted here.
// ---------------------------------------------------------------------------

type endpointState int

const (
	stateFresh    endpointState = iota // no data-plane verification yet (observation pool)
	stateHealthy                       // verified, no consecutive data-plane failure
	stateDegraded                      // verified, some consecutive failures (deprioritised)
	stateSuspect                       // consecutive failures reached the suspect threshold
)

// stateFailSuspectThreshold demotes a verified endpoint to Suspect after this
// many consecutive data-plane failures. It only DEPRIORITISES (via quality), it
// never evicts — a connect-time data-plane failure (incl. WSAENETUNREACH / FIB
// convergence) must never be read as endpoint death.
const stateFailSuspectThreshold = 3

// state reports the lifecycle state. Dead is deliberately absent: death is the
// failover path's VERDICT expressed as evict(), not a state an entry can sit in.
func (e endpointEntry) state() endpointState {
	if e.DataPlaneSuccess == 0 {
		return stateFresh
	}
	switch {
	case e.ConsecDPFail >= stateFailSuspectThreshold:
		return stateSuspect
	case e.ConsecDPFail > 0:
		return stateDegraded
	default:
		return stateHealthy
	}
}

// lastGoodTrustworthy reports whether an endpoint still deserves the LastGood
// absolute-first privilege. The bar is TWO consecutive data-plane failures: a
// single failure can still be transient even after the probe retry loop, while
// two across separate connects point at the endpoint, not the network.
//
// It reads ConsecDPFail directly rather than state(): state()'s Suspect
// threshold (3) is a POOL-MEMBERSHIP concept, not a trust concept, and reusing
// it would either withdraw the privilege too late (>=3) or conflate two
// different meanings. recordDataPlane(true) resets ConsecDPFail to 0, so the
// privilege restores itself on the next successful session — no extra recovery.
func (e endpointEntry) lastGoodTrustworthy() bool {
	return e.ConsecDPFail < 2
}

// healthyCount reports how many cached endpoints are currently Healthy (the
// Healthy Pool size).
func (c endpointCache) healthyCount() int {
	n := 0
	for _, e := range c.Endpoints {
		if e.state() == stateHealthy {
			n++
		}
	}
	return n
}

// observationAddrs returns the Observation Pool addresses — everything NOT
// currently Healthy (Fresh / Degraded / Suspect). Order is unspecified; callers
// order by qualityScore. A Fresh endpoint is observed (liveness → handshake →
// data-plane) rather than trusted up front.
func (c endpointCache) observationAddrs() []string {
	out := make([]string, 0, len(c.Endpoints))
	for _, e := range c.Endpoints {
		if e.state() != stateHealthy {
			out = append(out, e.Addr)
		}
	}
	return out
}

// needsDiscovery reports whether the Healthy Pool is empty: a connect then has
// no verified endpoint to lean on, so a fresh sweep is justified rather than
// re-probing an Observation Pool whose only members have never carried traffic.
func (c endpointCache) needsDiscovery() bool {
	return c.healthyCount() == 0
}

// recordAttempt records the outcome of ONE real-tunnel handshake attempt. This
// is what turns a slow connect into a fast next connect: without it, the 8
// endpoints that just burned 14s each on their handshake timeouts get no pen
// mark and are tried again, in the same order, forever.
//
// Failures are recorded but NEVER evicted here. Eviction is the failover path's
// verdict on an endpoint judged DEAD; a connect-time failure only means "rank
// this lower next time", because endpoints have transient bad phases (rate
// limiting, congestion) and evicting them would throw away a good endpoint.
func (c *endpointCache) recordAttempt(addr string, success bool) {
	if addr == "" {
		return
	}
	for i := range c.Endpoints {
		if c.Endpoints[i].Addr != addr {
			continue
		}
		c.Endpoints[i].Attempts++
		c.Endpoints[i].LastUsed = time.Now()
		if success {
			c.Endpoints[i].SuccessCount++
			c.Endpoints[i].FailCount = 0
			// A just-proven endpoint carries no measured RTT (the handshake not
			// the data path proves it), and 0 sorts it ahead on the tie-break.
			c.Endpoints[i].LastRttMs = 0
		}
		return
	}
	// Unknown endpoint: only a SUCCESS earns it a cache entry. Persisting every
	// failed candidate grew the cache by ~11 entries per sweep-driven connect
	// (8 -> 12 -> 19 -> ... on 2026-10-05), which inflates endpoints.json
	// without bound and, worse, makes the next fast path probe dozens of
	// endpoints that have never once worked. A failure is only interesting as a
	// demotion of something already known to work.
	if !success {
		return
	}
	c.Endpoints = append(c.Endpoints, endpointEntry{
		Addr:         addr,
		Attempts:     1,
		SuccessCount: 1,
		LastUsed:     time.Now(),
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
	})
}

// recordHandshake records the quality dimension of ONE real-tunnel handshake
// outcome, on top of the successRate accounting recordAttempt already owns.
// elapsedMs is the REAL handshake elapsed (WaitHandshake), never the disposable
// probe's nor the liveness RTT. It never touches SuccessCount/Attempts — those
// stay recordAttempt's single responsibility — and it never evicts.
func (c *endpointCache) recordHandshake(addr string, elapsedMs int64, ok bool) {
	if addr == "" {
		return
	}
	for i := range c.Endpoints {
		if c.Endpoints[i].Addr != addr {
			continue
		}
		c.Endpoints[i].LastSeen = time.Now()
		if ok && elapsedMs > 0 {
			c.Endpoints[i].LastHandshakeMs = elapsedMs
		}
		return
	}
}

// recordDataPlane records the quality dimension of the FINAL data-plane outcome
// of one connect (or one failover hop): a single success or failure, not the
// individual 300ms retry attempts inside the settle window. It never evicts —
// a connect-time data-plane failure must not remove an endpoint, only the
// failover path's verdict on a live-but-dead session may (see evict).
func (c *endpointCache) recordDataPlane(addr string, ok bool) {
	if addr == "" {
		return
	}
	for i := range c.Endpoints {
		if c.Endpoints[i].Addr != addr {
			continue
		}
		c.Endpoints[i].LastSeen = time.Now()
		if ok {
			c.Endpoints[i].DataPlaneSuccess++
			c.Endpoints[i].ConsecDPFail = 0
			c.Endpoints[i].LastDataPlaneOK = time.Now()
		} else {
			c.Endpoints[i].DataPlaneFail++
			c.Endpoints[i].ConsecDPFail++
		}
		return
	}
}

// recordSpeed records a measured throughput for an endpoint as an exponential
// moving average, so one transiently congested sample cannot permanently demote
// (or over-promote) an endpoint. A non-positive sample is a failed measurement
// and is dropped, never written. It only ever writes LastSpeedMbps/SpeedSampleAt
// (never SuccessCount/Attempts, never a synthetic speed from liveEndpoint.Speed),
// so it cannot forge successRate.
func (c *endpointCache) recordSpeed(addr string, mbps float64) {
	if addr == "" || mbps <= 0 {
		return
	}
	for i := range c.Endpoints {
		if c.Endpoints[i].Addr != addr {
			continue
		}
		if old := c.Endpoints[i].LastSpeedMbps; old > 0 {
			c.Endpoints[i].LastSpeedMbps = 0.5*old + 0.5*mbps
		} else {
			c.Endpoints[i].LastSpeedMbps = mbps
		}
		c.Endpoints[i].SpeedSampleAt = time.Now()
		c.Endpoints[i].LastSeen = time.Now()
		return
	}
}

// orderedAddrs returns cached endpoint addresses ordered for HANDSHAKE
// PRIORITY: by P5.2 quality (stability + freshness + validation + reliability +
// latency + speed), with the last known handshake RTT as the tie-break. It used
// to sort purely by successRate/RTT, which let a fast-but-unstable endpoint
// outrank a long-stable one.
func (c endpointCache) orderedAddrs() []string {
	es := append([]endpointEntry(nil), c.Endpoints...)
	now := time.Now()
	sort.Slice(es, func(i, j int) bool {
		if si, sj := es[i].qualityScore(now), es[j].qualityScore(now); si != sj {
			return si > sj
		}
		if es[i].LastRttMs != es[j].LastRttMs {
			return es[i].LastRttMs < es[j].LastRttMs
		}
		return es[i].Addr < es[j].Addr // deterministic: logs + tests
	})
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Addr)
	}
	return out
}

// recordSuccess updates (or inserts) an endpoint after a good handshake,
// resetting its consecutive-failure count.
func (c *endpointCache) recordSuccess(addr string, rttMs int64) {
	for i := range c.Endpoints {
		if c.Endpoints[i].Addr == addr {
			c.Endpoints[i].LastRttMs = rttMs
			c.Endpoints[i].SuccessCount++
			c.Endpoints[i].FailCount = 0
			c.Endpoints[i].LastUsed = time.Now()
			return
		}
	}
	c.Endpoints = append(c.Endpoints, endpointEntry{
		Addr:         addr,
		LastRttMs:    rttMs,
		SuccessCount: 1,
		LastUsed:     time.Now(),
	})
}

// recordLastGood persists the endpoint that just carried a REAL production
// session to Connected. It is the ONLY cache write that asserts full data-plane
// health: the caller must have completed a real handshake, installed the routes,
// AND passed data-plane verification before calling this — a disposable probe
// success, a liveness hit, or a bare handshake success must never reach here
// (see manager.Start: the call sits after the data-plane gate, right where the
// session is committed). It is the fast reconnect target: cachedCandidates puts
// it first, so a healthy machine reconnects without a sweep.
func recordLastGood(addr string) {
	if addr == "" {
		return
	}
	c := loadCache()
	if c.LastGood == addr {
		return // already the target; skip churn so the file timestamp is stable
	}
	c.LastGood = addr
	c.LastGoodAt = time.Now()
	c.save()
}

// pruneStaleCache runs the out-of-pool sweep against the on-disk cache and
// persists the result. It saves whenever the sweep RAN, not only when it removed
// something, so the LastPruned timestamp survives and the next connect does not
// rebuild the pool again. Connect-time only — it is far too heavy for
// loadCache's many hot callers.
func pruneStaleCache(seed string) (removed int, ran bool) {
	c := loadCache()
	removed, ran = c.pruneOutOfPool(seed)
	if ran {
		c.save()
	}
	return removed, ran
}

// evict removes addr from the cache immediately, bypassing the failure
// threshold. Used when an endpoint is observed DEAD rather than merely slow:
// during failover every candidate gets a real handshake against the live
// tunnel, so a failure there is proof, not a sample. Waiting for failThreshold
// more strikes kept handing the same known-bad endpoint back on every
// reconnect (162.159.192.164:500 at 0.9 Mbps was picked again and again while
// still cached).
//
// Eviction only costs a hint: the endpoint is re-cached by the next full sweep
// if it ever comes back, so this cannot lose an endpoint permanently.
func (c *endpointCache) evict(addr string) {
	if addr == "" {
		return
	}
	out := c.Endpoints[:0]
	removed := false
	for _, e := range c.Endpoints {
		if e.Addr == addr {
			removed = true
			continue
		}
		out = append(out, e)
	}
	if removed {
		c.Endpoints = out
		// The endpoint was judged dead and removed. It must not remain the
		// last-known-good target either: cachedCandidates fast-paths LastGood to
		// the front on the next connect, so a stale LastGood here would hand the
		// next connect straight back to the endpoint we just evicted (observed
		// 2026-10-08: 8.39.125.195:1843 was evicted by failover yet stayed
		// LastGood and was re-selected on every subsequent connect).
		if c.LastGood == addr {
			c.LastGood = ""
			c.LastGoodAt = time.Time{}
		}
	}
}

// recordFailure bumps an endpoint's consecutive-failure count and evicts it once
// it crosses the threshold. Prefer evict for endpoints that are known dead, not
// merely unlucky: three strikes lets a dead endpoint be retried twice more.
func (c *endpointCache) recordFailure(addr string) {
	for i := range c.Endpoints {
		if c.Endpoints[i].Addr != addr {
			continue
		}
		c.Endpoints[i].FailCount++
		if c.Endpoints[i].FailCount >= failThreshold {
			c.Endpoints = append(c.Endpoints[:i], c.Endpoints[i+1:]...)
			// Same stale-LastGood hazard as evict: an endpoint removed for
			// repeated failure must not stay the next connect's fast-path target.
			if c.LastGood == addr {
				c.LastGood = ""
				c.LastGoodAt = time.Time{}
			}
		}
		return
	}
}

// recordProbed persists probe-live (not yet handshake-verified) candidates as
// NEUTRAL cache entries: evidence from the UDP liveness probe and the parallel
// handshake pre-screen, never a forged success. A neutral entry scores 0.5
// (Laplace-smoothed, (0+1)/(0+2)), so it ranks below any historically
// successful endpoint but above the cold pool — the next connect re-probes it
// on the cheap fast path instead of paying for another full sweep. It is capped
// to maxHandshakeCandidates so it cannot trigger the unbounded growth
// recordAttempt deliberately avoids. Entries that later handshake are promoted
// in place by recordAttempt (Attempts/SuccessCount); entries that fail are
// demoted to 0.33 without ever being marked a success.
func recordProbed(eps []liveEndpoint) {
	if len(eps) == 0 {
		return
	}
	if len(eps) > maxHandshakeCandidates {
		eps = eps[:maxHandshakeCandidates]
	}
	c := loadCache()
	changed := false
	for _, ep := range eps {
		if ep.Addr == "" {
			continue
		}
		found := false
		for i := range c.Endpoints {
			if c.Endpoints[i].Addr != ep.Addr {
				continue
			}
			found = true
			// Refresh the probe RTT only when we have a real one and the entry
			// has none; never touch Attempts/SuccessCount (that would forge a
			// success rate).
			if ep.Latency > 0 && c.Endpoints[i].LastRttMs == 0 {
				c.Endpoints[i].LastRttMs = ep.Latency
				changed = true
			}
			break
		}
		if found {
			continue
		}
		c.Endpoints = append(c.Endpoints, endpointEntry{
			Addr:      ep.Addr,
			LastRttMs: ep.Latency,
			LastUsed:  time.Now(),
		})
		changed = true
	}
	if changed {
		c.save()
	}
}
