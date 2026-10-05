//go:build wgtun

package wgtun

import (
	"encoding/json"
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
}

const (
	cacheFileVersion = 1
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
	})
}

// orderedAddrs returns cached endpoint addresses ordered for HANDSHAKE
// PRIORITY: historically reliable first (successRate descending), with the last
// known handshake RTT as the tie-break. It used to sort purely by RTT, which
// put fast-answering-but-never-connecting endpoints ahead of ones that work.
func (c endpointCache) orderedAddrs() []string {
	es := append([]endpointEntry(nil), c.Endpoints...)
	sort.Slice(es, func(i, j int) bool {
		if ri, rj := es[i].successRate(), es[j].successRate(); ri != rj {
			return ri > rj
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
		}
		return
	}
}
