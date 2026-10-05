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
}

type endpointEntry struct {
	Addr         string    `json:"addr"`
	LastRttMs    int64     `json:"lastRttMs"`
	SuccessCount int       `json:"successCount"`
	FailCount    int       `json:"failCount"`
	LastUsed     time.Time `json:"lastUsed"`
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

// orderedAddrs returns cached endpoint addresses sorted by last handshake RTT
// ascending — fastest first.
func (c endpointCache) orderedAddrs() []string {
	es := append([]endpointEntry(nil), c.Endpoints...)
	sort.Slice(es, func(i, j int) bool { return es[i].LastRttMs < es[j].LastRttMs })
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
