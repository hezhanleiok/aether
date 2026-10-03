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

// recordFailure bumps an endpoint's consecutive-failure count and evicts it once
// it crosses the threshold.
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
