//go:build wgtun

package wgtun

import (
	"context"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// B: Healthy Pool empty → skip fast-path 2s retry → Fresh Discovery
// ---------------------------------------------------------------------------

// TestProbeCandidatesSkipsFastRetryWhenHealthyPoolEmpty pins the P5.3 sweep
// trigger: with an empty Healthy Pool, an all-dead fast-path liveness must NOT
// burn the 2s retry — it falls straight through to the sweep.
func TestProbeCandidatesSkipsFastRetryWhenHealthyPoolEmpty(t *testing.T) {
	defer saveStateDir(t)()

	// Healthy Pool empty: only a Fresh endpoint (never data-plane verified).
	c := loadCache()
	c.Endpoints = []endpointEntry{{Addr: "fresh:1"}}
	c.save()

	var calls int
	origFilter := filterLiveStrictFn
	filterLiveStrictFn = func(_ context.Context, _ []string, _ int, _ func(string)) []liveEndpoint {
		calls++
		return nil // all dead
	}
	defer func() { filterLiveStrictFn = origFilter }()

	start := time.Now()
	_, fromSweep, err := probeCandidates(context.Background(), Config{Endpoint: "seed:1"}, "", false, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected sweep error (no live endpoint), got nil")
	}
	if fromSweep != true {
		t.Fatalf("fromSweep = %v, want true (fresh discovery entered)", fromSweep)
	}
	// The fast-path retry must be SKIPPED: filterLiveStrictFn runs once on the
	// fast path and once on the sweep — never a third (retry) time.
	if calls != 2 {
		t.Fatalf("filterLiveStrictFn called %d times, want 2 (fast path + sweep, no retry)", calls)
	}
	// No 2s wait: the whole call must finish well under the retry delay.
	if elapsed >= time.Second {
		t.Fatalf("probeCandidates took %v, want < 1s (no 2s fast-path retry)", elapsed)
	}
}

// TestProbeCandidatesRetriesWhenHealthyPoolNonEmpty is the counter-case proving
// the seam: with a non-empty Healthy Pool, an all-dead fast-path liveness still
// gets the 2s retry (the P5.3 skip is gated on needsDiscovery() only).
func TestProbeCandidatesRetriesWhenHealthyPoolNonEmpty(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.Endpoints = []endpointEntry{{Addr: "h:1", DataPlaneSuccess: 1}} // Healthy
	c.save()

	var calls int
	origFilter := filterLiveStrictFn
	filterLiveStrictFn = func(_ context.Context, _ []string, _ int, _ func(string)) []liveEndpoint {
		calls++
		return nil // dead on fast path and sweep alike
	}
	defer func() { filterLiveStrictFn = origFilter }()

	start := time.Now()
	_, fromSweep, err := probeCandidates(context.Background(), Config{Endpoint: "seed:1"}, "", false, nil)
	elapsed := time.Since(start)

	// Healthy Pool non-empty → the 2s retry fires → fast path + retry + sweep = 3.
	if calls != 3 {
		t.Fatalf("filterLiveStrictFn called %d times, want 3 (fast path + retry + sweep)", calls)
	}
	if fromSweep != true || err == nil {
		t.Fatalf("fromSweep=%v err=%v, want sweep entered with error", fromSweep, err)
	}
	if elapsed < 1500*time.Millisecond {
		t.Fatalf("elapsed %v, want >= 1.5s (the 2s retry must have fired)", elapsed)
	}
}

// ---------------------------------------------------------------------------
// D: failover eviction (handshake + data-plane failure → evict)
// ---------------------------------------------------------------------------

// TestEvictRemovesOnlyTarget pins that evict removes exactly the target endpoint
// and preserves every other entry (failover death, not connect rollback).
func TestEvictRemovesOnlyTarget(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{
		{Addr: "a:1"}, {Addr: "b:1"}, {Addr: "c:1"},
	}}
	c.evict("b:1")
	if len(c.Endpoints) != 2 {
		t.Fatalf("evict left %d entries, want 2", len(c.Endpoints))
	}
	for _, e := range c.Endpoints {
		if e.Addr == "b:1" {
			t.Fatal("evicted endpoint still present")
		}
	}
}

// TestEvictEmptyAndUnknownAreNoops pins the evict boundaries (empty / unknown
// addresses must not mutate the cache).
func TestEvictEmptyAndUnknownAreNoops(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1"}}}
	c.evict("")
	c.evict("zz:1")
	if len(c.Endpoints) != 1 || c.Endpoints[0].Addr != "a:1" {
		t.Fatalf("no-op evict changed the cache: %+v", c.Endpoints)
	}
}

// TestEvictedEndpointNotReoffered pins that after evict, the warm path
// (cachedCandidates) no longer offers the evicted endpoint.
func TestEvictedEndpointNotReoffered(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.Endpoints = []endpointEntry{{Addr: "a:1"}, {Addr: "dead:1"}}
	c.evict("dead:1")
	c.save()

	for _, ep := range cachedCandidates("", "") {
		if ep.Addr == "dead:1" {
			t.Fatal("evicted endpoint re-offered by cachedCandidates")
		}
	}
}

// ---------------------------------------------------------------------------
// D2: evict / recordFailure must clear a stale LastGood
// ---------------------------------------------------------------------------

// TestEvictClearsLastGood pins that evicting the last-known-good endpoint also
// clears the LastGood field, so the next connect cannot fast-path back onto the
// endpoint that was just judged dead (observed 2026-10-08: 8.39.125.195:1843
// was evicted by failover yet stayed LastGood and was re-selected every time).
func TestEvictClearsLastGood(t *testing.T) {
	c := &endpointCache{
		LastGood:   "a:1",
		LastGoodAt: time.Now(),
		Endpoints:  []endpointEntry{{Addr: "a:1"}, {Addr: "b:1"}},
	}
	c.evict("a:1")
	if c.LastGood != "" {
		t.Fatalf("LastGood = %q, want empty after evicting it", c.LastGood)
	}
	if !c.LastGoodAt.IsZero() {
		t.Fatalf("LastGoodAt not zeroed after evict: %v", c.LastGoodAt)
	}
}

// TestEvictOtherDoesNotClearLastGood pins the reverse: evicting a DIFFERENT
// endpoint must leave the last-known-good untouched.
func TestEvictOtherDoesNotClearLastGood(t *testing.T) {
	c := &endpointCache{
		LastGood:   "a:1",
		LastGoodAt: time.Now(),
		Endpoints:  []endpointEntry{{Addr: "a:1"}, {Addr: "b:1"}},
	}
	c.evict("b:1")
	if c.LastGood != "a:1" {
		t.Fatalf("LastGood = %q, want a:1 (evicting another endpoint must not clear it)", c.LastGood)
	}
}

// TestRecordFailureThresholdClearsLastGood pins that recordFailure reaching the
// eviction threshold clears LastGood the same way evict does.
func TestRecordFailureThresholdClearsLastGood(t *testing.T) {
	c := &endpointCache{
		LastGood:   "a:1",
		LastGoodAt: time.Now(),
		Endpoints:  []endpointEntry{{Addr: "a:1"}},
	}
	for i := 0; i < failThreshold; i++ {
		c.recordFailure("a:1")
	}
	if c.LastGood != "" {
		t.Fatalf("LastGood = %q, want empty after recordFailure hit the threshold", c.LastGood)
	}
	if len(c.Endpoints) != 0 {
		t.Fatalf("endpoint still cached after %d failures: %+v", failThreshold, c.Endpoints)
	}
}
