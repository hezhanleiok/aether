//go:build wgtun

package wgtun

import (
	"testing"
	"time"
)

func TestEndpointCacheOrder(t *testing.T) {
	var c endpointCache
	c.recordSuccess("a:4500", 120)
	c.recordSuccess("b:4500", 45)
	c.recordSuccess("c:4500", 80)

	got := c.orderedAddrs()
	want := []string{"b:4500", "c:4500", "a:4500"} // fastest first
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

// TestSuccessRateSmoothing locks in the Laplace prior: an untried endpoint must
// score better than one that has only ever failed, and worse than one that has
// only ever succeeded — otherwise ranking degenerates into either "never touch
// anything untested" or "1 lucky hit outranks a proven endpoint".
func TestSuccessRateSmoothing(t *testing.T) {
	var (
		failed  = endpointEntry{Addr: "f", SuccessCount: 0, Attempts: 1}
		virgin  = endpointEntry{Addr: "v"}
		onceOk  = endpointEntry{Addr: "o", SuccessCount: 1, Attempts: 1}
		veteran = endpointEntry{Addr: "w", SuccessCount: 18, Attempts: 20}
	)
	if got, want := failed.successRate(), (1.0 / 3.0); got != want {
		t.Fatalf("failed rate = %v, want %v", got, want)
	}
	if got, want := virgin.successRate(), 0.5; got != want {
		t.Fatalf("virgin rate = %v, want %v", got, want)
	}
	if got, want := onceOk.successRate(), (2.0 / 3.0); got != want {
		t.Fatalf("once-ok rate = %v, want %v", got, want)
	}
	if onceOk.successRate() >= veteran.successRate() {
		t.Fatalf("one success (%v) must not outrank 18/20 (%v)",
			onceOk.successRate(), veteran.successRate())
	}
	// A legacy entry (written before Attempts existed) must bootstrap from its
	// successes rather than being treated as "0 attempts, 1 success".
	if got, want := (endpointEntry{SuccessCount: 3}).successRate(), (4.0 / 5.0); got != want {
		t.Fatalf("legacy rate = %v, want %v", got, want)
	}
}

// TestOrderBySuccessRate is the behaviour the ranking change exists for: after
// one bad run, the endpoint that actually connected must lead the next connect,
// and the ones that only burned their handshake timeout must fall behind even
// untested endpoints.
func TestOrderBySuccessRate(t *testing.T) {
	// orderHandshakeCandidates loads the cache itself, so the state dir — not a
	// local endpointCache — is what this test has to seed.
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	var c endpointCache
	// Endpoints only exist in the cache once they have succeeded (a failed
	// unknown candidate is never persisted), so "known but now failing" means
	// "worked before, timed out since".
	c.recordAttempt("good:2408", true)                   // never failed
	for _, ep := range []string{"bad:500", "bad:1701"} { // worked once ...
		c.recordAttempt(ep, true)
	}
	c.recordAttempt("bad:500", false) // ... then timed out twice
	c.recordAttempt("bad:500", false)
	for i := 0; i < 3; i++ { // ... and three times, so it is the worst
		c.recordAttempt("bad:1701", false)
	}
	// "new:8380" is not in the cache at all -> neutral prior (0.5).
	c.save()

	eps := orderHandshakeCandidates([]liveEndpoint{
		{Addr: "bad:500", Latency: 5},
		{Addr: "new:8380", Latency: 7},
		{Addr: "bad:1701", Latency: 6},
		{Addr: "good:2408", Latency: 9},
	})
	// good 1/1 = 0.67; new = 0.50; bad:500 1/3 = 0.40; bad:1701 1/4 = 0.33.
	want := []string{"good:2408", "new:8380", "bad:500", "bad:1701"}
	if len(eps) != len(want) {
		t.Fatalf("len = %d, want %d", len(eps), len(want))
	}
	for i := range want {
		if eps[i].Addr != want[i] {
			t.Fatalf("got[%d]=%q, want %q (full: %v)", i, eps[i].Addr, want[i], eps)
		}
	}
	// Failures must be recorded, never evicted: only failover evicts.
	if len(c.Endpoints) != 3 {
		t.Fatalf("attempts should not evict; got %d entries", len(c.Endpoints))
	}
}

// TestRecordAttemptDoesNotCreateOnFailure is the cache-growth guard. Persisting
// every failed candidate added ~11 entries per sweep-driven connect, which grew
// endpoints.json without bound and made the next fast path probe dozens of
// endpoints that had never once worked. A failure may only demote something
// already known.
func TestRecordAttemptDoesNotCreateOnFailure(t *testing.T) {
	var c endpointCache
	c.recordAttempt("never-worked:500", false)
	if len(c.Endpoints) != 0 {
		t.Fatalf("failure created a cache entry for an unknown endpoint: %d", len(c.Endpoints))
	}
	// A success does create one...
	c.recordAttempt("worked:2408", true)
	if len(c.Endpoints) != 1 || c.Endpoints[0].SuccessCount != 1 || c.Endpoints[0].Attempts != 1 {
		t.Fatalf("success accounting wrong: %+v", c.Endpoints)
	}
	// ...and from then on its failures are recorded (that is what demotes it).
	c.recordAttempt("worked:2408", false)
	if len(c.Endpoints) != 1 {
		t.Fatalf("known endpoint should stay: %d", len(c.Endpoints))
	}
	if c.Endpoints[0].Attempts != 2 || c.Endpoints[0].SuccessCount != 1 {
		t.Fatalf("demotion accounting wrong: %+v", c.Endpoints[0])
	}
	// 1 success / 2 attempts scores exactly the neutral prior (2/4): one failure
	// alone does not yet make an endpoint worse than an untried one — that is
	// deliberate, otherwise a single loss spike would bury a good endpoint.
	if got := c.Endpoints[0].successRate(); got != 0.5 {
		t.Fatalf("1/2 rate = %v, want 0.5", got)
	}
	// Two failures for one success does drop it below the prior.
	c.recordAttempt("worked:2408", false)
	if got := c.Endpoints[0].successRate(); got >= 0.5 {
		t.Fatalf("1/3 rate = %v, want < 0.5", got)
	}
}

// TestPruneOutOfPool covers the "ghost" cleanup: an address the current pool can
// no longer generate must go, an in-pool address must stay, the seed is always
// kept, and the sweep is throttled so it cannot rebuild the pool on every
// connect.
func TestPruneOutOfPool(t *testing.T) {
	// A real pool address (host 228 -> warpPorts[228%54] == 903) and a ghost
	// (a 8.x segment the prefix list dropped).
	inPool := "162.159.195.228:903"
	ghost := "8.39.125.118:2408"
	poolHas := false
	for _, ep := range poolAddresses() {
		if ep == inPool {
			poolHas = true
			break
		}
	}
	if !poolHas {
		t.Fatalf("%s should be in the generated pool (host%%54 mapping)", inPool)
	}

	var c endpointCache
	c.recordAttempt(inPool, true)
	c.recordAttempt(ghost, true)

	removed, ran := c.pruneOutOfPool(ghost) // ghost passed as the pinned seed
	if !ran {
		t.Fatal("first prune must run (LastPruned zero value = never)")
	}
	if removed != 0 {
		t.Fatalf("seed should never be pruned, removed %d", removed)
	}

	// Second call is throttled.
	if _, ran := c.pruneOutOfPool(ghost); ran {
		t.Fatal("second prune must be throttled by pruneInterval")
	}

	// With no seed pinning it, the ghost goes and the pool address stays.
	c.LastPruned = time.Time{}
	removed, _ = c.pruneOutOfPool("some-other-seed:1")
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	if len(c.Endpoints) != 1 || c.Endpoints[0].Addr != inPool {
		t.Fatalf("survivors wrong: %+v", c.Endpoints)
	}
}

func TestEndpointCacheEviction(t *testing.T) {
	var c endpointCache
	c.recordSuccess("a:4500", 100)
	c.recordFailure("a:4500")
	c.recordFailure("a:4500")
	if len(c.Endpoints) != 1 {
		t.Fatalf("evicted too early after 2 failures: %d", len(c.Endpoints))
	}
	c.recordFailure("a:4500")
	if len(c.Endpoints) != 0 {
		t.Fatalf("not evicted after 3 failures: %d", len(c.Endpoints))
	}
}

func TestEndpointCacheSuccessResetsFail(t *testing.T) {
	var c endpointCache
	c.recordSuccess("a:4500", 100)
	c.recordFailure("a:4500")
	c.recordFailure("a:4500")
	c.recordSuccess("a:4500", 90) // success resets the failure streak
	c.recordFailure("a:4500")
	if len(c.Endpoints) != 1 {
		t.Fatalf("evicted despite a successful reset: %d", len(c.Endpoints))
	}
	if c.Endpoints[0].FailCount != 1 {
		t.Fatalf("fail count = %d, want 1", c.Endpoints[0].FailCount)
	}
}
