//go:build wgtun

package wgtun

import "testing"

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
	c.recordAttempt("good:2408", true) // the one that worked
	c.recordAttempt("bad:500", false)  // timed out
	c.recordAttempt("bad:1701", false) // timed out
	// "new:8380" is not in the cache at all -> neutral prior (0.5).
	c.save()

	eps := orderHandshakeCandidates([]liveEndpoint{
		{Addr: "bad:500", Latency: 5},
		{Addr: "new:8380", Latency: 7},
		{Addr: "bad:1701", Latency: 6},
		{Addr: "good:2408", Latency: 9},
	})
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
	if c.Endpoints[0].Attempts != 1 || c.Endpoints[0].SuccessCount != 1 {
		t.Fatalf("good endpoint accounting wrong: %+v", c.Endpoints[0])
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
