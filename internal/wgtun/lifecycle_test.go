//go:build wgtun

package wgtun

import "testing"

// TestStateDerivation pins the P5.3 lifecycle derivation across all four states.
func TestStateDerivation(t *testing.T) {
	fresh := (endpointEntry{}).state()
	healthy := (endpointEntry{DataPlaneSuccess: 1, ConsecDPFail: 0}).state()
	degraded := (endpointEntry{DataPlaneSuccess: 1, ConsecDPFail: 2}).state()
	suspect := (endpointEntry{DataPlaneSuccess: 1, ConsecDPFail: 3}).state()
	if fresh != stateFresh || healthy != stateHealthy || degraded != stateDegraded || suspect != stateSuspect {
		t.Fatalf("states wrong: fresh=%v healthy=%v degraded=%v suspect=%v", fresh, healthy, degraded, suspect)
	}
}

// TestStateThresholdBoundary pins the Degraded→Suspect boundary at exactly
// stateFailSuspectThreshold consecutive data-plane failures.
func TestStateThresholdBoundary(t *testing.T) {
	below := (endpointEntry{DataPlaneSuccess: 1, ConsecDPFail: stateFailSuspectThreshold - 1}).state()
	at := (endpointEntry{DataPlaneSuccess: 1, ConsecDPFail: stateFailSuspectThreshold}).state()
	if below != stateDegraded {
		t.Fatalf("below threshold = %v, want degraded", below)
	}
	if at != stateSuspect {
		t.Fatalf("at threshold = %v, want suspect", at)
	}
}

// TestStateFreshWithoutDataPlane pins that any handshake success without a
// data-plane verification is still Fresh (observation pool, never Healthy).
func TestStateFreshWithoutDataPlane(t *testing.T) {
	e := endpointEntry{SuccessCount: 5, Attempts: 5, DataPlaneSuccess: 0}
	if e.state() != stateFresh {
		t.Fatalf("handshake-only endpoint = %v, want fresh", e.state())
	}
}

// TestHealthyCount pins the Healthy Pool size.
func TestHealthyCount(t *testing.T) {
	c := endpointCache{Endpoints: []endpointEntry{
		{Addr: "h1:1", DataPlaneSuccess: 1},
		{Addr: "h2:1", DataPlaneSuccess: 2},
		{Addr: "f1:1", DataPlaneSuccess: 0},
		{Addr: "s1:1", DataPlaneSuccess: 1, ConsecDPFail: 3},
	}}
	if n := c.healthyCount(); n != 2 {
		t.Fatalf("healthyCount = %d, want 2", n)
	}
}

// TestObservationAddrs pins that only non-Healthy endpoints land in the
// Observation Pool, and Healthy endpoints never leak into it.
func TestObservationAddrs(t *testing.T) {
	c := endpointCache{Endpoints: []endpointEntry{
		{Addr: "h1:1", DataPlaneSuccess: 1},
		{Addr: "f1:1", DataPlaneSuccess: 0},
		{Addr: "d1:1", DataPlaneSuccess: 1, ConsecDPFail: 1},
		{Addr: "s1:1", DataPlaneSuccess: 1, ConsecDPFail: 3},
	}}
	obs := c.observationAddrs()
	if len(obs) != 3 {
		t.Fatalf("observationAddrs = %v, want 3 entries", obs)
	}
	seen := map[string]bool{}
	for _, a := range obs {
		seen[a] = true
	}
	if seen["h1:1"] {
		t.Fatal("Healthy endpoint leaked into the Observation Pool")
	}
	for _, want := range []string{"f1:1", "d1:1", "s1:1"} {
		if !seen[want] {
			t.Fatalf("Observation Pool missing %s", want)
		}
	}
}

// TestNeedsDiscovery pins the sweep-trigger predicate: empty or Fresh-only pools
// need a fresh sweep; a pool with at least one Healthy endpoint does not.
func TestNeedsDiscovery(t *testing.T) {
	if !(endpointCache{}).needsDiscovery() {
		t.Fatal("empty cache should need discovery")
	}
	if !(endpointCache{Endpoints: []endpointEntry{{Addr: "f:1"}}}).needsDiscovery() {
		t.Fatal("Fresh-only pool should need discovery (no verified endpoint)")
	}
	if (endpointCache{Endpoints: []endpointEntry{{Addr: "h:1", DataPlaneSuccess: 1}}}).needsDiscovery() {
		t.Fatal("pool with a Healthy endpoint should NOT need discovery")
	}
}

// TestStateNeverEvicts pins that lifecycle state is derived and never evicts: a
// Suspect endpoint (5 consecutive data-plane failures) stays in the cache —
// only the failover path may evict, and only on handshake+data-plane double failure.
func TestStateNeverEvicts(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "s:1", DataPlaneSuccess: 1, ConsecDPFail: 5}}}
	if len(c.Endpoints) != 1 {
		t.Fatalf("Suspect entry evicted: %d entries", len(c.Endpoints))
	}
	if c.Endpoints[0].state() != stateSuspect {
		t.Fatalf("state = %v, want suspect", c.Endpoints[0].state())
	}
}
