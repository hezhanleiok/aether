//go:build wgtun

package wgtun

import (
	"math"
	"testing"
	"time"
)

var qNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// TestValidationScoreTiers pins the ordering data-plane > handshake-only >
// liveness-only, and that a fresh node still gets a non-zero score.
func TestValidationScoreTiers(t *testing.T) {
	dp := endpointEntry{DataPlaneSuccess: 1}.validationScore()
	hs := endpointEntry{SuccessCount: 1}.validationScore()
	lo := (endpointEntry{}).validationScore()
	if dp <= hs || hs <= lo {
		t.Fatalf("tiers wrong: dp=%v hs=%v lo=%v", dp, hs, lo)
	}
	if lo <= 0 {
		t.Fatalf("liveness-only node must not be zeroed: %v", lo)
	}
}

// TestStabilityScoreLifetimeAndFailures pins the three forces: repeated
// data-plane success, observed lifetime, and consecutive data-plane failures.
func TestStabilityScoreLifetimeAndFailures(t *testing.T) {
	stable := endpointEntry{
		DataPlaneSuccess: 3,
		FirstSeen:        qNow.Add(-24 * time.Hour),
		LastDataPlaneOK:  qNow,
	}
	if s := stable.stabilityScore(qNow); s != 25 {
		t.Fatalf("stable = %v, want 25", s)
	}
	if s := (endpointEntry{}).stabilityScore(qNow); s != 0 {
		t.Fatalf("fresh = %v, want 0", s)
	}
	failing := endpointEntry{
		DataPlaneSuccess: 3,
		ConsecDPFail:     3,
		FirstSeen:        qNow.Add(-24 * time.Hour),
		LastDataPlaneOK:  qNow,
	}
	if s := failing.stabilityScore(qNow); s != 6 {
		t.Fatalf("failing = %v, want 6 (30 - 24 penalty)", s)
	}
}

// TestStabilityScoreMissingFieldsNoNaN pins that missing FirstSeen/LastDataPlaneOK
// never produce NaN/Inf or a windfall high score.
func TestStabilityScoreMissingFieldsNoNaN(t *testing.T) {
	e := endpointEntry{DataPlaneSuccess: 1} // FirstSeen/LastDataPlaneOK zero
	s := e.stabilityScore(qNow)
	if math.IsNaN(s) || math.IsInf(s, 0) || s < 0 || s > 30 {
		t.Fatalf("stability NaN/out-of-range: %v", s)
	}
}

// TestFreshnessScoreDecay pins half-life decay at age 0 / half-life / 2*half-life,
// and the zero / future timestamp edges.
func TestFreshnessScoreDecay(t *testing.T) {
	f0 := endpointEntry{LastDataPlaneOK: qNow}.freshnessScore(qNow)
	f1 := endpointEntry{LastDataPlaneOK: qNow.Add(-24 * time.Hour)}.freshnessScore(qNow)
	f2 := endpointEntry{LastDataPlaneOK: qNow.Add(-48 * time.Hour)}.freshnessScore(qNow)
	if f0 <= f1 || f1 <= f2 {
		t.Fatalf("not decaying: f0=%v f1=%v f2=%v", f0, f1, f2)
	}
	if z := (endpointEntry{}).freshnessScore(qNow); z != 0 {
		t.Fatalf("zero-timestamp freshness = %v, want 0", z)
	}
	if fut := (endpointEntry{LastDataPlaneOK: qNow.Add(time.Hour)}).freshnessScore(qNow); fut != 12 {
		t.Fatalf("future freshness = %v, want 12 (clamped to age 0)", fut)
	}
}

// TestReliabilityScoreDistinguishesCount pins that 1/1 scores strictly below
// 100/100 (Laplace smoothing), so a one-hit wonder cannot equal a long-reliable node.
func TestReliabilityScoreDistinguishesCount(t *testing.T) {
	one := endpointEntry{Attempts: 1, SuccessCount: 1}.reliabilityScore()
	hundred := endpointEntry{Attempts: 100, SuccessCount: 100}.reliabilityScore()
	if one >= hundred {
		t.Fatalf("1/1 (%v) should be < 100/100 (%v)", one, hundred)
	}
}

// TestLatencyScoreNeutralAndRank pins that missing latency is neutral (not a
// floor) and lower real handshake latency scores higher.
func TestLatencyScoreNeutralAndRank(t *testing.T) {
	missing := (endpointEntry{}).latencyScore()
	if missing != 3 {
		t.Fatalf("neutral latency = %v, want 3", missing)
	}
	fast := endpointEntry{LastHandshakeMs: 400}.latencyScore()
	slow := endpointEntry{LastHandshakeMs: 5000}.latencyScore()
	if fast <= missing || slow >= missing || fast <= slow {
		t.Fatalf("latency ranking wrong: fast=%v slow=%v neutral=%v", fast, slow, missing)
	}
}

// TestSpeedScoreNeutralAndRank pins the log-scaled speed component and its
// neutral default. The log scale keeps 10 vs 200 Mbps visibly distinct, unlike
// the old flat Mbps/50 clamp that made every 50+ Mbps endpoint score the same.
func TestSpeedScoreNeutralAndRank(t *testing.T) {
	if m := (endpointEntry{}).speedScore(); m != 7.5 {
		t.Fatalf("neutral speed = %v, want 7.5", m)
	}
	full := endpointEntry{LastSpeedMbps: 200}.speedScore()
	fast := endpointEntry{LastSpeedMbps: 100}.speedScore()
	slow := endpointEntry{LastSpeedMbps: 10}.speedScore()
	if full != 15 || fast >= full || slow >= fast {
		t.Fatalf("speed ranking wrong: full=%v fast=%v slow=%v", full, fast, slow)
	}
}

// TestQualityScoreRange pins the total stays within 0-100 for extremes.
func TestQualityScoreRange(t *testing.T) {
	perfect := endpointEntry{
		DataPlaneSuccess: 3, FirstSeen: qNow.Add(-48 * time.Hour), LastDataPlaneOK: qNow,
		SuccessCount: 100, Attempts: 100, LastHandshakeMs: 100, LastSpeedMbps: 100,
	}
	if s := perfect.qualityScore(qNow); s < 0 || s > 100 {
		t.Fatalf("perfect quality out of range: %v", s)
	}
	if s := (endpointEntry{}).qualityScore(qNow); s < 0 || s > 100 {
		t.Fatalf("empty quality out of range: %v", s)
	}
}

// TestStableBeatsFastShortLived is the core P5 invariant: a long-stable but
// slower endpoint must outrank a fast but just-created one, even though the
// fast one has better latency and speed.
func TestStableBeatsFastShortLived(t *testing.T) {
	stable := endpointEntry{
		DataPlaneSuccess: 5, FirstSeen: qNow.Add(-72 * time.Hour), LastDataPlaneOK: qNow,
		SuccessCount: 50, Attempts: 50, LastHandshakeMs: 2000, LastSpeedMbps: 5,
	}
	fast := endpointEntry{
		DataPlaneSuccess: 1, FirstSeen: qNow.Add(-time.Minute), LastDataPlaneOK: qNow,
		SuccessCount: 1, Attempts: 1, LastHandshakeMs: 100, LastSpeedMbps: 500,
	}
	if fast.qualityScore(qNow) >= stable.qualityScore(qNow) {
		t.Fatalf("fast short-lived (%v) beat long-stable (%v)", fast.qualityScore(qNow), stable.qualityScore(qNow))
	}
}

// TestOrderHandshakeCandidatesUsesQuality pins that the Healthy Pool now orders
// by adaptive quality rather than successRate alone.
func TestOrderHandshakeCandidatesUsesQuality(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.Endpoints = []endpointEntry{
		{Addr: "stable:1", DataPlaneSuccess: 5, FirstSeen: qNow.Add(-72 * time.Hour), LastDataPlaneOK: qNow, SuccessCount: 50, Attempts: 50},
		{Addr: "new:1", DataPlaneSuccess: 0, SuccessCount: 0},
	}
	c.save()

	got := orderHandshakeCandidates([]liveEndpoint{{Addr: "new:1"}, {Addr: "stable:1"}})
	if got[0].Addr != "stable:1" || got[1].Addr != "new:1" {
		t.Fatalf("quality ordering wrong: %v", addrs(got))
	}
}

// TestLastGoodFirstRegardlessOfQuality is the mandated P4.2 regression: even when
// LastGood has the LOWEST quality and every other endpoint has the highest,
// LastGood must still handshake first.
func TestLastGoodFirstRegardlessOfQuality(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "lastgood:1"
	c.Endpoints = []endpointEntry{
		{Addr: "lastgood:1", DataPlaneSuccess: 0, SuccessCount: 1, Attempts: 5}, // lowest quality
		{Addr: "great:1", DataPlaneSuccess: 10, FirstSeen: qNow.Add(-100 * time.Hour), LastDataPlaneOK: qNow, SuccessCount: 100, Attempts: 100, LastSpeedMbps: 500},
	}
	c.save()

	ordered := orderHandshakeCandidates([]liveEndpoint{{Addr: "lastgood:1"}, {Addr: "great:1"}})
	got := lastGoodFirst(ordered)
	if got[0].Addr != "lastgood:1" {
		t.Fatalf("LastGood not first despite lowest quality: %v", addrs(got))
	}
}
