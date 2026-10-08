//go:build wgtun

package wgtun

import "testing"

// TestLastGoodFirstPromotes pins P4.2: an endpoint whose historical successRate
// would rank it BELOW others still goes first when it is the persisted LastGood.
func TestLastGoodFirstPromotes(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "lastgood:1"
	c.save()

	eps := []liveEndpoint{
		{Addr: "highrate:1"}, // would rank first by successRate
		{Addr: "lastgood:1"}, // lower successRate, but is LastGood
		{Addr: "other:1"},
	}
	got := lastGoodFirst(eps)
	if got[0].Addr != "lastgood:1" {
		t.Fatalf("first = %q, want lastgood:1", got[0].Addr)
	}
	// The rest keep their relative order (no duplicate, no reshuffle).
	if got[1].Addr != "highrate:1" || got[2].Addr != "other:1" {
		t.Fatalf("tail order = %v, want [highrate:1 other:1]", addrs(got))
	}
}

// TestLastGoodFirstAlreadyFirst pins that an already-first LastGood is left
// untouched (no reallocation churn on the hot path).
func TestLastGoodFirstAlreadyFirst(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "a:1"
	c.save()

	eps := []liveEndpoint{{Addr: "a:1"}, {Addr: "b:1"}}
	got := lastGoodFirst(eps)
	if got[0].Addr != "a:1" || got[1].Addr != "b:1" {
		t.Fatalf("order changed: %v", addrs(got))
	}
}

// TestLastGoodFirstAbsent pins that when LastGood is not in the list (excluded,
// dead on liveness, or not yet cached) the list is returned unchanged — it must
// never fabricate an unverified candidate.
func TestLastGoodFirstAbsent(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "gone:1"
	c.save()

	eps := []liveEndpoint{{Addr: "x:1"}, {Addr: "y:1"}}
	got := lastGoodFirst(eps)
	if got[0].Addr != "x:1" || got[1].Addr != "y:1" {
		t.Fatalf("order changed: %v", addrs(got))
	}
}

// TestLastGoodFirstEmpty pins that an empty LastGood (no prior verified session)
// leaves the list unchanged.
func TestLastGoodFirstEmpty(t *testing.T) {
	defer saveStateDir(t)()

	eps := []liveEndpoint{{Addr: "x:1"}, {Addr: "y:1"}}
	got := lastGoodFirst(eps)
	if got[0].Addr != "x:1" || got[1].Addr != "y:1" {
		t.Fatalf("order changed: %v", addrs(got))
	}
}

// TestLastGoodFirstSingle pins the single-candidate boundary.
func TestLastGoodFirstSingle(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "a:1"
	c.save()

	got := lastGoodFirst([]liveEndpoint{{Addr: "a:1"}})
	if len(got) != 1 || got[0].Addr != "a:1" {
		t.Fatalf("changed: %v", addrs(got))
	}
}

// TestLastGoodFirstTrustworthyZero pins that a cached LastGood with no
// consecutive data-plane failures keeps the absolute-first privilege.
func TestLastGoodFirstTrustworthyZero(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "lg:1"
	c.Endpoints = []endpointEntry{{Addr: "lg:1", DataPlaneSuccess: 1, ConsecDPFail: 0}}
	c.save()

	eps := []liveEndpoint{{Addr: "other:1"}, {Addr: "lg:1"}}
	got := lastGoodFirst(eps)
	if got[0].Addr != "lg:1" {
		t.Fatalf("first = %q, want lg:1 (ConsecDPFail=0 keeps privilege)", got[0].Addr)
	}
}

// TestLastGoodFirstTrustworthyOne pins that ONE consecutive data-plane failure
// is still tolerated: the privilege is only withdrawn at >= 2.
func TestLastGoodFirstTrustworthyOne(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "lg:1"
	c.Endpoints = []endpointEntry{{Addr: "lg:1", DataPlaneSuccess: 1, ConsecDPFail: 1}}
	c.save()

	eps := []liveEndpoint{{Addr: "other:1"}, {Addr: "lg:1"}}
	got := lastGoodFirst(eps)
	if got[0].Addr != "lg:1" {
		t.Fatalf("first = %q, want lg:1 (ConsecDPFail=1 still keeps privilege)", got[0].Addr)
	}
}

// TestLastGoodFirstWithdrawsAtTwo pins the fix: TWO consecutive data-plane
// failures withdraw the absolute-first privilege. The input is deliberately
// [bad, good] so a pass proves the function did NOT move the untrustworthy
// LastGood forward.
func TestLastGoodFirstWithdrawsAtTwo(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "bad:1"
	c.Endpoints = []endpointEntry{
		{Addr: "bad:1", DataPlaneSuccess: 1, ConsecDPFail: 2},
	}
	c.save()

	eps := []liveEndpoint{{Addr: "bad:1"}, {Addr: "good:1"}}
	got := lastGoodFirst(eps)
	if got[0].Addr != "bad:1" {
		t.Fatalf("untrustworthy LastGood was moved to front: %v", addrs(got))
	}
}

// TestLastGoodFirstWithdrawsAtThree pins that the trust threshold is
// ConsecDPFail < 2, not state()'s Suspect threshold (3): three failures also
// withdraw the privilege.
func TestLastGoodFirstWithdrawsAtThree(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "bad:1"
	c.Endpoints = []endpointEntry{
		{Addr: "bad:1", DataPlaneSuccess: 1, ConsecDPFail: 3},
	}
	c.save()

	eps := []liveEndpoint{{Addr: "bad:1"}, {Addr: "good:1"}}
	got := lastGoodFirst(eps)
	if got[0].Addr != "bad:1" {
		t.Fatalf("suspect LastGood was moved to front: %v", addrs(got))
	}
}

// TestLastGoodFirstRecovery pins the full loop: two failures withdraw the
// privilege, a real recordDataPlane(true) resets ConsecDPFail to 0, and the
// privilege is restored — no manual field reset.
func TestLastGoodFirstRecovery(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "lg:1"
	c.Endpoints = []endpointEntry{
		{Addr: "lg:1", DataPlaneSuccess: 1, ConsecDPFail: 2},
	}
	c.save()

	eps := []liveEndpoint{{Addr: "lg:1"}, {Addr: "other:1"}}
	if got := lastGoodFirst(eps); got[0].Addr != "lg:1" {
		t.Fatalf("withdrawn privilege should keep order, got %v", addrs(got))
	}

	// Real recovery mutation: recordDataPlane(true) resets ConsecDPFail to 0.
	c = loadCache()
	c.recordDataPlane("lg:1", true)
	c.save()

	if got := lastGoodFirst(eps); got[0].Addr != "lg:1" {
		t.Fatalf("privilege not restored after data-plane success: %v", addrs(got))
	}
}

// TestLastGoodFirstPipelineFallback pins that once the privilege is withdrawn,
// the existing qualityScore ordering takes over: a healthy high-quality endpoint
// ranks ahead of the untrustworthy LastGood through the full candidate pipeline.
func TestLastGoodFirstPipelineFallback(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "bad:1"
	c.Endpoints = []endpointEntry{
		{Addr: "bad:1", DataPlaneSuccess: 1, ConsecDPFail: 2},
		{Addr: "good:1", DataPlaneSuccess: 5, ConsecDPFail: 0},
	}
	c.save()

	// orderHandshakeCandidates ranks by qualityScore; lastGoodFirst must no
	// longer pull the untrustworthy LastGood back to the front.
	got := lastGoodFirst(orderHandshakeCandidates([]liveEndpoint{
		{Addr: "bad:1"},
		{Addr: "good:1"},
	}))
	if got[0].Addr != "good:1" {
		t.Fatalf("after privilege withdrawal, qualityScore must lead: %v", addrs(got))
	}
}
