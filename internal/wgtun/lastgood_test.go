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
