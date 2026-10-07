//go:build wgtun

package wgtun

import (
	"testing"
	"time"
)

func saveStateDir(t *testing.T) func() {
	t.Helper()
	orig := stateDir
	stateDir = t.TempDir()
	return func() { stateDir = orig }
}

func addrs(eps []liveEndpoint) []string {
	out := make([]string, len(eps))
	for i, e := range eps {
		out[i] = e.Addr
	}
	return out
}

// TestRecordLastGoodPersists pins that recordLastGood writes, survives a
// loadCache round-trip, and stamps a non-zero timestamp.
func TestRecordLastGoodPersists(t *testing.T) {
	defer saveStateDir(t)()

	recordLastGood("162.159.192.99:2408")
	c := loadCache()
	if c.LastGood != "162.159.192.99:2408" {
		t.Fatalf("LastGood = %q, want 162.159.192.99:2408", c.LastGood)
	}
	if c.LastGoodAt.IsZero() {
		t.Fatalf("LastGoodAt is zero, want a timestamp")
	}
}

// TestRecordLastGoodEmptyIsNoop pins that an empty address is never recorded.
func TestRecordLastGoodEmptyIsNoop(t *testing.T) {
	defer saveStateDir(t)()

	recordLastGood("")
	if c := loadCache(); c.LastGood != "" {
		t.Fatalf("LastGood = %q, want empty", c.LastGood)
	}
}

// TestRecordLastGoodIdempotent pins that re-recording the same address does not
// rewrite the timestamp (no file churn on every connect).
func TestRecordLastGoodIdempotent(t *testing.T) {
	defer saveStateDir(t)()

	recordLastGood("a:1")
	first := loadCache().LastGoodAt
	time.Sleep(10 * time.Millisecond)
	recordLastGood("a:1")
	if got := loadCache().LastGoodAt; !got.Equal(first) {
		t.Fatalf("LastGoodAt changed on idempotent write: %v -> %v", first, got)
	}
}

// TestRecordLastGoodDoesNotForgeSuccessRate pins that recording last-good does
// NOT touch the endpoint's handshake success accounting — it is a separate
// "data plane proven" fact, never a forged successRate.
func TestRecordLastGoodDoesNotForgeSuccessRate(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.Endpoints = []endpointEntry{{Addr: "a:1", Attempts: 5, SuccessCount: 2}}
	c.save()

	recordLastGood("a:1")
	got := loadCache()
	if len(got.Endpoints) != 1 || got.Endpoints[0].Attempts != 5 || got.Endpoints[0].SuccessCount != 2 {
		t.Fatalf("recordLastGood mutated success accounting: %+v", got.Endpoints)
	}
	if got.LastGood != "a:1" {
		t.Fatalf("LastGood = %q, want a:1", got.LastGood)
	}
}

// TestCachedCandidatesLastGoodPriority pins the discovery order: seed first,
// then last-known-good (even when it is NOT the top handshake-ranked cache
// entry), then the rest of the cache by handshake success.
func TestCachedCandidatesLastGoodPriority(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.Endpoints = []endpointEntry{
		{Addr: "proven:1", Attempts: 10, SuccessCount: 9},  // successRate 0.83
		{Addr: "meh:1", Attempts: 2, SuccessCount: 0},      // 0.25
		{Addr: "lastgood:1", Attempts: 1, SuccessCount: 1}, // 0.67 (lower than proven)
	}
	c.LastGood = "lastgood:1"
	c.save()

	got := cachedCandidates("seed:1", "")
	want := []string{"seed:1", "lastgood:1", "proven:1", "meh:1"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", addrs(got), want)
	}
	for i := range want {
		if got[i].Addr != want[i] {
			t.Fatalf("cachedCandidates[%d] = %q, want %q (full: %v)", i, got[i].Addr, want[i], addrs(got))
		}
	}
}

// TestCachedCandidatesLastGoodDedup pins that a last-good that is also in the
// regular cache appears exactly once, and first.
func TestCachedCandidatesLastGoodDedup(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.Endpoints = []endpointEntry{
		{Addr: "lastgood:1", Attempts: 1, SuccessCount: 1},
		{Addr: "other:1", Attempts: 1, SuccessCount: 1},
	}
	c.LastGood = "lastgood:1"
	c.save()

	got := cachedCandidates("", "")
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2 (dedup): %v", len(got), addrs(got))
	}
	if got[0].Addr != "lastgood:1" {
		t.Fatalf("first candidate = %q, want lastgood:1", got[0].Addr)
	}
}

// TestCachedCandidatesExcludeStillSkipsLastGood pins that the exclude filter
// applies to the last-good slot too (a just-failed endpoint must not be handed
// straight back on the very next attempt).
func TestCachedCandidatesExcludeStillSkipsLastGood(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.Endpoints = []endpointEntry{{Addr: "lastgood:1", Attempts: 1, SuccessCount: 1}, {Addr: "other:1", Attempts: 1, SuccessCount: 1}}
	c.LastGood = "lastgood:1"
	c.save()

	got := cachedCandidates("", "lastgood:1")
	if len(got) != 1 || got[0].Addr != "other:1" {
		t.Fatalf("got %v, want [other:1] (excluded last-good)", addrs(got))
	}
}
