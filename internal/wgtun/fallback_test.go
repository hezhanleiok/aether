//go:build wgtun

package wgtun

import "testing"

// TestFallbackCandidatesBasic pins that the candidates AFTER `current` are
// returned, capped by budget (candidate source for connect-stage fallback).
func TestFallbackCandidatesBasic(t *testing.T) {
	cands := []liveEndpoint{{Addr: "a"}, {Addr: "b"}, {Addr: "c"}, {Addr: "d"}}
	got := fallbackCandidates(cands, "a", 2)
	want := []string{"b", "c"}
	if len(got) != len(want) {
		t.Fatalf("fallbackCandidates = %v, want %v", addrs(got), want)
	}
	for i := range want {
		if got[i].Addr != want[i] {
			t.Fatalf("fallbackCandidates[%d] = %q, want %q (full %v)", i, got[i].Addr, want[i], addrs(got))
		}
	}
}

// TestFallbackCandidatesBudgetCap pins that only `budget` later candidates are
// returned even when more exist (F4 budget exhaustion boundary).
func TestFallbackCandidatesBudgetCap(t *testing.T) {
	cands := []liveEndpoint{{Addr: "a"}, {Addr: "b"}, {Addr: "c"}, {Addr: "d"}, {Addr: "e"}}
	got := fallbackCandidates(cands, "a", 2)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (budget cap), got %v", len(got), addrs(got))
	}
	if got[0].Addr != "b" || got[1].Addr != "c" {
		t.Fatalf("fallbackCandidates = %v, want [b c]", addrs(got))
	}
}

// TestFallbackCandidatesCurrentAbsent pins that an absent current yields nil
// (no panic, no fabricated candidates) — F5's empty-fallback path.
func TestFallbackCandidatesCurrentAbsent(t *testing.T) {
	cands := []liveEndpoint{{Addr: "a"}, {Addr: "b"}}
	if got := fallbackCandidates(cands, "zzz", 2); got != nil {
		t.Fatalf("absent current should yield nil, got %v", addrs(got))
	}
}

// TestFallbackCandidatesLastIsEmpty pins that when current is the last
// candidate there are no later candidates (F5: no later candidate, no panic).
func TestFallbackCandidatesLastIsEmpty(t *testing.T) {
	cands := []liveEndpoint{{Addr: "a"}, {Addr: "b"}}
	got := fallbackCandidates(cands, "b", 2)
	if len(got) != 0 {
		t.Fatalf("last candidate should yield empty, got %v", addrs(got))
	}
}

// TestFallbackCandidatesExcludesCurrentAndEarlier pins that candidates at or
// before `current` are never re-offered (A and A's earlier handshake failures
// are out of scope for the fallback).
func TestFallbackCandidatesExcludesCurrentAndEarlier(t *testing.T) {
	cands := []liveEndpoint{{Addr: "x"}, {Addr: "a"}, {Addr: "b"}, {Addr: "c"}}
	got := fallbackCandidates(cands, "a", 2)
	if len(got) != 2 || got[0].Addr != "b" || got[1].Addr != "c" {
		t.Fatalf("fallbackCandidates = %v, want [b c] (never x or a)", addrs(got))
	}
}
