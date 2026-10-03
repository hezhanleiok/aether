//go:build wgtun

package wgtun

import "testing"

// isolateCache points stateDir at a temp dir so buildCandidates reads no real
// cache file left behind by earlier runs.
func isolateCache(t *testing.T) {
	t.Helper()
	orig := stateDir
	stateDir = t.TempDir()
	t.Cleanup(func() { stateDir = orig })
}

func TestBuildCandidates(t *testing.T) {
	isolateCache(t)
	seed := "162.159.192.100:2408"
	c := buildCandidates(seed)
	if len(c) == 0 {
		t.Fatal("empty candidates")
	}

	if c[0] != seed {
		t.Fatalf("seed not first: got %q", c[0])
	}

	// No cache, so the first pooled candidate is the 4500 lead.
	if c[1] != "8.6.112.7:4500" {
		t.Fatalf("expected 4500 priority first, got %q", c[1])
	}

	want := 1 + len(warpPoolsV4)*len(probeHosts)*len(warpPorts)
	if len(c) != want {
		t.Fatalf("candidate count = %d, want %d", len(c), want)
	}

	seen := make(map[string]bool, len(c))
	for _, ep := range c {
		if seen[ep] {
			t.Fatalf("duplicate endpoint %q", ep)
		}
		seen[ep] = true
	}
}

func TestBuildCandidatesSeedDedup(t *testing.T) {
	isolateCache(t)
	seed := "162.159.192.7:4500"
	c := buildCandidates(seed)
	if c[0] != seed {
		t.Fatalf("seed not first: %q", c[0])
	}
	for i, ep := range c[1:] {
		if ep == seed {
			t.Fatalf("seed %q duplicated at index %d", seed, i+1)
		}
	}
}

func TestBuildCandidatesNoSeed(t *testing.T) {
	isolateCache(t)
	c := buildCandidates("")
	if len(c) == 0 {
		t.Fatal("empty candidates without seed")
	}
	if c[0] != "8.6.112.7:4500" {
		t.Fatalf("expected 4500 lead, got %q", c[0])
	}
}

func TestBuildCandidatesCachePriority(t *testing.T) {
	isolateCache(t)
	var c endpointCache
	c.recordSuccess("9.9.9.9:4500", 40)  // fastest
	c.recordSuccess("9.9.9.8:4500", 120) // slower
	c.save()

	got := buildCandidates("")
	if got[0] != "9.9.9.9:4500" {
		t.Fatalf("fastest cached endpoint should lead, got %q", got[0])
	}
	if got[1] != "9.9.9.8:4500" {
		t.Fatalf("second cached endpoint wrong, got %q", got[1])
	}
	if got[2] != "8.6.112.7:4500" {
		t.Fatalf("pool lead should follow cache, got %q", got[2])
	}
}
