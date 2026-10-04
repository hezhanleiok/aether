//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// TestProbeCandidatesCancel verifies that a cancelled context makes
// probeCandidates return immediately — before the fast path, and therefore
// before any UDP liveness sweep. This is the mechanism behind the GUI cancel
// button: a connect cancelled mid-scan must not keep emitting UDP.
func TestProbeCandidatesCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel: simulates a cancel fired before/while probing

	start := time.Now()
	_, err := probeCandidates(ctx, Config{}, "", false, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("probeCandidates with cancelled ctx: got nil error, want context.Canceled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("probeCandidates with cancelled ctx: want context.Canceled, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("probeCandidates with cancelled ctx should return without probing, took %v", elapsed)
	}
}

// TestWarpPortsExpanded verifies the port pool covers the official 54-port set,
// including the two ports that actually succeeded for this host historically
// (903, 3581) and the original 4 priority ports.
func TestWarpPortsExpanded(t *testing.T) {
	have := map[int]bool{}
	for _, p := range warpPorts {
		have[p] = true
	}
	for _, w := range []int{4500, 2408, 500, 1701, 903, 3581} {
		if !have[w] {
			t.Errorf("warpPorts missing %d", w)
		}
	}
	if len(warpPorts) != 54 {
		t.Errorf("len(warpPorts) = %d, want 54", len(warpPorts))
	}
}

// TestBuildCandidatesFullCoverage proves the candidate pool now samples every
// host of every /24 prefix (full /24 coverage) with one port per host mapped by
// host%54 — the reference scanner's strategy that reaches the drifting endpoints
// the old {.7,.8}×all-ports sampling missed.
func TestBuildCandidatesFullCoverage(t *testing.T) {
	got := buildCandidates("")
	// 8 prefixes × 254 hosts = 2032 (plus any cached endpoints on a dev machine).
	if len(got) < len(cfIPv4Prefixes)*254 {
		t.Fatalf("buildCandidates full pool = %d, want >= %d", len(got), len(cfIPv4Prefixes)*254)
	}

	// Every pooled endpoint must be a valid host:port.
	seen := map[string]bool{}
	for _, ep := range got {
		host, portStr, err := net.SplitHostPort(ep)
		if err != nil {
			t.Fatalf("bad candidate %q: %v", ep, err)
		}
		if host == "" || portStr == "" {
			t.Fatalf("bad candidate %q", ep)
		}
		seen[ep] = true
	}
	if len(seen) != len(got) {
		t.Errorf("duplicate candidates: %d unique of %d", len(seen), len(got))
	}

	// Spot-check host%54 port mapping: host 1 maps to warpPorts[1].
	want := "162.159.192.1:2408" // warpPorts[1] == 2408
	found := false
	for _, ep := range got {
		if ep == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %s in the pool (host%%54 mapping broken)", want)
	}
}
