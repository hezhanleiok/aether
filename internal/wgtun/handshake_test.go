//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// saveHandshakeSeams snapshots and restores the seams the handshake-path tests
// override, and points stateDir at a temp dir so recordProbed never touches the
// real cache.
func saveHandshakeSeams(t *testing.T) func() {
	t.Helper()
	origProbe, origCands, origDir := probeHandshakeOnceFn, probeCandidatesFn, stateDir
	stateDir = t.TempDir()
	return func() {
		probeHandshakeOnceFn, probeCandidatesFn, stateDir = origProbe, origCands, origDir
	}
}

// TestRankCandidatesConcurrent pins that the disposable handshake probes many
// candidates IN PARALLEL: three ~60ms probes finish in ~60ms, not ~180ms serial.
// The exact survivor count is intentionally not asserted — first-success-wins
// cancels the rest, so the result is a small (racy) subset.
func TestRankCandidatesConcurrent(t *testing.T) {
	defer saveHandshakeSeams(t)()
	probeHandshakeOnceFn = func(ctx context.Context, _ Config, _ string, _ time.Duration) bool {
		select {
		case <-time.After(60 * time.Millisecond):
			return true
		case <-ctx.Done():
			return false
		}
	}
	cands := []liveEndpoint{{Addr: "a:1"}, {Addr: "b:1"}, {Addr: "c:1"}}
	start := time.Now()
	got := rankCandidatesByHandshake(context.Background(), Config{}, cands)
	elapsed := time.Since(start)
	if len(got) < 1 {
		t.Fatalf("got no successes, want >=1")
	}
	if elapsed >= 150*time.Millisecond {
		t.Fatalf("candidates were not probed in parallel: elapsed = %v", elapsed)
	}
}

// TestRankCandidatesFirstSuccessCancelsOthers pins the "first success wins"
// contract: the moment one candidate handshakes, the other probes observe a
// cancelled context and stop instead of running to completion.
func TestRankCandidatesFirstSuccessCancelsOthers(t *testing.T) {
	defer saveHandshakeSeams(t)()
	var mu sync.Mutex
	cancelled := map[string]bool{}
	probeHandshakeOnceFn = func(ctx context.Context, _ Config, endpoint string, _ time.Duration) bool {
		if endpoint == "a:1" {
			return true // immediate success
		}
		select {
		case <-ctx.Done():
			mu.Lock()
			cancelled[endpoint] = true
			mu.Unlock()
		case <-time.After(3 * time.Second):
		}
		return false
	}
	cands := []liveEndpoint{{Addr: "a:1"}, {Addr: "b:1"}, {Addr: "c:1"}}
	got := rankCandidatesByHandshake(context.Background(), Config{}, cands)
	if len(got) != 1 || got[0].Addr != "a:1" {
		t.Fatalf("got %v, want exactly [a:1]", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if !cancelled["b:1"] || !cancelled["c:1"] {
		t.Fatalf("remaining probes were not cancelled: %v", cancelled)
	}
}

// TestRankCandidatesSlowDoesNotBlockFast pins that a slow candidate cannot delay
// the whole ranking: a fast success cancels the slow ones promptly.
func TestRankCandidatesSlowDoesNotBlockFast(t *testing.T) {
	defer saveHandshakeSeams(t)()
	probeHandshakeOnceFn = func(ctx context.Context, _ Config, endpoint string, _ time.Duration) bool {
		if endpoint == "fast:1" {
			return true
		}
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
		return false
	}
	cands := []liveEndpoint{{Addr: "slow1:1"}, {Addr: "fast:1"}, {Addr: "slow2:1"}}
	start := time.Now()
	got := rankCandidatesByHandshake(context.Background(), Config{}, cands)
	elapsed := time.Since(start)
	if len(got) != 1 || got[0].Addr != "fast:1" {
		t.Fatalf("got %v, want [fast:1]", got)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("slow candidates blocked the fast success: elapsed = %v", elapsed)
	}
}

// TestRankCandidatesAllFail pins that when no candidate completes a disposable
// handshake, the ranking returns an empty list (the caller fails loudly).
func TestRankCandidatesAllFail(t *testing.T) {
	defer saveHandshakeSeams(t)()
	probeHandshakeOnceFn = func(context.Context, Config, string, time.Duration) bool {
		return false
	}
	cands := []liveEndpoint{{Addr: "a:1"}, {Addr: "b:1"}}
	if got := rankCandidatesByHandshake(context.Background(), Config{}, cands); len(got) != 0 {
		t.Fatalf("got %v, want empty (all failed)", got)
	}
}

// TestRankCandidatesContextCancel pins that an outer cancellation stops the
// ranking (the derived probe context is cancelled).
func TestRankCandidatesContextCancel(t *testing.T) {
	defer saveHandshakeSeams(t)()
	probeHandshakeOnceFn = func(ctx context.Context, _ Config, _ string, _ time.Duration) bool {
		<-ctx.Done()
		return false
	}
	ctx, cancel := context.WithCancel(context.Background())
	cands := []liveEndpoint{{Addr: "a:1"}, {Addr: "b:1"}}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if got := rankCandidatesByHandshake(ctx, Config{}, cands); len(got) != 0 {
		t.Fatalf("got %v, want empty (cancelled)", got)
	}
}

// TestHandshakeCandidatesWarmFailThenSweepAndRank pins the P3 orchestration:
// a warm path that fails re-discovers via the sweep, ranks with the parallel
// disposable handshake, and then hands the REAL tunnel only the candidates that
// actually completed a disposable handshake (never the serial full list).
func TestHandshakeCandidatesWarmFailThenSweepAndRank(t *testing.T) {
	defer saveHandshakeSeams(t)()

	probeCandidatesFn = func(_ context.Context, _ Config, _ string, useSweep bool, _ func(string)) ([]liveEndpoint, bool, error) {
		if !useSweep {
			return []liveEndpoint{{Addr: "seed:1"}}, false, nil
		}
		return []liveEndpoint{{Addr: "swept-a:1"}, {Addr: "swept-b:1"}, {Addr: "swept-c:1"}}, true, nil
	}
	probeHandshakeOnceFn = func(_ context.Context, _ Config, endpoint string, _ time.Duration) bool {
		return endpoint == "swept-b:1" // only one swept candidate actually handshakes
	}

	var handshakeCalls [][]liveEndpoint
	handshake := func(cs []liveEndpoint, _ time.Duration) (string, error) {
		handshakeCalls = append(handshakeCalls, cs)
		if cs[0].Addr == "seed:1" {
			return "", errors.New("seed failed")
		}
		return cs[0].Addr, nil
	}
	var setCalls []string
	setEndpoint := func(ep string) error { setCalls = append(setCalls, ep); return nil }

	cands := []liveEndpoint{{Addr: "seed:1"}}
	connected, err := handshakeCandidates(context.Background(), Config{}, cands, false, nil, newPhaseTimer("test"), handshake, setEndpoint)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if connected != "swept-b:1" {
		t.Fatalf("connected = %q, want swept-b:1", connected)
	}
	if len(handshakeCalls) != 2 {
		t.Fatalf("handshake called %d times, want 2 (warm + ranked)", len(handshakeCalls))
	}
	// The ranked handshake must contain ONLY the disposable-successful candidate.
	if len(handshakeCalls[1]) != 1 || handshakeCalls[1][0].Addr != "swept-b:1" {
		t.Fatalf("ranked handshake got %v, want [swept-b:1]", handshakeCalls[1])
	}
	if len(setCalls) != 1 || setCalls[0] != "swept-b:1" {
		t.Fatalf("setEndpoint calls = %v, want [swept-b:1]", setCalls)
	}
}

// TestHandshakeCandidatesColdPathRanks pins that the cold path (fromSweep true)
// skips the warm short-deadline handshake and goes straight to ranking.
func TestHandshakeCandidatesColdPathRanks(t *testing.T) {
	defer saveHandshakeSeams(t)()

	probeHandshakeOnceFn = func(_ context.Context, _ Config, endpoint string, _ time.Duration) bool {
		return endpoint == "cold-a:1"
	}
	var handshakeCalls [][]liveEndpoint
	handshake := func(cs []liveEndpoint, _ time.Duration) (string, error) {
		handshakeCalls = append(handshakeCalls, cs)
		return cs[0].Addr, nil
	}
	setEndpoint := func(string) error { return nil }

	cands := []liveEndpoint{{Addr: "cold-a:1"}, {Addr: "cold-b:1"}}
	connected, err := handshakeCandidates(context.Background(), Config{}, cands, true, nil, newPhaseTimer("test"), handshake, setEndpoint)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if connected != "cold-a:1" {
		t.Fatalf("connected = %q, want cold-a:1", connected)
	}
	// The cold path must NOT attempt the warm short-deadline handshake; it
	// ranks first, then handshakes once over the survivors.
	if len(handshakeCalls) != 1 || len(handshakeCalls[0]) != 1 || handshakeCalls[0][0].Addr != "cold-a:1" {
		t.Fatalf("cold handshake calls = %v, want a single [cold-a:1] handshake", handshakeCalls)
	}
}
