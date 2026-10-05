//go:build wgtun

package wgtun

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestPortVariants covers the cheapest failover move: the same host on the
// other WARP ports. Port, not host, is what gets blocked (observed 2026-10-04),
// so these must come out in the observed-stable order and never repeat the
// address we are already on.
func TestPortVariants(t *testing.T) {
	got := portVariants("8.35.211.174:500", nil)
	want := []string{"8.35.211.174:2408", "8.35.211.174:4500", "8.35.211.174:1701"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("portVariants = %v, want %v", got, want)
	}
	// Current address and anything already tried must be dropped.
	got = portVariants("8.35.211.174:2408", map[string]bool{"8.35.211.174:500": true})
	want = []string{"8.35.211.174:4500", "8.35.211.174:1701"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("portVariants (avoid) = %v, want %v", got, want)
	}
	// A malformed address yields nothing rather than a panic.
	if got := portVariants("not-an-endpoint", nil); len(got) != 0 {
		t.Fatalf("portVariants(bad) = %v, want empty", got)
	}
}

// TestFailoverCandidates locks in the ordering and the exclusions that make a
// failover safe: never the current endpoint, never one already tried this
// cycle, cheapest move (same host, other port) first, and a bounded list so a
// failover never has to wait for a full-pool sweep.
func TestFailoverCandidates(t *testing.T) {
	origDir := stateDir
	stateDir = t.TempDir()
	defer func() { stateDir = origDir }()

	current := "8.35.211.174:500"
	got := failoverCandidates(current, nil, 4)
	if len(got) == 0 {
		t.Fatal("failoverCandidates returned nothing")
	}
	if len(got) > 4 {
		t.Fatalf("failoverCandidates = %d entries, want <= 4 (bounded)", len(got))
	}
	// Same-host, other-port first.
	host, _, _ := net.SplitHostPort(got[0])
	if host != "8.35.211.174" {
		t.Fatalf("first candidate = %s, want a variant of the current host", got[0])
	}
	for _, ep := range got {
		if ep == current {
			t.Fatalf("candidate list contains the current endpoint %s", current)
		}
	}

	// skip must be honoured (this is what stops a failover retrying a candidate
	// that just failed).
	skip := map[string]bool{}
	for _, ep := range got {
		skip[ep] = true
	}
	next := failoverCandidates(current, skip, 4)
	for _, ep := range next {
		if skip[ep] {
			t.Fatalf("second round returned already-tried endpoint %s", ep)
		}
	}
}

// TestParseLastHandshakeSec covers the staleness signal used by the health
// monitor: newest peer wins, and "never handshaken" is 0 (not an error).
func TestParseLastHandshakeSec(t *testing.T) {
	cases := []struct {
		name string
		uapi string
		want int64
	}{
		{"empty", "", 0},
		{"never", "public_key=aa\nlast_handshake_time_sec=0\n", 0},
		{"one", "last_handshake_time_sec=1700000000\n", 1700000000},
		{"newest of two", "last_handshake_time_sec=100\nlast_handshake_time_sec=900\n", 900},
		{"garbage", "last_handshake_time_sec=abc\n", 0},
	}
	for _, c := range cases {
		if got := parseLastHandshakeSec(c.uapi); got != c.want {
			t.Fatalf("%s: parseLastHandshakeSec = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestProbeOnceCtxCancelled pins the interruptible probe (2026-10-05 fix): a
// stop context that is already cancelled must fail the probe immediately — no
// network round-trip, no waiting out the timeout. This is the seam Stop()
// uses to cut a running failover short instead of queueing behind its m.mu.
func TestProbeOnceCtxCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probeOnceCtx(ctx, 5*time.Second); err == nil {
		t.Fatal("probeOnceCtx with a cancelled ctx must fail immediately")
	}
}

// TestStopSetsStopReq pins the pre-lock half of the fix: Stop() must set the
// stop flag (on every path, including the instant no-op teardown), because a
// failover that is holding m.mu right now can only observe the stop through
// this flag — the lock itself will not be reached until the failover exits.
func TestStopSetsStopReq(t *testing.T) {
	m := &Manager{}
	if err := m.Stop(); err != nil {
		t.Fatalf("Stop on an idle Manager: %v", err)
	}
	if !m.stopReq.Load() {
		t.Fatal("Stop must set stopReq (the flag that interrupts an in-flight failover)")
	}
}

// TestFailoverAbortsWhenStopRequested proves the failover entry check: with
// stopReq already set (Stop() queued on m.mu), failover must return false
// without touching the (nil) tunnel or routes.
func TestFailoverAbortsWhenStopRequested(t *testing.T) {
	m := &Manager{}
	m.stopReq.Store(true)
	if m.failover() {
		t.Fatal("failover with stop requested must return false immediately")
	}
}

// TestHealLinkMetric pins the physical-link metric residue heal (2026-10-06):
// "automatic disabled + metric 0" — the state an interrupted run leaves behind,
// and one that BEATS the tunnel's metric 1, so the physical link keeps the
// default route — must be restored to automatic. Every other value, including a
// hand-set metric with automatic disabled, is preserved as captured.
func TestHealLinkMetric(t *testing.T) {
	cases := []struct {
		name       string
		metric     uint32
		auto       uint8
		wantMetric uint32
		wantAuto   uint8
	}{
		{"residue: auto off, metric 0", 0, 0, 0, 1},
		{"healthy automatic", 25, 1, 25, 1},
		{"hand-set metric, auto off", 10, 0, 10, 0},
		{"metric 0 but automatic on", 0, 1, 0, 1},
	}
	for _, c := range cases {
		gotMetric, gotAuto := healLinkMetric(c.metric, c.auto)
		if gotMetric != c.wantMetric || gotAuto != c.wantAuto {
			t.Fatalf("%s: healLinkMetric(%d, %d) = (%d, %d), want (%d, %d)",
				c.name, c.metric, c.auto, gotMetric, gotAuto, c.wantMetric, c.wantAuto)
		}
	}
}
