//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"testing"
)

// TestProbePhaseFormat proves the progress-label pure function formats as the UI expects.
func TestProbePhaseFormat(t *testing.T) {
	if got := probePhase(37, 112); got != "probe 37/112" {
		t.Fatalf("probePhase(37,112) = %q; want %q", got, "probe 37/112")
	}
	if got := probePhase(1, 112); got != "probe 1/112" {
		t.Fatalf("probePhase(1,112) = %q; want %q", got, "probe 1/112")
	}
}

// TestProbeEndpointsCancelReportsNothing proves the phase callback is never fired
// once the context is already cancelled at a candidate boundary: a cancelled
// connect must not leave a stale "probe N/total" label behind (the UI only shows
// phase while Connecting, but a stray label after cancel would be wrong).
func TestProbeEndpointsCancelReportsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the sweep starts

	var calls int
	onPhase := func(string) { calls++ }

	// A single candidate with a cancelled context returns at the first boundary
	// without touching the (nil) tunnel or calling onPhase.
	_, err := probeEndpoints(ctx, nil, []string{"198.51.100.1:2408"}, onPhase)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
	if calls != 0 {
		t.Fatalf("onPhase called %d times after cancel; want 0", calls)
	}
}
