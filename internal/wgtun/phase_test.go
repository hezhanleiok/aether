//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"testing"
)

// TestProbeCandidatesCancelReportsNothing proves the phase callback is never
// fired once the context is already cancelled: a cancelled connect must not
// leave a stale progress label behind (the UI only shows phase while
// Connecting, but a stray label after cancel would be wrong).
func TestProbeCandidatesCancelReportsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before the probe starts

	var calls int
	onPhase := func(string) { calls++ }

	_, err := probeCandidates(ctx, Config{}, "", false, onPhase)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
	if calls != 0 {
		t.Fatalf("onPhase called %d times after cancel; want 0", calls)
	}
}
