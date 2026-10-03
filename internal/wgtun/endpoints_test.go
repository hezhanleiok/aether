//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestProbeEndpointsCancel verifies that a cancelled context makes the probe
// loop return immediately at the first candidate boundary, without touching the
// tunnel (passed as nil here, since the ctx check happens before any handshake).
// This is the mechanism behind the GUI cancel button: a long 112-candidate sweep
// stops as soon as the in-flight handshake finishes and the next gap is reached.
//
// The ~tens of ms elapsed is loadCache/save disk I/O, not a handshake (which
// would be ~2s per candidate); the assertion only requires it to be far below a
// single handshake timeout.
func TestProbeEndpointsCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel: simulates a cancel fired before/while probing

	start := time.Now()
	_, err := probeEndpoints(ctx, nil, []string{"1.2.3.4:2408", "5.6.7.8:2408"}, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("probeEndpoints with cancelled ctx: got nil error, want context.Canceled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("probeEndpoints with cancelled ctx: want context.Canceled, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("probeEndpoints with cancelled ctx should return without a handshake, took %v", elapsed)
	}
}
