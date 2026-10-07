//go:build wgtun

package wgtun

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// saveDataPlaneSeams snapshots and restores the three injectable seams the
// data-plane retry tests override. Kept as a helper so each test is self-contained.
func saveDataPlaneSeams(t *testing.T) (restore func()) {
	t.Helper()
	origProbe, origInterval, origWindow := probeOnceWithFn, dataPlaneRetryInterval, dataPlaneSettleWindow
	return func() {
		probeOnceWithFn, dataPlaneRetryInterval, dataPlaneSettleWindow = origProbe, origInterval, origWindow
	}
}

// TestDataPlaneRetryShortInterval pins the P2 cadence: after an immediate
// WSAENETUNREACH the next probe fires at ~300ms, NOT the old 1.5s blind sleep.
func TestDataPlaneRetryShortInterval(t *testing.T) {
	defer saveDataPlaneSeams(t)()
	dataPlaneSettleWindow = 10 * time.Second // leave the real 300ms interval in place

	var mu sync.Mutex
	var stamps []time.Time
	probeOnceWithFn = func(*http.Client, time.Duration) error {
		mu.Lock()
		stamps = append(stamps, time.Now())
		n := len(stamps)
		mu.Unlock()
		if n == 1 {
			return syscall.ENETUNREACH
		}
		return nil // succeed on the 2nd attempt
	}

	start := time.Now()
	if err := probeTunnelDataPlane(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("err = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(stamps) != 2 {
		t.Fatalf("probe called %d times, want 2", len(stamps))
	}
	gap := stamps[1].Sub(stamps[0])
	if gap >= time.Second {
		t.Fatalf("retry gap = %v, want ~300ms (the old code slept 1.5s)", gap)
	}
	if gap < 100*time.Millisecond {
		t.Fatalf("retry gap = %v, want a real ~300ms interval", gap)
	}
	if elapsed := time.Since(start); elapsed >= 2*time.Second {
		t.Fatalf("total = %v, want well under the old 1.5s+1.5s settle", elapsed)
	}
}

// TestDataPlaneSucceedsMidwayStopsEarly pins that a mid-window success returns
// immediately and does not keep probing.
func TestDataPlaneSucceedsMidwayStopsEarly(t *testing.T) {
	defer saveDataPlaneSeams(t)()
	dataPlaneRetryInterval = 10 * time.Millisecond
	dataPlaneSettleWindow = 5 * time.Second

	var calls int32
	probeOnceWithFn = func(*http.Client, time.Duration) error {
		if atomic.AddInt32(&calls, 1) <= 3 {
			return syscall.ENETUNREACH
		}
		return nil
	}

	if err := probeTunnelDataPlane(context.Background(), 5*time.Second); err != nil {
		t.Fatalf("err = %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Fatalf("probe called %d times, want exactly 4 (stopped on success)", got)
	}
}

// TestDataPlaneCancelExitsImmediately pins that a cancelled connect returns
// context.Canceled at the next checkpoint instead of sleeping out the interval
// (or the whole settle window).
func TestDataPlaneCancelExitsImmediately(t *testing.T) {
	defer saveDataPlaneSeams(t)()
	dataPlaneRetryInterval = 10 * time.Millisecond
	dataPlaneSettleWindow = 5 * time.Second // long, but cancel must win

	ctx, cancel := context.WithCancel(context.Background())
	probeOnceWithFn = func(*http.Client, time.Duration) error {
		cancel() // the connect is abandoned while the first probe runs
		return syscall.ENETUNREACH
	}

	start := time.Now()
	err := probeTunnelDataPlane(ctx, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
		t.Fatalf("cancel exit took %v, want immediate", elapsed)
	}
}

// TestDataPlaneBudgetExhaustedFails pins that when the path never converges the
// loop still retries (short intervals) and then returns the last error.
func TestDataPlaneBudgetExhaustedFails(t *testing.T) {
	defer saveDataPlaneSeams(t)()
	dataPlaneRetryInterval = 10 * time.Millisecond
	dataPlaneSettleWindow = 50 * time.Millisecond

	var calls int32
	probeOnceWithFn = func(*http.Client, time.Duration) error {
		atomic.AddInt32(&calls, 1)
		return syscall.ENETUNREACH
	}

	err := probeTunnelDataPlane(context.Background(), 5*time.Second)
	if err == nil {
		t.Fatal("expected failure after the settle budget runs out")
	}
	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Fatalf("probe called %d times, want >=2 (retried before giving up)", got)
	}
}
