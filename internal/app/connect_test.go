//go:build wgtun

package app

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/coremgr"
	"github.com/aethergui/aethergui/internal/node"
	"github.com/aethergui/aethergui/internal/vpn"
	"github.com/aethergui/aethergui/internal/watchguard"
)

// newNativeApp builds a minimal App that takes the native path in tests.
// ExitChain makes the connect a NATIVE EXIT (the only thing the native
// transport exists for now); AWGI1="none" pins the transport to plain WG so
// exactly one transport attempt runs per connect (no AWG->WG fallback, which
// would double every hook count below). The native connect fails fast in the
// test environment (no warp-accounts dir), so no real tunnel is built. A
// non-nil (but empty) core is supplied so SetNativeState does not dereference
// a nil core; a zero-value Guard is supplied so Disconnect's SetUp call is
// safe without starting a real guard.
func newNativeApp() *App {
	return &App{
		VPN:   vpn.New(coremgr.NewManager(coremgr.NewProcessBackend())),
		Guard: &watchguard.Watch{},
		Pool:  &node.Pool{},
		Settings: config.Settings{
			NativeWireGuard:  true,
			Mode:             config.ModeWARP,
			StackedWireGuard: true,
			ExitChain:        vpn.ChainPsiphon,
			AWGI1:            "none", // plain WG, no fallback retry
		},
	}
}

// TestConcurrentConnectRejected proves the new re-entrancy guard: while one
// connect is in progress (blocked inside connectNativeStacked via
// connectEnterHook, holding connMu), a second concurrent Connect must return
// ErrAlreadyConnecting immediately — NOT block behind connMu for the whole
// probe. This is the fix for the old "two stacked connects build two wintun
// stacks" accident, now expressed as fail-fast rather than mutual exclusion.
func TestConcurrentConnectRejected(t *testing.T) {
	a := newNativeApp()

	entered := int32(0)
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	orig := connectEnterHook
	defer func() { connectEnterHook = orig }()
	connectEnterHook = func() {
		atomic.AddInt32(&entered, 1)
		once.Do(func() { close(started) })
		<-release // hold the first connect "in progress" until the test says go
	}

	errc := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { errc <- a.Connect() }()
	}

	<-started                         // first connect entered the native path and is blocked
	time.Sleep(50 * time.Millisecond) // give the second goroutine time to hit the CAS guard

	// The second connect must return ErrAlreadyConnecting promptly, not block.
	select {
	case err := <-errc:
		if !errors.Is(err, ErrAlreadyConnecting) {
			t.Fatalf("concurrent connect returned %v; want ErrAlreadyConnecting", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second concurrent connect blocked instead of returning ErrAlreadyConnecting")
	}

	// Only one connect ever entered the native path.
	if got := atomic.LoadInt32(&entered); got != 1 {
		t.Fatalf("native connect entered %d times during an in-progress connect; want 1", got)
	}

	close(release) // let the first (blocked) connect finish — it fails fast (no warp-accounts)
	<-errc         // drain the first connect's result
}

// TestConnectFailureResetsCAS proves the connect guard is reset on the failure
// path: after a connect fails (no warp-accounts in the test env), the CAS flag
// must be cleared so a subsequent Connect is allowed to enter the native path
// rather than being mis-rejected with ErrAlreadyConnecting.
func TestConnectFailureResetsCAS(t *testing.T) {
	a := newNativeApp()

	entered := int32(0)
	orig := connectEnterHook
	defer func() { connectEnterHook = orig }()
	connectEnterHook = func() { atomic.AddInt32(&entered, 1) }

	// First connect fails (no warp-accounts) but must reset the guard.
	if err := a.Connect(); err == nil {
		t.Fatal("expected first connect to fail in test env")
	}
	if got := atomic.LoadInt32(&entered); got != 1 {
		t.Fatalf("first connect entered native path %d times; want 1", got)
	}

	// Second connect must be allowed in (entered == 2), proving the stale CAS
	// flag did not linger and mis-reject it.
	if err := a.Connect(); err == nil {
		t.Fatal("expected second connect to also fail in test env")
	}
	if got := atomic.LoadInt32(&entered); got != 2 {
		t.Fatalf("second connect was blocked by stale CAS flag: entered=%d want 2", got)
	}
}

// TestReconnectClearsCAS proves the Reconnect path is not permanently disabled
// by a stale guard. Reconnect = Disconnect() + Connect() serially; Disconnect
// must clear the connect guard so the following Connect is not mis-rejected. We
// seed the guard as "set" (simulating an in-flight/aborted connect) and assert
// that after Reconnect the Connect actually enters the native path.
func TestReconnectClearsCAS(t *testing.T) {
	a := newNativeApp()

	// Simulate a stale guard left by a previous aborted connect.
	a.connecting.Store(true)

	entered := int32(0)
	orig := connectEnterHook
	defer func() { connectEnterHook = orig }()
	connectEnterHook = func() { atomic.AddInt32(&entered, 1) }

	a.Reconnect() // Disconnect() (clears guard) + Connect() (must enter)

	if got := atomic.LoadInt32(&entered); got != 1 {
		t.Fatalf("Reconnect's Connect was blocked by stale guard: entered=%d want 1", got)
	}
	if a.connecting.Load() {
		t.Fatal("connect guard not reset after Reconnect's Connect returned")
	}
}
