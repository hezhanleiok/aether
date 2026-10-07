//go:build wgtun

package wgtun

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// This file implements a PARALLEL handshake pre-screen for the cold-connect
// path (the WARPSCOUT idea, adapted to the hard constraint that only ONE real
// tunnel may ever touch the system routing table / DNS / a wintun adapter).
//
// The disposable "device" used here is a pure user-space wireguard-go device
// whose TUN is a dummy (it discards everything and never creates a wintun
// adapter) and whose socket is a plain host UDP bind. A disposable handshake
// therefore ranks a candidate list by "did this endpoint actually complete a
// WireGuard handshake" — the thing the stateless UDP liveness probe cannot
// tell (2026-10-05: 8 of 12 probe-live candidates timed out at handshake) —
// without ever competing for the default route.
//
// The result is a RANKING hint only. The real tunnel (handshakeAcross) still
// handshakes every candidate it tries, so a disposable handshake that does not
// reproduce on the real tunnel is harmless: it merely cost a slot ahead of a
// candidate that might have worked.

// handshakeProbeWorkers bounds concurrent disposable handshakes. It is well
// below udpProbeWorkers: each disposable device spawns wireguard-go's full
// worker set, so this is a CPU/memory bound, not a link-saturation bound.
const handshakeProbeWorkers = 6

// handshakeProbeTimeout is the per-candidate disposable handshake deadline. It
// must cover WireGuard's 5s initiation retry (RekeyTimeout) plus a slow RTT,
// but stays below the real tunnel's handshakeTimeout: a disposable probe that
// is not going to answer should fail fast so the ranking finishes promptly.
const handshakeProbeTimeout = 8 * time.Second

// dummyTun is a tun.Device that discards every packet and never touches the
// system: it lets a wireguard-go device run a handshake without creating a
// wintun adapter, assigning addresses, or installing routes.
type dummyTun struct {
	mtu    int
	closed chan struct{}
	ev     chan tun.Event
}

func newDummyTun(mtu int) *dummyTun {
	if mtu <= 0 {
		mtu = 1280
	}
	return &dummyTun{mtu: mtu, closed: make(chan struct{}), ev: make(chan tun.Event, 1)}
}

func (d *dummyTun) File() *os.File { return nil }

// Read blocks until Close, mirroring a real TUN that has no packets until it is
// torn down. wireguard-go's RoutineReadFromTUN calls this in a loop; blocking
// (instead of spinning) is what keeps a disposable device cheap.
func (d *dummyTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-d.closed
	return 0, os.ErrClosed
}

func (d *dummyTun) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }

func (d *dummyTun) MTU() (int, error) { return d.mtu, nil }

func (d *dummyTun) Name() (string, error) { return "probe", nil }

func (d *dummyTun) Events() <-chan tun.Event { return d.ev }

func (d *dummyTun) Close() error {
	select {
	case <-d.closed:
	default:
		close(d.closed)
		close(d.ev)
	}
	return nil
}

func (d *dummyTun) BatchSize() int { return 1 }

// probeHandshakeOnce runs one disposable handshake against endpoint and reports
// whether it completed. It is a pure ranking primitive: no system mutation.
// Junk is zeroed so the probe is a bare WireGuard handshake — the AWG decoys
// are a property of the real session, and a ranking must not depend on them.
func probeHandshakeOnce(ctx context.Context, cfg Config, endpoint string, timeout time.Duration) bool {
	probeCfg := cfg
	probeCfg.Endpoint = endpoint
	probeCfg.JunkCount, probeCfg.JunkMinSize, probeCfg.JunkMaxSize = 0, 0, 0
	probeCfg.JunkI1 = nil
	conf, err := buildUAPI(probeCfg)
	if err != nil {
		return false
	}
	logger := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(string, ...any) {},
	}
	dev := device.NewDevice(newDummyTun(probeCfg.MTU), conn.NewDefaultBind(), logger)
	defer dev.Close()
	if err := dev.IpcSet(conf); err != nil {
		return false
	}
	if err := dev.Up(); err != nil {
		return false
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		if s, err := dev.IpcGet(); err == nil && hasHandshake(s) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// probeHandshakeOnceFn is the injectable seam for the disposable handshake probe
// (overridden in tests so the parallel ranking is exercised without the network).
var probeHandshakeOnceFn = probeHandshakeOnce

// rankCandidatesByHandshake runs a PARALLEL disposable handshake across the
// candidate list (dummy TUN + host UDP bind, handshakeProbeWorkers concurrent)
// and returns ONLY the candidates that actually completed a WireGuard handshake,
// in completion order. It is a validation/ranking pass, NOT a substitute for the
// real tunnel: the caller still handshakes the returned candidates on the real
// device. First success wins — the moment one candidate handshakes, the derived
// context is cancelled so the remaining probes (and the scheduling loop) stop
// promptly instead of waiting out a slow candidate's full timeout. A candidate
// that failed the disposable probe is dropped: the real tunnel must never burn a
// full handshakeTimeout on it.
func rankCandidatesByHandshake(ctx context.Context, cfg Config, cands []liveEndpoint) []liveEndpoint {
	// <2 candidates: nothing to rank — return unchanged so the real tunnel still
	// attempts the (single) candidate (a lone endpoint must not be dropped on a
	// disposable-probe false negative).
	if len(cands) < 2 || ctx.Err() != nil {
		return cands
	}
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu        sync.Mutex
		succeeded []liveEndpoint
		wg        sync.WaitGroup
	)
	sem := make(chan struct{}, handshakeProbeWorkers)

schedule:
	for _, c := range cands {
		select {
		case sem <- struct{}{}:
		case <-probeCtx.Done():
			break schedule
		}
		wg.Add(1)
		go func(c liveEndpoint) {
			defer wg.Done()
			defer func() { <-sem }()
			if !probeHandshakeOnceFn(probeCtx, cfg, c.Addr, handshakeProbeTimeout) {
				return
			}
			mu.Lock()
			succeeded = append(succeeded, c)
			mu.Unlock()
			cancel() // first success wins: stop every other probe
		}(c)
	}
	wg.Wait()

	if len(succeeded) > 0 {
		logx.Infof("[wgtun] parallel handshake pre-screen: %d/%d candidates handshaked", len(succeeded), len(cands))
	}
	return succeeded
}
