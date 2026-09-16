// Package watchguard watches the network and the tunnel, driving automatic
// reconnection and gateway failover:
//
//   - network change: Windows notifies us via NotifyAddrChange (async); we
//     debounce, verify connectivity, and reconnect if we were up.
//   - tunnel death: the core exits; the manager surfaces "stopped"; we
//     reconnect with a fresh scan (failover) or the cached gateway.
//   - gateway health: periodic SOCKS probe through the tunnel; on repeated
//     failure we consider the gateway dead and rescan.
package watchguard

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
)

// Notifier is the callback set the GUI (or tests) provide.
type Notifier interface {
	// NetworkChanged fires when the machine's connectivity changed.
	NetworkChanged()
	// TunnelDown fires when the tunnel died unexpectedly.
	TunnelDown()
	// GatewayUnhealthy fires when probes through the tunnel keep failing.
	GatewayUnhealthy()
}

// Config tunes the guard.
type Config struct {
	NetworkDebounce time.Duration // default 3s
	ProbeEvery      time.Duration // default 30s
	ProbeTimeout    time.Duration // default 8s
	ProbeURL        string        // default https://www.cloudflare.com/cdn-cgi/trace
	FailAfter       int           // consecutive failures before failover (3)
}

func (c *Config) fill() {
	if c.NetworkDebounce == 0 {
		c.NetworkDebounce = 3 * time.Second
	}
	if c.ProbeEvery == 0 {
		c.ProbeEvery = 30 * time.Second
	}
	if c.ProbeTimeout == 0 {
		c.ProbeTimeout = 8 * time.Second
	}
	if c.ProbeURL == "" {
		c.ProbeURL = "https://www.cloudflare.com/cdn-cgi/trace"
	}
	if c.FailAfter == 0 {
		c.FailAfter = 3
	}
}

// Watch is one running guard.
type Watch struct {
	cfg      Config
	n        Notifier
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	up       bool           // tunnel currently expected up
	fails    int
	client   *http.Client   // probes go through the tunnel (SOCKS)
	stopNet  chan struct{}
}

// New starts a guard.
func New(cfg Config, n Notifier, socksDial func(ctx context.Context, network, addr string) (net.Conn, error)) *Watch {
	cfg.fill()
	ctx, cancel := context.WithCancel(context.Background())
	w := &Watch{
		cfg:    cfg,
		n:      n,
		ctx:    ctx,
		cancel: cancel,
		client: &http.Client{Timeout: cfg.ProbeTimeout},
	}
	if socksDial != nil {
		w.client.Transport = &http.Transport{DialContext: socksDial}
	}
	go w.watchNetwork()
	go w.probeLoop()
	return w
}

// SetUp tells the guard the tunnel is (or is no longer) expected up.
func (w *Watch) SetUp(up bool) {
	w.mu.Lock()
	w.up = up
	if up {
		w.fails = 0
	}
	w.mu.Unlock()
}

// Close stops the guard.
func (w *Watch) Close() { w.cancel() }

// watchNetwork polls the machine's interfaces for address changes. A richer
// Windows-specific notifier (NotifyAddrChange) is provided in notify_windows.go.
func (w *Watch) watchNetwork() {
	last := snapshotAddrs()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-tick.C:
			cur := snapshotAddrs()
			if !sameAddrs(last, cur) {
				logx.Infof("[watchguard] network change detected")
				last = cur
				time.Sleep(w.cfg.NetworkDebounce)
				w.n.NetworkChanged()
			} else {
				last = cur
			}
		}
	}
}

func snapshotAddrs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			out = append(out, ifc.Name+"|"+a.String())
		}
	}
	return out
}

func sameAddrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if !set[y] {
			return false
		}
	}
	return true
}

// probeLoop checks the tunnel from the inside while it should be up.
func (w *Watch) probeLoop() {
	tick := time.NewTicker(w.cfg.ProbeEvery)
	defer tick.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-tick.C:
			w.mu.Lock()
			up := w.up
			w.mu.Unlock()
			if !up {
				continue
			}
			ctx, cancel := context.WithTimeout(w.ctx, w.cfg.ProbeTimeout)
			req, err := http.NewRequestWithContext(ctx, "GET", w.cfg.ProbeURL, nil)
			if err != nil {
				cancel()
				continue
			}
			resp, err := w.client.Do(req)
			if err != nil {
				w.mu.Lock()
				w.fails++
				fails := w.fails
				w.mu.Unlock()
				logx.Warnf("[watchguard] tunnel probe failed (%d/%d): %v", fails, w.cfg.FailAfter, err)
				if fails >= w.cfg.FailAfter {
					w.mu.Lock()
					w.fails = 0
					w.mu.Unlock()
					w.n.GatewayUnhealthy()
				}
			} else {
				resp.Body.Close()
				w.mu.Lock()
				w.fails = 0
				w.mu.Unlock()
			}
			cancel()
		}
	}
}
