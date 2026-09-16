package app

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/node"
	"github.com/aethergui/aethergui/internal/vpn"
)

// testingNodes is true while a latency sweep is in flight (the UI shows it).
// probingNodes is true while the edge-location probe is running.
var (
	testingNodes atomic.Bool
	probingNodes atomic.Bool
)

// Nodes returns the current node pool in stable order.
func (a *App) Nodes() []node.Node { return a.Pool.List() }

// NodesTesting reports whether a latency sweep is running.
func (a *App) NodesTesting() bool { return testingNodes.Load() }

// NodesProbing reports whether the edge-location probe is running.
func (a *App) NodesProbing() bool { return probingNodes.Load() }

// ProbeNodes asks every not-yet-known node which Cloudflare datacentre serves
// it, so the list can show a real location and flag. Edges are anycast, so the
// answer is specific to this machine's route — no offline database can supply
// it. Already-probed nodes are skipped: the answer never changes.
func (a *App) ProbeNodes() {
	if !probingNodes.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer func() {
			probingNodes.Store(false)
			a.notifyNodes()
		}()
		var todo []node.Node
		for _, n := range a.Pool.List() {
			if n.Colo == "" {
				todo = append(todo, n)
			}
		}
		if len(todo) == 0 {
			return
		}
		logx.Infof("[app] locating %d edges", len(todo))
		sem := make(chan struct{}, 16)
		var wg sync.WaitGroup
		for _, n := range todo {
			wg.Add(1)
			sem <- struct{}{}
			go func(n node.Node) {
				defer wg.Done()
				defer func() { <-sem }()
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				colo, err := node.ProbeColo(ctx, n.Addr(), 6*time.Second)
				if err != nil || colo == "" {
					return
				}
				a.Pool.UpdateColo(n.ID, colo)
			}(n)
		}
		wg.Wait()
		logx.Infof("[app] edge location probe finished")
	}()
}

// ActiveNodeID returns the pool entry that matches the pinned gateway or the
// node flagged as connected; "" means automatic selection.
func (a *App) ActiveNodeID() string {
	for _, n := range a.Pool.List() {
		if n.Status == node.StConnected {
			return n.ID
		}
	}
	gw := a.Settings.CachedGateway
	if gw == "" {
		return ""
	}
	for _, n := range a.Pool.List() {
		if n.Addr() == gw {
			return n.ID
		}
	}
	return ""
}

// TestAllNodes measures a real TCP handshake against every node in the pool
// and reorders the list by the measured latency. Safe to call repeatedly: a
// second call while a sweep runs is ignored.
func (a *App) TestAllNodes() {
	if !testingNodes.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer func() {
			testingNodes.Store(false)
			a.notifyNodes()
		}()
		list := a.Pool.List()
		logx.Infof("[app] testing %d nodes", len(list))
		sem := make(chan struct{}, 32)
		var wg sync.WaitGroup
		for _, n := range list {
			wg.Add(1)
			sem <- struct{}{}
			go func(n node.Node) {
				defer wg.Done()
				defer func() { <-sem }()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				ms, err := node.TCPing(ctx, n.Addr(), 2500*time.Millisecond)
				if err != nil {
					a.Pool.UpdateLatency(n.ID, 0, 0)
					return
				}
				a.Pool.UpdateLatency(n.ID, ms, 0)
			}(n)
		}
		wg.Wait()
		a.Pool.SortByLatency()
		logx.Infof("[app] node latency sweep finished")
		// Latency and location always go together in the UI.
		a.ProbeNodes()
	}()
}

// SelectNode pins one node as the gateway for the next connection and, when a
// tunnel is already up, reconnects through it right away.
func (a *App) SelectNode(id string) error {
	n, ok := a.Pool.Get(id)
	if !ok {
		return fmt.Errorf("node %s not found", id)
	}
	s := a.Settings
	s.CachedGateway = n.Addr()
	s.AutoScan = false
	s.LastNode = id
	if err := a.SaveSettings(s); err != nil {
		return err
	}
	logx.Infof("[app] node pinned: %s", n.Addr())
	a.reconnectIfUp()
	return nil
}

// SelectAutoNode clears the pinned gateway so the core scans for the best one.
func (a *App) SelectAutoNode() error {
	s := a.Settings
	s.CachedGateway = ""
	s.AutoScan = true
	s.LastNode = ""
	if err := a.SaveSettings(s); err != nil {
		return err
	}
	logx.Infof("[app] gateway selection: automatic (scan)")
	a.reconnectIfUp()
	return nil
}

// reconnectIfUp reapplies the gateway choice on a live tunnel.
func (a *App) reconnectIfUp() {
	switch a.VPN.State().Status {
	case vpn.StatusConnected, vpn.StatusConnecting, vpn.StatusReconnecting:
		a.Reconnect()
	}
}
