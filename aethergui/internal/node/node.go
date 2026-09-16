// Package node models the "airport-style" node list. A node is one reachable
// WARP/MASQUE edge: an IP in Cloudflare's published ranges, the port it answers
// on, its measured latency, and the exit-country metadata we fill in once the
// tunnel is up. The core owns discovery; this package only measures and maps
// edges to friendly entries.
package node

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

// Quality buckets for latency.
type Quality string

const (
	QExcellent Quality = "Excellent"
	QGood      Quality = "Good"
	QMedium    Quality = "Medium"
	QPoor      Quality = "Poor"
)

// LatencyQuality maps ms to the quality bucket.
func LatencyQuality(ms int64) Quality {
	switch {
	case ms <= 100:
		return QExcellent
	case ms <= 200:
		return QGood
	case ms <= 400:
		return QMedium
	default:
		return QPoor
	}
}

// Status of a node row.
type Status string

const (
	StAvailable    Status = "Available"
	StTesting      Status = "Testing"
	StUnavailable  Status = "Unavailable"
	StConnected    Status = "Connected"
)

// Node is one edge entry in the list.
type Node struct {
	ID       string `json:"id"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Label    string `json:"label"`      // "Japan", "United States", ...
	Flag     string `json:"flag"`       // "🇯🇵"
	Country  string `json:"country"`    // "Japan"
	Colo     string `json:"colo"`       // Cloudflare datacentre that answered (NRT, LAX, …)
	ExitIP   string `json:"exit_ip"`    // filled after a real connection
	ExitCountry string `json:"exit_country"`
	LatencyMs int64 `json:"latency_ms"` // 0 = never measured
	TCPMs    int64 `json:"tcp_ms"`
	HTTPSMs  int64 `json:"https_ms"`
	Status   Status `json:"status"`
	LastTest time.Time `json:"last_test"`
}

// Addr returns "ip:port".
func (n *Node) Addr() string { return fmt.Sprintf("%s:%d", n.IP, n.Port) }

// Pool is the observable node list.
type Pool struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	order []string
	subMu sync.Mutex
	subs  []func()
}

func NewPool() *Pool {
	return &Pool{nodes: map[string]*Node{}}
}

// Subscribe fires on every mutation.
func (p *Pool) Subscribe(fn func()) {
	p.subMu.Lock()
	p.subs = append(p.subs, fn)
	p.subMu.Unlock()
}

func (p *Pool) publish() {
	p.subMu.Lock()
	subs := append([]func(){}, p.subs...)
	p.subMu.Unlock()
	for _, fn := range subs {
		fn()
	}
}

// seedRanges are Cloudflare edge CIDRs the core scans (prober.rs mirrors).
// We sample a few addresses per range for the node list; the real sweep is
// done by the core itself.
var seedRanges = []string{
	"162.159.196.0/24", "162.159.195.0/24", "162.159.192.0/24", "162.159.193.0/24",
	"162.159.204.0/24", "162.159.197.0/24", "162.159.198.0/24", "172.65.251.0/24",
	"188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24",
	"162.159.36.0/24", "162.159.46.0/24",
}

// masquePorts mirrors prober::MASQUE_PORTS.
var masquePorts = []int{443, 500, 1701, 4500, 4443, 8443, 8095}

// Seed populates the pool with a deterministic sample of edges: one address
// from every range on port 443, plus a couple of alternates.
func (p *Pool) Seed() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nodes = map[string]*Node{}
	p.order = p.order[:0]
	rng := rand.New(rand.NewSource(1))
	for _, cidr := range seedRanges {
		ip := pickIP(rng, cidr)
		if ip == "" {
			continue
		}
		n := &Node{
			ID: ip, IP: ip, Port: 443,
			Label: "Edge " + ip, Flag: "🌐", Country: "",
			Status: StAvailable,
		}
		p.nodes[n.ID] = n
		p.order = append(p.order, n.ID)
	}
}

func pickIP(rng *rand.Rand, cidr string) string {
	_, net4, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip := net4.IP.To4()
	if ip == nil {
		return ""
	}
	n := rng.Intn(254) + 1
	ip[3] = byte(n)
	return ip.String()
}

// List returns the nodes in stable order.
func (p *Pool) List() []Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Node, 0, len(p.order))
	for _, id := range p.order {
		if n, ok := p.nodes[id]; ok {
			out = append(out, *n)
		}
	}
	return out
}

// Get fetches one node.
func (p *Pool) Get(id string) (Node, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n, ok := p.nodes[id]
	if !ok {
		return Node{}, false
	}
	return *n, true
}

// MarkConnected flags the given edge as the connected one.
func (p *Pool) MarkConnected(id string) {
	p.mu.Lock()
	for _, n := range p.nodes {
		if n.ID == id {
			n.Status = StConnected
		} else if n.Status == StConnected {
			n.Status = StAvailable
		}
	}
	p.mu.Unlock()
	p.publish()
}

// UpdateExit records the observed exit on the connected node.
func (p *Pool) UpdateExit(id, exitIP, exitCountry, flag string) {
	p.mu.Lock()
	if n, ok := p.nodes[id]; ok {
		n.ExitIP = exitIP
		n.ExitCountry = exitCountry
		if flag != "" {
			n.Flag = flag
			if exitCountry != "" {
				n.Label = exitCountry
				n.Country = exitCountry
			}
		}
	}
	p.mu.Unlock()
	p.publish()
}

// UpdateColo records which Cloudflare datacentre answered this edge.
func (p *Pool) UpdateColo(id, colo string) {
	p.mu.Lock()
	if n, ok := p.nodes[id]; ok {
		n.Colo = colo
	}
	p.mu.Unlock()
	p.publish()
}

// ClearStatus resets every node to Available.
func (p *Pool) ClearStatus() {
	p.mu.Lock()
	for _, n := range p.nodes {
		n.Status = StAvailable
	}
	p.mu.Unlock()
	p.publish()
}

// UpdateLatency stores a latency result.
func (p *Pool) UpdateLatency(id string, tcpMs, httpsMs int64) {
	p.mu.Lock()
	if n, ok := p.nodes[id]; ok {
		n.TCPMs = tcpMs
		n.HTTPSMs = httpsMs
		if tcpMs > 0 && (n.LatencyMs == 0 || tcpMs < n.LatencyMs) {
			n.LatencyMs = tcpMs
		}
		n.LastTest = time.Now()
		if n.Status == StAvailable && tcpMs == 0 {
			n.Status = StUnavailable
		} else if n.Status == StUnavailable && tcpMs > 0 {
			n.Status = StAvailable
		}
	}
	p.mu.Unlock()
	p.publish()
}

// SortByLatency reorders the visible list by measured latency (unmeasured last).
func (p *Pool) SortByLatency() {
	p.mu.Lock()
	sort.SliceStable(p.order, func(i, j int) bool {
		a, b := p.nodes[p.order[i]], p.nodes[p.order[j]]
		if a == nil || b == nil {
			return false
		}
		if a.LatencyMs == 0 && b.LatencyMs == 0 {
			return a.ID < b.ID
		}
		if a.LatencyMs == 0 {
			return false
		}
		if b.LatencyMs == 0 {
			return true
		}
		return a.LatencyMs < b.LatencyMs
	})
	p.mu.Unlock()
	p.publish()
}

// TCPing measures a TCP handshake latency to ip:port.
func TCPing(ctx context.Context, addr string, timeout time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	_ = c.Close()
	return time.Since(start).Milliseconds(), nil
}
