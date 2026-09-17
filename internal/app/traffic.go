//go:build windows

package app

import (
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/aethergui/aethergui/internal/vpn"
)

// TrafficSample is one throughput snapshot for the UI.
type TrafficSample struct {
	DownBytesPerSec int64
	UpBytesPerSec   int64
	DownTotal       int64
	UpTotal         int64
	Valid           bool // false while disconnected
}

// TrafficPoint is one history sample: bytes per second at time T (unix ms).
type TrafficPoint struct {
	T    int64 `json:"t"`
	Down int64 `json:"down"`
	Up   int64 `json:"up"`
}

const (
	histSecMax = 3600 // 1 hour at 1s resolution
	histMinMax = 1440 // 24 hours at 60s resolution
)

// TrafficSampler measures throughput by reading the byte counters of the
// interface that carries the default route.
//
// It cannot use loopback: Windows does not account loopback traffic anywhere —
// the pseudo-interface has no NDIS counters (GetIfTable2 reports zeros) and the
// performance counters expose no loopback instance at all. The core is a
// user-space SOCKS5/HTTP proxy with no virtual adapter either, so the physical
// uplink is the only place where the tunnelled bytes are actually counted.
//
// Pure observation: it never sends traffic and never touches the tunnel.
//
// It also keeps two history rings so the UI can draw real 1m/5m/1h/1d charts:
// one at 1s resolution (last hour) and one at 60s resolution (last day).
type TrafficSampler struct {
	app  *App
	mu   sync.Mutex
	subs []func(TrafficSample)
	last TrafficSample

	prevIn, prevOut uint64
	havePrev        bool

	sec []TrafficPoint
	min []TrafficPoint

	minBucket int64
	minDown   int64
	minUp     int64
	minCount  int

	tick *time.Ticker
	stop chan struct{}
}

// NewTrafficSampler starts a 1s sampler (idle until the tunnel is up).
func NewTrafficSampler(a *App) *TrafficSampler {
	ts := &TrafficSampler{app: a, stop: make(chan struct{})}
	ts.tick = time.NewTicker(time.Second)
	go ts.loop()
	return ts
}

// Subscribe registers a listener; it fires immediately with the last sample.
func (ts *TrafficSampler) Subscribe(fn func(TrafficSample)) {
	ts.mu.Lock()
	ts.subs = append(ts.subs, fn)
	last := ts.last
	ts.mu.Unlock()
	fn(last)
}

func (ts *TrafficSampler) publish(s TrafficSample) {
	ts.mu.Lock()
	ts.last = s
	subs := append([]func(TrafficSample){}, ts.subs...)
	ts.mu.Unlock()
	for _, fn := range subs {
		fn(s)
	}
}

func (ts *TrafficSampler) loop() {
	for {
		select {
		case <-ts.stop:
			return
		case <-ts.tick.C:
			if ts.app.VPN.State().Status != vpn.StatusConnected {
				ts.mu.Lock()
				ts.havePrev = false
				ts.last = TrafficSample{}
				s := ts.last
				ts.mu.Unlock()
				ts.publish(s)
				continue
			}
			in, out, ok := uplinkOctets()
			if !ok {
				ts.publish(TrafficSample{Valid: false})
				continue
			}
			ts.mu.Lock()
			if !ts.havePrev {
				ts.prevIn, ts.prevOut, ts.havePrev = in, out, true
				ts.mu.Unlock()
				ts.publish(TrafficSample{Valid: true})
				continue
			}
			dIn := int64(in - ts.prevIn)
			dOut := int64(out - ts.prevOut)
			if dIn < 0 {
				dIn = 0
			}
			if dOut < 0 {
				dOut = 0
			}
			ts.prevIn, ts.prevOut = in, out
			ts.last.DownBytesPerSec = dIn
			ts.last.UpBytesPerSec = dOut
			ts.last.DownTotal += dIn
			ts.last.UpTotal += dOut
			ts.last.Valid = true
			ts.pushHistory(time.Now(), dIn, dOut)
			s := ts.last
			ts.mu.Unlock()
			ts.publish(s)
		}
	}
}

// pushHistory appends one second-resolution sample and rolls the
// minute-resolution ring over when the wall clock crosses a minute boundary.
// Caller must hold ts.mu.
func (ts *TrafficSampler) pushHistory(now time.Time, down, up int64) {
	ts.sec = append(ts.sec, TrafficPoint{T: now.UnixMilli(), Down: down, Up: up})
	if len(ts.sec) > histSecMax {
		ts.sec = append([]TrafficPoint(nil), ts.sec[len(ts.sec)-histSecMax:]...)
	}

	bucket := now.Unix() / 60
	if ts.minBucket == 0 {
		ts.minBucket = bucket
	}
	if bucket != ts.minBucket {
		if ts.minCount > 0 {
			ts.min = append(ts.min, TrafficPoint{
				T:    ts.minBucket * 60000,
				Down: ts.minDown / int64(ts.minCount),
				Up:   ts.minUp / int64(ts.minCount),
			})
			if len(ts.min) > histMinMax {
				ts.min = append([]TrafficPoint(nil), ts.min[len(ts.min)-histMinMax:]...)
			}
		}
		ts.minBucket = bucket
		ts.minDown, ts.minUp, ts.minCount = 0, 0, 0
	}
	ts.minDown += down
	ts.minUp += up
	ts.minCount++
}

// Series returns the throughput history for one UI range.
// range is one of "1m", "5m", "1h", "1d".
func (ts *TrafficSampler) Series(rng string) []TrafficPoint {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	switch rng {
	case "5m":
		return lastN(ts.sec, 300)
	case "1h":
		return downsample(ts.sec, 120)
	case "1d":
		out := append([]TrafficPoint(nil), ts.min...)
		if ts.minCount > 0 {
			out = append(out, TrafficPoint{
				T:    ts.minBucket * 60000,
				Down: ts.minDown / int64(ts.minCount),
				Up:   ts.minUp / int64(ts.minCount),
			})
		}
		return downsample(out, 120)
	default: // "1m"
		return lastN(ts.sec, 60)
	}
}

// Current returns the newest sample (bytes/sec + cumulative totals).
func (ts *TrafficSampler) Current() TrafficSample {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.last
}

func lastN(in []TrafficPoint, n int) []TrafficPoint {
	if len(in) <= n {
		return append([]TrafficPoint(nil), in...)
	}
	return append([]TrafficPoint(nil), in[len(in)-n:]...)
}

// downsample averages the series into at most target buckets so the chart keeps
// a constant point count across every range.
func downsample(in []TrafficPoint, target int) []TrafficPoint {
	if len(in) == 0 {
		return nil
	}
	if len(in) <= target {
		return append([]TrafficPoint(nil), in...)
	}
	size := (len(in) + target - 1) / target
	out := make([]TrafficPoint, 0, target+1)
	for i := 0; i < len(in); i += size {
		end := i + size
		if end > len(in) {
			end = len(in)
		}
		var d, u int64
		for _, p := range in[i:end] {
			d += p.Down
			u += p.Up
		}
		s := int64(end - i)
		out = append(out, TrafficPoint{T: in[i].T, Down: d / s, Up: u / s})
	}
	return out
}

// Close stops the sampler.
func (ts *TrafficSampler) Close() {
	select {
	case <-ts.stop:
	default:
		close(ts.stop)
	}
}

// uplinkOctets reads the cumulative In/Out octets of the interface behind the
// default route. ok=false when the counter cannot be read (soft-fail).
func uplinkOctets() (in, out uint64, ok bool) {
	idx, ok := defaultInterfaceIndex()
	if !ok {
		return 0, 0, false
	}
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil {
		return 0, 0, false
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	n := int(table.NumEntries)
	if n == 0 {
		return 0, 0, false
	}
	rows := (*[1 << 16]windows.MibIfRow2)(unsafe.Pointer(&table.Table[0]))[:n:n]
	for i := range rows {
		if rows[i].InterfaceIndex == idx {
			return rows[i].InOctets, rows[i].OutOctets, true
		}
	}
	return 0, 0, false
}

// defaultInterfaceIndex resolves the interface index behind the default route
// by asking the OS which local address it would use to reach the internet.
func defaultInterfaceIndex() (uint32, bool) {
	// A UDP "connection" performs no traffic but makes the routing decision.
	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP == nil {
		return 0, false
	}

	var table *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_INET, &table); err != nil {
		return 0, false
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))

	n := int(table.NumEntries)
	if n == 0 {
		return 0, false
	}
	rows := (*[1 << 16]windows.MibUnicastIpAddressRow)(unsafe.Pointer(&table.Table[0]))[:n:n]
	for i := range rows {
		if rows[i].Address.Family != windows.AF_INET {
			continue
		}
		// SOCKADDR_INET is a union; for AF_INET the IPv4 address lives at
		// offset 4 (after Family+Port), which RawSockaddrInet4 models.
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&rows[i].Address))
		if ip := net.IPv4(a.Addr[0], a.Addr[1], a.Addr[2], a.Addr[3]); ip.Equal(local.IP) {
			return rows[i].InterfaceIndex, true
		}
	}
	return 0, false
}
