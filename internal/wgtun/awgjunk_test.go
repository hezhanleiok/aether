//go:build wgtun

package wgtun

import (
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// loopbackTun is a tun.Device that carries no traffic: it exposes a pollable fd
// (an os.Pipe read end) so the device's loops can run, and discards writes. The
// tests below only care about what the device puts on the wire, not about the
// TUN side, and this keeps them offline (no wintun, no elevation).
type loopbackTun struct {
	r         *os.File
	w         *os.File
	ev        chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

func newLoopbackTun(t *testing.T) *loopbackTun {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	ft := &loopbackTun{r: r, w: w, ev: make(chan tun.Event, 1), closed: make(chan struct{})}
	t.Cleanup(func() { _ = ft.Close() })
	return ft
}

func (d *loopbackTun) File() *os.File { return d.r }

func (d *loopbackTun) Read([][]byte, []int, int) (int, error) {
	<-d.closed
	return 0, io.EOF
}

func (d *loopbackTun) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }

func (d *loopbackTun) MTU() (int, error)  { return 1280, nil }
func (d *loopbackTun) Name() (string, error) {
	return "lo0", nil
}
func (d *loopbackTun) Events() <-chan tun.Event { return d.ev }
func (d *loopbackTun) BatchSize() int           { return 1 }

func (d *loopbackTun) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		_ = d.w.Close()
		_ = d.r.Close()
		close(d.ev)
	})
	return nil
}

// silentLogger keeps the device quiet: these tests assert on bytes, not logs.
func silentLogger() *device.Logger {
	return &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(string, ...any) {},
	}
}

// collectWire reads UDP datagrams sent to pc until it has n of them or the
// deadline passes.
func collectWire(t *testing.T, pc net.PacketConn, n int, d time.Duration) [][]byte {
	t.Helper()
	out := make([][]byte, 0, n)
	_ = pc.SetReadDeadline(time.Now().Add(d))
	for len(out) < n {
		buf := make([]byte, 2048)
		got, _, err := pc.ReadFrom(buf)
		if err != nil {
			break // deadline: whatever we have is what was sent
		}
		out = append(out, buf[:got])
	}
	return out
}

// TestJunkPacketsPrecedeUnchangedHandshake is the core assertion of the AWG
// minimal set, proven on the wire:
//
//  1. with Jc/Jmin/Jmax, Jc random packets in [Jmin,Jmax) go out BEFORE the
//     handshake initiation, from the same socket/5-tuple;
//  2. the initiation that follows is byte-for-byte the standard WireGuard one
//     (148 bytes, message type 1, three zero reserved bytes) — which is exactly
//     why any standard WireGuard peer (WARP) still accepts it and merely drops
//     the decoys.
//
// Both halves run offline: loopback UDP, no wintun, no elevation.
func TestJunkPacketsPrecedeUnchangedHandshake(t *testing.T) {
	priv, _, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	_, peerPub, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair (peer): %v", err)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	for _, tc := range []struct {
		name    string
		junk    bool
		wantPre int
	}{
		{"junk on", true, 6},
		{"junk off (baseline)", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ft := newLoopbackTun(t)
			dev := device.NewDevice(ft, conn.NewDefaultBind(), silentLogger())
			defer dev.Close()

			cfg := Config{
				PrivateKey:    priv,
				PeerPublicKey: peerPub,
				Endpoint:      pc.LocalAddr().String(),
			}
			if tc.junk {
				cfg.JunkCount, cfg.JunkMinSize, cfg.JunkMaxSize = 6, 10, 50
			}
			uapi, err := buildUAPI(cfg)
			if err != nil {
				t.Fatalf("buildUAPI: %v", err)
			}
			if err := dev.IpcSet(uapi); err != nil {
				t.Fatalf("IpcSet: %v", err)
			}
			if err := dev.Up(); err != nil {
				t.Fatalf("Up: %v", err)
			}

			want := tc.wantPre + 1
			pkts := collectWire(t, pc, want, 3*time.Second)
			if len(pkts) < want {
				t.Fatalf("got %d datagrams, want at least %d", len(pkts), want)
			}

			for i := 0; i < tc.wantPre; i++ {
				if n := len(pkts[i]); n < 10 || n > 50 {
					t.Fatalf("junk packet %d: size %d, want within [10,50]", i, n)
				}
			}

			init := pkts[tc.wantPre]
			if len(init) != 148 {
				t.Fatalf("initiation size = %d, want 148 (handshake must be unchanged)", len(init))
			}
			if init[0] != 1 {
				t.Fatalf("initiation type = %d, want 1 (MessageInitiationType)", init[0])
			}
			if init[1] != 0 || init[2] != 0 || init[3] != 0 {
				t.Fatalf("initiation reserved bytes = %v, want all zero", init[1:4])
			}
		})
	}
}

// TestBuildUAPIJunkWiring locks in that junk is opt-in at the config layer: a
// config without junk produces the exact same UAPI as before (so WireGuard
// mode is untouched), and a config with junk appends the three keys.
func TestBuildUAPIJunkWiring(t *testing.T) {
	priv, pub, err := generateKeypair()
	if err != nil {
		t.Fatalf("generateKeypair: %v", err)
	}
	base := Config{PrivateKey: priv, PeerPublicKey: pub, Endpoint: "8.35.211.174:500"}

	plain, err := buildUAPI(base)
	if err != nil {
		t.Fatalf("buildUAPI: %v", err)
	}
	if strings.Contains(plain, "jc=") || strings.Contains(plain, "jmin=") || strings.Contains(plain, "jmax=") {
		t.Fatalf("baseline UAPI must not carry junk keys:\n%s", plain)
	}

	withJunk := base
	withJunk.JunkCount, withJunk.JunkMinSize, withJunk.JunkMaxSize = 6, 10, 50
	got, err := buildUAPI(withJunk)
	if err != nil {
		t.Fatalf("buildUAPI (junk): %v", err)
	}
	for _, want := range []string{"jc=6", "jmin=10", "jmax=50"} {
		if !strings.Contains(got, want) {
			t.Fatalf("UAPI missing %q:\n%s", want, got)
		}
	}
	// Junk must not disturb the rest of the config.
	if !strings.Contains(got, "endpoint=8.35.211.174:500") {
		t.Fatalf("endpoint lost:\n%s", got)
	}
}

// TestLoadOverrideConfJunk covers parsing an Amnezia/AWG .conf: the keys are
// read case-insensitively, I1 (special junk) is ignored but reported, and a
// half-specified junk config is rejected rather than silently ignored.
func TestLoadOverrideConfJunk(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/awg.conf"
	conf := `[Interface]
PrivateKey = ` + testOverridePrivKey + `
Address = 172.16.0.2/32
DNS = 1.1.1.1, 1.0.0.1
Jc = 6
Jmin = 10
Jmax = 50
I1 = <b 0xc100000001>

[Peer]
PublicKey = ` + testOverridePubKey + `
AllowedIPs = 0.0.0.0/0
Endpoint = 8.35.211.174:500
PersistentKeepalive = 25
`
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := loadOverrideConf(path)
	if err != nil {
		t.Fatalf("loadOverrideConf: %v", err)
	}
	if cfg.JunkCount != 6 || cfg.JunkMinSize != 10 || cfg.JunkMaxSize != 50 {
		t.Fatalf("junk = %d/%d/%d, want 6/10/50", cfg.JunkCount, cfg.JunkMinSize, cfg.JunkMaxSize)
	}
	if cfg.Endpoint != "8.35.211.174:500" {
		t.Fatalf("endpoint = %q", cfg.Endpoint)
	}

	// Jc without sizes is a config error, not a silent no-op.
	half := dir + "/half.conf"
	_ = os.WriteFile(half, []byte("[Interface]\nPrivateKey = "+testOverridePrivKey+"\nJc = 6\n\n[Peer]\nPublicKey = "+testOverridePubKey+"\nEndpoint = 1.2.3.4:500\n"), 0o600)
	if _, err := loadOverrideConf(half); err == nil {
		t.Fatal("Jc without Jmin/Jmax: want error")
	}

	// No junk keys at all = plain WireGuard.
	plain := dir + "/plain.conf"
	_ = os.WriteFile(plain, []byte("[Interface]\nPrivateKey = "+testOverridePrivKey+"\n\n[Peer]\nPublicKey = "+testOverridePubKey+"\nEndpoint = 1.2.3.4:500\n"), 0o600)
	p, err := loadOverrideConf(plain)
	if err != nil {
		t.Fatalf("loadOverrideConf (plain): %v", err)
	}
	if p.JunkCount != 0 {
		t.Fatalf("JunkCount = %d, want 0 (baseline)", p.JunkCount)
	}
}

// Fixed test keys (base64, 32 bytes) — never a real identity.
const (
	testOverridePrivKey = "4LBRXs4CBTrwzrihkX/cFc8l34tOx/2QXO8WcZgZ6FQ="
	testOverridePubKey  = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
)
