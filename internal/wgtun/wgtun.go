//go:build wgtun

// Package wgtun is the native WireGuard (kernel-speed) backend for Xiaohe,
// gated behind the "wgtun" build tag so the default build never needs
// wireguard-go / wintun.
//
// It reuses the WARP identity that the Aether core has already provisioned in
// aether.toml (see cmd/aetherwg) and runs it through wireguard-go + a wintun
// TUN adapter instead of Aether's user-space netstack, matching the data-plane
// speed of the WireGuard app / wgcf.
//
// # WARP reserved bytes
//
// Cloudflare WARP uses the three WireGuard-handshake bytes that follow the
// message type as a client identifier; upstream wireguard-go hard-codes them
// to zero, which Cloudflare rejects. The vendored copy of wireguard-go is
// therefore patched: device.SetReserved([3]byte) feeds those bytes into every
// initiation packet (see vendor/golang.zx2c4.com/wireguard/device).
//
// # VENDOR-PATCH ACCOUNTING (do not lose this)
//
// The reserved-bytes change lives directly in
// vendor/golang.zx2c4.com/wireguard/device (device.go: reserved field +
// SetReserved; noise-protocol.go: Type carries reserved<<8/16/24). This is a
// KNOWN LIABILITY: a single `go mod vendor` silently overwrites the patch
// (Go does not error on a dirty vendor tree), and the WARP handshake then
// breaks again with zero build-time warning. The patch is not migrated to a
// local fork + `replace` yet on purpose - a fork adds its own maintenance
// surface, and this has not run on real hardware. Once the native tunnel is
// proven on a machine, MOVE the patch to a fork and replace the module, then
// delete this paragraph.
//
// # KNOWN ISSUES (route/DNS takeover, routes_windows.go)
//
// Tracked, not blocking the first machine test:
//
//  1. If the endpoint's physical default route has NextHop 0.0.0.0/:: (a
//     directly-connected "on-link" network), the host route we pin would carry
//     a zero gateway and is not a valid exclusion - the handshake could loop.
//     Home networks normally have a real gateway, so this is deferred.
//  2. routeManager.oldDNS / haveOldDNS are only reset by revertDNS indirectly;
//     reusing one routeManager across Apply -> Revert -> Apply can carry a
//     stale oldDNS. The app creates a fresh Manager per connect, so it is not
//     hit today, but the struct is not safe for repeated Apply on one instance.
package wgtun

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aethergui/aethergui/internal/logx"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Config is the identity and endpoint a native WireGuard tunnel needs. It is
// produced from Aether's aether.toml (see cmd/aetherwg).
// DefaultInterfaceName is the wintun adapter name used when Config.InterfaceName
// is empty. watchguard uses it as an ignore-prefix so the virtual interface's
// create/destroy never masquerades as a network-environment change.
const DefaultInterfaceName = "Xiaohe"

type Config struct {
	InterfaceName string   // "Xiaohe" or similar
	PrivateKey    string   // base64, 32 bytes
	PeerPublicKey string   // base64, 32 bytes
	Reserved      [3]byte  // WARP client_id, decoded from base64
	HasReserved   bool     // true only when Reserved is meaningful (client_id present / .conf Reserved line)
	IPv4          string   // e.g. 172.16.0.2
	IPv6          string   // e.g. 2606:4700:110:...
	Endpoint      string   // ip:port
	MTU           int      // 1280 (WARP)
	DNS           []string // e.g. 1.1.1.1, 1.0.0.1
}

// Tunnel is a running native WireGuard session.
type Tunnel interface {
	// Up configures and starts the device. It must be idempotent.
	Up() error
	// Down tears the adapter and routes down and releases OS resources.
	Down() error
}

type tunnel struct {
	tun tun.Device
	dev *device.Device
	cfg Config
	up  bool
}

// New creates the wintun adapter and the wireguard-go device and applies the
// WARP reserved bytes. Call Up to configure peers and start, Down to stop.
//
// The first call requires an elevated process (the wintun adapter is a kernel
// driver) and wintun.dll next to the executable.
func New(cfg Config) (*tunnel, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	name := cfg.InterfaceName
	if name == "" {
		name = DefaultInterfaceName
	}

	tdev, err := tun.CreateTUN(name, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("wgtun: creating wintun adapter: %w", err)
	}

	// Route wireguard-go's logs through logx (not its default os.Stdout writer,
	// which headless runs would drop) so handshake diagnostics land in
	// aethergui.log. Verbose is used deliberately: it shows "Sending handshake
	// initiation" / "Received handshake response", which is exactly what we need
	// to tell apart a black-holed UDP path from a rejected WARP identity.
	// The per-device name prefix is essential for stacked mode: the outer and
	// inner devices log identically otherwise, making it impossible to tell
	// which layer read/wrote a packet.
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			logx.Debugf("[xiaohe-wg:"+name+"] "+format, args...)
		},
		Errorf: func(format string, args ...any) {
			logx.Errorf("[xiaohe-wg:"+name+"] "+format, args...)
		},
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	// Must be applied before the first handshake; otherwise Cloudflare WARP
	// rejects the initiation (reserved bytes are its client identifier). It is
	// optional: a plain .conf without a Reserved line keeps them at zero.
	if cfg.HasReserved {
		dev.SetReserved(cfg.Reserved)
	}

	return &tunnel{tun: tdev, dev: dev, cfg: cfg}, nil
}

func (t *tunnel) Up() error {
	if t.up {
		return nil
	}
	conf, err := buildUAPI(t.cfg)
	if err != nil {
		return err
	}
	if err := t.dev.IpcSet(conf); err != nil {
		return fmt.Errorf("wgtun: configuring device: %w", err)
	}
	if err := t.dev.Up(); err != nil {
		return fmt.Errorf("wgtun: bringing device up: %w", err)
	}
	t.up = true
	// Routing/DNS is deliberately NOT handled here: it lives in routes_windows.go
	// and is driven by Manager, which composes the device lifecycle with the
	// Windows route/DNS takeover. Keeping the device bring-up separate keeps it
	// testable on its own.
	return nil
}

func (t *tunnel) Down() error {
	if t.dev != nil {
		t.dev.Close()
	}
	t.up = false
	return nil
}

// stats returns the peer's cumulative transmit/receive byte counts from the
// UAPI "get" dump. Used to prove the data plane is actually moving bytes on both
// layers of a stacked tunnel (handshake success alone is not proof).
func (t *tunnel) stats() (tx, rx uint64) {
	if t.dev == nil {
		return 0, 0
	}
	s, err := t.dev.IpcGet()
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "tx_bytes="); ok {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				tx = n
			}
		}
		if v, ok := strings.CutPrefix(line, "rx_bytes="); ok {
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				rx = n
			}
		}
	}
	return tx, rx
}

// setEndpoint switches the running device's peer to a new endpoint and restarts
// the handshake, WITHOUT recreating the wintun adapter. It is the hot path for
// endpoint probing: remove + recreate the peer via UAPI, which is millisecond
// scale vs. the 3-4s a full adapter teardown/rebuild costs.
func (t *tunnel) setEndpoint(hostport string) error {
	peerHex, err := keyToHex(t.cfg.PeerPublicKey)
	if err != nil {
		return err
	}
	// Remove the existing peer. If it does not exist yet (first switch), the
	// remove is a harmless no-op.
	_ = t.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", peerHex))
	// Recreate the peer against the new endpoint; handlePostConfig -> peer.Start
	// fires a fresh handshake because the peer is newly created.
	if err := t.dev.IpcSet(buildPeerUAPI(peerHex, hostport)); err != nil {
		return fmt.Errorf("wgtun: updating endpoint: %w", err)
	}
	return nil
}

// WaitHandshake blocks until the WireGuard handshake completes or the timeout
// elapses. It polls IpcGet for a peer whose last_handshake_time is non-zero.
func (t *tunnel) WaitHandshake(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s, err := t.dev.IpcGet(); err == nil && hasHandshake(s) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("handshake did not complete within %v", timeout)
}

// hasHandshake reports whether a UAPI "get" dump shows at least one peer whose
// handshake has completed (last_handshake_time_sec > 0). Pure, so unit-testable.
func hasHandshake(uapi string) bool {
	for _, line := range strings.Split(uapi, "\n") {
		const prefix = "last_handshake_time_sec="
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if secs, err := strconv.ParseInt(strings.TrimSpace(line[len(prefix):]), 10, 64); err == nil && secs > 0 {
			return true
		}
	}
	return false
}

// luid returns the wintun adapter's NET_LUID, used to bind routes and the DNS
// registry key. Returns 0 if the adapter has already been closed.
func (t *tunnel) luid() uint64 {
	if nt, ok := t.tun.(*tun.NativeTun); ok {
		return nt.LUID()
	}
	return 0
}

// buildUAPI renders the UAPI configuration wireguard-go expects. Keys are
// hex-encoded (not base64), which is why the aether.toml values are decoded
// and re-encoded here.
func buildUAPI(cfg Config) (string, error) {
	priv, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("wgtun: private key: %w", err)
	}
	pub, err := keyToHex(cfg.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("wgtun: peer public key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	fmt.Fprintf(&b, "listen_port=0\n")
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	fmt.Fprintf(&b, "endpoint=%s\n", cfg.Endpoint)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=25\n")
	return b.String(), nil
}

func keyToHex(base64Key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(base64Key))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key length %d, want 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// buildPeerUAPI renders a UAPI fragment that (re)creates the single peer with a
// given endpoint. It is used to switch the endpoint on an already-running device
// without tearing the wintun adapter down: remove + recreate the peer, which
// makes wireguard-go start a fresh handshake against the new endpoint.
func buildPeerUAPI(peerHex, endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", peerHex)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=25\n")
	return b.String()
}
