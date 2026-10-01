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
// WARP reserved bytes
//
// Cloudflare WARP uses the three WireGuard-handshake bytes that follow the
// message type as a client identifier; upstream wireguard-go hard-codes them
// to zero, which Cloudflare rejects. The vendored copy of wireguard-go is
// therefore patched: device.SetReserved([3]byte) feeds those bytes into every
// initiation packet (see vendor/golang.zx2c4.com/wireguard/device).
package wgtun

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Config is the identity and endpoint a native WireGuard tunnel needs. It is
// produced from Aether's aether.toml (see cmd/aetherwg).
type Config struct {
	InterfaceName string   // "Xiaohe" or similar
	PrivateKey    string   // base64, 32 bytes
	PeerPublicKey string   // base64, 32 bytes
	Reserved      [3]byte  // WARP client_id, decoded from base64
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
func New(cfg Config) (Tunnel, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	name := cfg.InterfaceName
	if name == "" {
		name = "Xiaohe"
	}

	tdev, err := tun.CreateTUN(name, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("wgtun: creating wintun adapter: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, "[xiaohe-wg] ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	// Must be applied before the first handshake; otherwise Cloudflare WARP
	// rejects the initiation (reserved bytes are its client identifier).
	dev.SetReserved(cfg.Reserved)

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
	// NOTE: routing is intentionally not done here yet. The caller must add a
	// default route (0.0.0.0/0 + ::/0) through this adapter, exclude the WG
	// endpoint itself, and set DNS - exactly what wg-quick does. Keeping it out
	// of this package keeps the device lifecycle testable on its own.
	return nil
}

func (t *tunnel) Down() error {
	if t.dev != nil {
		t.dev.Close()
	}
	t.up = false
	return nil
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
