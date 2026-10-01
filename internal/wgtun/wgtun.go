//go:build wgtun

// Package wgtun is the native WireGuard (kernel-speed) backend for Xiaohe.
// It is gated behind the "wgtun" build tag so the default build never needs
// wireguard-go / wintun, and it only exists to give Xiaohe a data path that
// matches the speed of the WireGuard app / wgcf instead of Aether's user-space
// netstack.
//
// Design
//
// Aether already provisions a WARP account and stores the matched key pair,
// the reserved bytes (client_id) and the tunnel addresses in aether.toml. The
// cmd/aetherwg tool exports exactly that into a wgcf-compatible config. This
// package is the in-process version of the same idea:
//
//	aether.toml identity
//	  -> wintun adapter (TUN) + wireguard-go device
//	  -> routes 0.0.0.0/0 + ::/0 through the adapter
//	  -> the fast path, no Aether core in the data plane
//
// BLOCKER (recorded so it is not forgotten)
//
// Upstream wireguard-go does NOT implement WARP's "reserved" bytes: the three
// bytes after the sender index in the WireGuard handshake init are hard-coded
// to zero, and Cloudflare WARP uses them as a client identifier and rejects a
// handshake that sends zeros (verified: no "reserved"/"WARP" support anywhere
// in the vendored device package). Options, in order of preference:
//
//  1. Patch the vendored wireguard-go (device/noise-protocol.go) to write the
//     three reserved bytes from Config.Reserved into every initiation packet.
//  2. Use a fork that already ships WARP support.
//
// Until one of those lands, New returns an explicit error instead of silently
// producing a tunnel that can never handshake.
package wgtun

import "errors"

// ErrNotImplemented is returned while the reserved-bytes support is missing.
var ErrNotImplemented = errors.New("wgtun: wireguard-go has no WARP reserved-bytes support yet; see package doc")

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
	// Up brings the adapter and routes online. It must be idempotent.
	Up() error
	// Down tears the adapter and routes down and releases the OS resources.
	Down() error
}

// New returns a placeholder until the reserved-bytes support is implemented.
func New(cfg Config) (Tunnel, error) {
	return nil, ErrNotImplemented
}
