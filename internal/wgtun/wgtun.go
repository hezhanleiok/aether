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
// # WARP reserved bytes (NOT used)
//
// Cloudflare WARP accepts a standard WireGuard handshake with the three bytes
// after the message type left at zero (the "no reserved" compatibility path).
// Real-machine testing (2026-10-04) proved that a vendored patch injecting the
// account's client_id into those bytes made Cloudflare REJECT the handshake,
// while the same account/endpoint handshakes fine without them — and the
// reference scanner (sing-box, whose wireguard-go fork has no SetReserved) also
// sends zero reserved bytes. The reserved patch was therefore removed: the
// vendored wireguard-go is unmodified upstream, and Config carries no Reserved
// field. Do not re-add it without re-verifying on real hardware.
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
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/aethergui/aethergui/internal/logx"
	"golang.org/x/sys/windows"
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
	IPv4          string   // e.g. 172.16.0.2
	IPv6          string   // e.g. 2606:4700:110:...
	Endpoint      string   // ip:port
	MTU           int      // 1280 (WARP)
	DNS           []string // e.g. 1.1.1.1, 1.0.0.1

	// AmneziaWG junk decoys (anti-DPI). JunkCount == 0 disables them, which is
	// the WireGuard-baseline behaviour. They are one-sided: random packets sent
	// from the same socket immediately BEFORE each handshake initiation, so the
	// flow no longer opens with a bare 148-byte WireGuard initiation. The
	// handshake bytes are unchanged, so any standard WireGuard peer (WARP
	// included) is unaffected — see the note in device/awgjunk.go.
	JunkCount   int // Jc
	JunkMinSize int // Jmin
	JunkMaxSize int // Jmax

	// JunkI1 is the AmneziaWG fake first packet: one canned packet sent BEFORE
	// the junk decoys and before the handshake initiation, so the flow opens
	// with something other than a bare 148-byte WireGuard initiation. Nil
	// disables it. Upstream (warpscout) reports this is the half that actually
	// gets a connection past a filter; the junk sizes alone rarely do.
	// See i1gen.go for the generators and for what they do NOT claim.
	JunkI1 []byte
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

// New creates the wintun adapter and the wireguard-go device. Call Up to
// configure peers, assign the tunnel addresses and start; Down to stop.
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
	// Assign addresses AFTER the device is up: wintun only reports the adapter
	// media-connected once the session starts, and CreateUnicastIpAddressEntry
	// against a disconnected adapter silently does nothing (observed
	// 2026-10-04: the call returned success but the adapter ended up with only
	// an fe80:: link-local, so the tunnel had no IPv4 source address and every
	// data packet was unreachable).
	if err := t.assignAddresses(); err != nil {
		return fmt.Errorf("wgtun: assigning interface address: %w", err)
	}
	// MTU: wireguard-go only RECORDS the MTU we passed to CreateTUN (it reports
	// it back from MTU()); the Windows adapter keeps wintun's default NlMtu of
	// 65535 unless told otherwise. With 65535, TCP picks a ~1460-byte MSS and
	// its packets are larger than the tunnel's real path MTU (~1400, measured),
	// so they are dropped (DF) and the transfer crawls — this was measured at
	// 6.5 Mbps against 168 Mbps for the official client on the same endpoint.
	// Failure here is non-fatal: a suboptimal MTU is slow, an aborted connect
	// is worse.
	if err := setAdapterMTU(t.luid(), t.cfg.MTU); err != nil {
		logx.Warnf("[wgtun] setting adapter MTU %d: %v", t.cfg.MTU, err)
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
	if t.up {
		// Remove the interface addresses we added: the wintun adapter survives
		// process exit (on-demand pool), and a stale 172.16.0.2 on it would
		// break the next connect's assignment.
		t.removeAddresses()
	}
	t.up = false
	return nil
}

// setInterfaceEntry is the syscall seam used by setAdapterMTU, so its arguments
// can be asserted offline (no adapter, no elevation).
var setInterfaceEntry = setIpInterfaceEntry

// setAdapterMTU pins the wintun adapter's MTU (NlMtu) for both address
// families. This is what the official WireGuard client does with the MTU line
// in its .conf; without it the adapter stays at wintun's 65535 default and TCP
// emits packets the tunnel cannot carry.
//
// Both families must be set: with IPv4 pinned and IPv6 left at 65535, an AAAA
// answer would still be tried with jumbo-sized v6 packets.
func setAdapterMTU(luid uint64, mtu int) error {
	if mtu <= 0 {
		return fmt.Errorf("invalid MTU %d", mtu)
	}
	var errs []error
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		var row windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&row)
		row.Family = family
		row.InterfaceLuid = luid
		row.NlMtu = uint32(mtu)
		if err := setInterfaceEntry(&row); err != nil {
			errs = append(errs, fmt.Errorf("family %d: %w", family, err))
			continue
		}
		logx.Infof("[wgtun] adapter MTU set to %d (family=%d)", mtu, family)
	}
	return errors.Join(errs...)
}

// assignAddresses installs the tunnel's IPv4 (/32) and IPv6 (/128) unicast
// addresses on the wintun adapter. IPv4 is required; IPv6 is best-effort
// (a missing v6 just disables v6 through the tunnel). Infinite lifetimes keep
// the assignment for the adapter's lifetime.
func (t *tunnel) assignAddresses() error {
	if v4 := net.ParseIP(t.cfg.IPv4); v4 != nil {
		row := t.unicastRow(sockaddrInet4(v4.To4()), 32)
		if err := createUnicastIpAddressEntry(&row); err != nil && !isAlreadyExists(err) {
			return fmt.Errorf("IPv4 %s: %w", t.cfg.IPv4, err)
		}
		logx.Infof("[wgtun] assigned %s/32 to wintun adapter", t.cfg.IPv4)
	} else {
		logx.Warnf("[wgtun] no IPv4 address in config; wintun adapter has no source address")
	}
	if v6 := net.ParseIP(t.cfg.IPv6); v6 != nil && v6.To16() != nil && t.cfg.IPv6 != "" {
		row := t.unicastRow(sockaddrInet6(v6.To16()), 128)
		if err := createUnicastIpAddressEntry(&row); err != nil && !isAlreadyExists(err) {
			// Best-effort: a failed v6 address must not kill an otherwise
			// working v4 tunnel.
			logx.Warnf("[wgtun] IPv6 address %s skipped: %v", t.cfg.IPv6, err)
		}
	}
	return nil
}

// removeAddresses deletes the addresses assignAddresses added. Errors are
// logged, not returned: Down must always finish teardown.
func (t *tunnel) removeAddresses() {
	if v4 := net.ParseIP(t.cfg.IPv4); v4 != nil {
		row := t.unicastRow(sockaddrInet4(v4.To4()), 32)
		if err := deleteUnicastIpAddressEntry(&row); err != nil && !isNotFound(err) {
			logx.Warnf("[wgtun] removing IPv4 address: %v", err)
		}
	}
	if v6 := net.ParseIP(t.cfg.IPv6); v6 != nil && v6.To16() != nil && t.cfg.IPv6 != "" {
		row := t.unicastRow(sockaddrInet6(v6.To16()), 128)
		if err := deleteUnicastIpAddressEntry(&row); err != nil && !isNotFound(err) {
			logx.Warnf("[wgtun] removing IPv6 address: %v", err)
		}
	}
}

// unicastRow builds a MIB_UNICASTIPADDRESS_ROW for one address on this
// adapter, with infinite lifetime and an on-link prefix of /32 (v4) or /128
// (v6) — a point-to-point tunnel address, matching what sing-box's system
// stack and the official WireGuard client install.
func (t *tunnel) unicastRow(sa windows.RawSockaddrInet, prefixLen uint8) windows.MibUnicastIpAddressRow {
	var row windows.MibUnicastIpAddressRow
	initializeUnicastIpAddressEntry(&row)
	// MibUnicastIpAddressRow.Address is the SOCKADDR_INET union, typed as
	// RawSockaddrInet6 by x/sys. Both families' sockaddr share the first 16
	// bytes (family + body); copy bytewise so IPv4 bytes land correctly and the
	// Initialize-zeroed padding stays clean.
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&row.Address)), 16),
		unsafe.Slice((*byte)(unsafe.Pointer(&sa)), 16))
	row.InterfaceLuid = t.luid()
	row.OnLinkPrefixLength = prefixLen
	row.ValidLifetime = 0xFFFFFFFF
	row.PreferredLifetime = 0xFFFFFFFF
	// NL_PREFIX_ORIGIN/NL_SUFFIX_ORIGIN: 1 == Manual. Initialize leaves these
	// as "Unchanged" (16), and Windows then discards the entry — the call
	// returns success while the adapter keeps only its fe80:: link-local.
	// wireguard-windows' winipcfg sets both to Manual for exactly this reason.
	row.PrefixOrigin = 1
	row.SuffixOrigin = 1
	return row
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

// waitHandshakeCtx is WaitHandshake with an interruption channel: it returns
// ctx.Err() the moment ctx is cancelled. It exists so Stop() can abort a
// failover mid-handshake — the plain WaitHandshake sits out its full timeout
// while the caller (failover) holds m.mu, which is what left the power button
// dead for as long as the failover loop ran (2026-10-05).
func (t *tunnel) waitHandshakeCtx(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s, err := t.dev.IpcGet(); err == nil && hasHandshake(s) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("handshake did not complete within %v", timeout)
}

// lastHandshakeAge reports how long ago the peer's last completed handshake
// was. A healthy peer rekeys well before handshakeStaleAfter, so a large age
// means the endpoint stopped answering even if no user traffic happened to be
// flowing (which is what makes this usable as a liveness signal while idle).
func (t *tunnel) lastHandshakeAge() (time.Duration, bool) {
	if t.dev == nil {
		return 0, false
	}
	s, err := t.dev.IpcGet()
	if err != nil {
		return 0, false
	}
	sec := parseLastHandshakeSec(s)
	if sec <= 0 {
		return 0, false // never handshaken
	}
	return time.Since(time.Unix(sec, 0)), true
}

// parseLastHandshakeSec pulls the newest last_handshake_time_sec out of a UAPI
// "get" dump. Pure, so it is unit-testable without a device.
func parseLastHandshakeSec(uapi string) int64 {
	const prefix = "last_handshake_time_sec="
	var newest int64
	for _, line := range strings.Split(uapi, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		secs, err := strconv.ParseInt(strings.TrimSpace(line[len(prefix):]), 10, 64)
		if err != nil {
			continue
		}
		if secs > newest {
			newest = secs
		}
	}
	return newest
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
	// Fake first packet (I1) first, then the junk decoys: both are device-level
	// keys and are applied (and validated) only after the whole UAPI operation
	// has been read.
	if len(cfg.JunkI1) > 0 {
		fmt.Fprintf(&b, "i1=%x\n", cfg.JunkI1)
	}
	if cfg.JunkCount > 0 {
		fmt.Fprintf(&b, "jc=%d\n", cfg.JunkCount)
		fmt.Fprintf(&b, "jmin=%d\n", cfg.JunkMinSize)
		fmt.Fprintf(&b, "jmax=%d\n", cfg.JunkMaxSize)
	}
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
