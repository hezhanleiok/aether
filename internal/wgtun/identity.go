//go:build wgtun

package wgtun

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LoadIdentity reads the WARP identity that the Aether core has already
// provisioned into aether.toml and turns it into a wgtun.Config. The same
// account/key the core uses is repackaged for the native (kernel-speed)
// WireGuard tunnel, so no second WARP registration is needed.
//
// endpointOverride ("ip:port") wins over the core's assigned endpoint; this is
// how a hand-picked wgcf/warpscout winner is fed to the native tunnel.
func LoadIdentity(configDir, endpointOverride string) (Config, error) {
	// Override bypass: if wgtun-override.conf exists next to aether.toml it
	// wins. This lets a hand-edited WireGuard .conf (e.g. one exported from
	// wgcf/warpscout and verified working in the official client) be fed to the
	// native tunnel directly, without touching the aether.toml path.
	overridePath := filepath.Join(configDir, "wgtun-override.conf")
	if _, err := os.Stat(overridePath); err == nil {
		cfg, err := loadOverrideConf(overridePath)
		if err != nil {
			return Config{}, fmt.Errorf("wgtun: wgtun-override.conf: %w", err)
		}
		return cfg, nil
	}

	kv, err := readFlatToml(filepath.Join(configDir, "aether.toml"))
	if err != nil {
		return Config{}, fmt.Errorf("wgtun: reading identity: %w", err)
	}

	cfg := Config{
		PrivateKey:    kv["wg_private_key"],
		PeerPublicKey: kv["wg_peer_public_key"],
		IPv4:          kv["ipv4"],
		IPv6:          kv["ipv6"],
		MTU:           1280, // WARP's own tunnel MTU (what wgcf ships)
		DNS:           []string{"1.1.1.1", "1.0.0.1"},
	}
	if cfg.PrivateKey == "" || cfg.PeerPublicKey == "" || cfg.IPv4 == "" {
		return Config{}, fmt.Errorf("wgtun: aether.toml is missing wg_private_key / wg_peer_public_key / ipv4")
	}

	reserved, err := decodeReservedBytes(kv["client_id"])
	if err != nil {
		return Config{}, fmt.Errorf("wgtun: client_id: %w", err)
	}
	cfg.Reserved = reserved
	cfg.HasReserved = true

	ep := strings.TrimSpace(endpointOverride)
	if ep == "" {
		if assigned := kv["assigned_endpoint"]; assigned != "" {
			ep = net.JoinHostPort(assigned, "2408") // WARP's default WireGuard port
		}
	}
	if ep == "" {
		return Config{}, fmt.Errorf("wgtun: no endpoint (aether.toml has none and none was pinned)")
	}
	cfg.Endpoint = ep
	return cfg, nil
}

// loadOverrideConf parses a WireGuard .conf (INI) into a Config. It supports the
// subset the native tunnel consumes: [Interface] PrivateKey/Address/DNS/MTU and
// [Peer] PublicKey/Endpoint/Reserved(optional). AllowedIPs and
// PersistentKeepalive are read but intentionally ignored — the native tunnel
// hard-wires AllowedIPs=0.0.0.0/0,::/0 and keepalive=25, which is exactly what
// WARP .conf files ship.
func loadOverrideConf(path string) (Config, error) {
	kv, err := readFlatToml(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		PrivateKey:    kv["PrivateKey"],
		PeerPublicKey: kv["PublicKey"],
		MTU:           1280,
	}
	if cfg.PrivateKey == "" || cfg.PeerPublicKey == "" {
		return Config{}, fmt.Errorf("missing PrivateKey or PublicKey")
	}

	// Address: comma-separated CIDRs, IPv4 and/or IPv6.
	for _, a := range strings.Split(kv["Address"], ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			if ip = net.ParseIP(a); ip == nil {
				continue
			}
		}
		if ip.To4() != nil {
			cfg.IPv4 = ip.String()
		} else {
			cfg.IPv6 = ip.String()
		}
	}

	// DNS: comma-separated.
	for _, d := range strings.Split(kv["DNS"], ",") {
		if d = strings.TrimSpace(d); d != "" {
			cfg.DNS = append(cfg.DNS, d)
		}
	}

	// MTU.
	if s := strings.TrimSpace(kv["MTU"]); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			cfg.MTU = n
		}
	}

	// Endpoint (required).
	if cfg.Endpoint = strings.TrimSpace(kv["Endpoint"]); cfg.Endpoint == "" {
		return Config{}, fmt.Errorf("missing Endpoint")
	}

	// Reserved (optional): three comma-separated decimal bytes.
	if s := strings.TrimSpace(kv["Reserved"]); s != "" {
		parts := strings.Split(s, ",")
		if len(parts) != 3 {
			return Config{}, fmt.Errorf("Reserved must be 3 comma-separated bytes, got %q", s)
		}
		for i, p := range parts {
			n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
			if err != nil {
				return Config{}, fmt.Errorf("Reserved[%d]: %w", i, err)
			}
			cfg.Reserved[i] = byte(n)
		}
		cfg.HasReserved = true
	}
	return cfg, nil
}

// decodeReservedBytes turns Aether's base64 client_id (three bytes) into the
// reserved triple the WARP handshake needs.
func decodeReservedBytes(clientID string) ([3]byte, error) {
	var out [3]byte
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(clientID))
	if err != nil {
		return out, err
	}
	if len(raw) != 3 {
		return out, fmt.Errorf("client_id decodes to %d bytes, want 3", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

// readFlatToml parses the flat `key = "value"` lines Aether writes. It is
// deliberately not a full TOML parser: the identity file only has flat
// assignments (sections and comments are skipped).
func readFlatToml(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = strings.Trim(val, `"`)
		out[key] = val
	}
	return out, sc.Err()
}
