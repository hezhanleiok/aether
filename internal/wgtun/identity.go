//go:build wgtun

package wgtun

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aethergui/aethergui/internal/logx"
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
		// The endpoint override still wins: an A/B run must be able to pin one
		// endpoint while taking the identity (and junk params) from the file,
		// otherwise the endpoint is a second variable.
		if ep := strings.TrimSpace(endpointOverride); ep != "" {
			cfg.Endpoint = ep
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

// LoadConfFile parses a WireGuard/AWG .conf into a Config. It exists so tools
// (cmd/wgbench) can load a config from an arbitrary path — the A/B runs must
// pin an identity without disturbing the app's own override slot.
func LoadConfFile(path string) (Config, error) {
	return loadOverrideConf(path)
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

	// A Reserved line, if present, is intentionally ignored: the WARP client_id
	// is NOT sent in the handshake (see the reserved-bytes note in wgtun.go).

	// AmneziaWG junk decoys. Absent (or Jc=0) means plain WireGuard — the
	// baseline for the anti-DPI A/B.
	cfg.JunkCount = iniInt(kv, "Jc")
	cfg.JunkMinSize = iniInt(kv, "Jmin")
	cfg.JunkMaxSize = iniInt(kv, "Jmax")
	if cfg.JunkCount > 0 && (cfg.JunkMinSize <= 0 || cfg.JunkMaxSize <= 0) {
		return Config{}, fmt.Errorf("Jc=%d but Jmin/Jmax missing or non-positive", cfg.JunkCount)
	}

	// I1..I5 (the fixed "special junk" templates, e.g. a canned QUIC Initial)
	// are NOT implemented yet: the minimal set is Jc/Jmin/Jmax only. Say so
	// loudly instead of silently dropping them — the A/B result is meaningless
	// if you think I1 was applied when it was not.
	for _, k := range []string{"I1", "I2", "I3", "I4", "I5", "J1", "J2", "J3"} {
		if iniRaw(kv, k) != "" {
			logx.Warnf("[wgtun] %s in override conf: special/controlled junk is NOT implemented yet; ignored", k)
		}
	}
	return cfg, nil
}

// iniInt reads one case-insensitive integer key out of an INI-style map
// (Amnezia writes "Jc", wgcf writes "MTU", casing varies by exporter).
func iniInt(kv map[string]string, key string) int {
	v := iniRaw(kv, key)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// iniRaw returns the value of key, matched case-insensitively.
func iniRaw(kv map[string]string, key string) string {
	for k, v := range kv {
		if strings.EqualFold(k, key) {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
