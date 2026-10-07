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

// LoadIdentity builds the native-tunnel Config for one connect. The WARP
// identity comes from aether.toml (the project's single source of truth,
// provisioned by the core / cmd:aetherwg), and wgtun-override.conf is an
// OPTIONAL partial overlay on top of it: the override may pin an endpoint, DNS,
// MTU or AmneziaWG junk, or it may be a full hand-edited WireGuard .conf
// (wgcf / warpscout export) that replaces the identity outright.
//
// The merge is what fixed the 2026-10-06 incident: an accidental non-WireGuard
// file (an HTML tutorial) landed in wgtun-override.conf, and because the old
// code treated the override as an EXCLUSIVE replacement, it took down the whole
// native connect with "missing PrivateKey or PublicKey" while aether.toml still
// held a valid identity. An override that lacks keys now simply contributes
// whatever fields it has — it can never blank the identity.
//
// endpointOverride ("ip:port") wins over both the identity file and the
// override; this is how a hand-picked wgcf/warpscout winner is pinned for an A/B.
func LoadIdentity(configDir, endpointOverride string) (Config, error) {
	base, baseEp := loadIdentityBase(configDir)

	overridePath := filepath.Join(configDir, "wgtun-override.conf")
	if _, err := os.Stat(overridePath); err == nil {
		if kv, err := readFlatToml(overridePath); err == nil {
			over := parseOverrideFields(kv)
			if over.PrivateKey == "" && over.PeerPublicKey == "" {
				logx.Warnf("[wgtun] wgtun-override.conf carries no PrivateKey/PublicKey; treating it as a partial overlay on aether.toml")
			}
			mergeOverride(&base, over)
		} else {
			logx.Warnf("[wgtun] wgtun-override.conf unreadable (%v); ignoring it", err)
		}
	}

	// An explicit endpoint pin wins over both the identity file and the override.
	if ep := strings.TrimSpace(endpointOverride); ep != "" {
		base.Endpoint = ep
	} else if base.Endpoint == "" {
		base.Endpoint = baseEp
	}

	if base.PrivateKey == "" || base.PeerPublicKey == "" {
		return Config{}, fmt.Errorf("wgtun: no WireGuard identity (both aether.toml and wgtun-override.conf lack PrivateKey/PublicKey)")
	}
	if base.IPv4 == "" {
		return Config{}, fmt.Errorf("wgtun: no tunnel IPv4 address (both aether.toml and wgtun-override.conf lack one)")
	}
	if base.Endpoint == "" {
		return Config{}, fmt.Errorf("wgtun: no endpoint (aether.toml has none and none was pinned)")
	}
	return base, nil
}

// loadIdentityBase reads the WARP identity the core provisioned into aether.toml
// and returns the derived endpoint separately (assigned_endpoint + WARP's
// default port). It does NOT hard-fail when aether.toml is missing: a hand-
// exported wgcf/warpscout .conf may be the sole config source, so an absent
// identity file just leaves the base empty for the override to fill.
func loadIdentityBase(configDir string) (Config, string) {
	cfg := Config{
		MTU: 1280, // WARP's own tunnel MTU (what wgcf ships)
		DNS: []string{"1.1.1.1", "1.0.0.1"},
	}
	kv, err := readFlatToml(filepath.Join(configDir, "aether.toml"))
	if err != nil {
		logx.Warnf("[wgtun] aether.toml unreadable (%v); relying on wgtun-override.conf if present", err)
		return cfg, ""
	}
	cfg.PrivateKey = kv["wg_private_key"]
	cfg.PeerPublicKey = kv["wg_peer_public_key"]
	cfg.IPv4 = kv["ipv4"]
	cfg.IPv6 = kv["ipv6"]
	ep := ""
	if assigned := kv["assigned_endpoint"]; assigned != "" {
		ep = net.JoinHostPort(assigned, "2408") // WARP's default WireGuard port
	}
	return cfg, ep
}

// mergeOverride overlays an override onto the base identity: a non-empty
// override field wins, an empty one leaves the base value untouched. This is
// what makes wgtun-override.conf a safe partial overlay — it can pin just an
// endpoint or junk params without carrying (and thus without risking) the
// identity.
func mergeOverride(base *Config, over Config) {
	if over.PrivateKey != "" {
		base.PrivateKey = over.PrivateKey
	}
	if over.PeerPublicKey != "" {
		base.PeerPublicKey = over.PeerPublicKey
	}
	if over.IPv4 != "" {
		base.IPv4 = over.IPv4
	}
	if over.IPv6 != "" {
		base.IPv6 = over.IPv6
	}
	if len(over.DNS) > 0 {
		base.DNS = over.DNS
	}
	// MTU: parseOverrideFields defaults to 1280 (WARP's value), so !=1280 means
	// "the file set it explicitly".
	if over.MTU != 0 && over.MTU != 1280 {
		base.MTU = over.MTU
	}
	if over.Endpoint != "" {
		base.Endpoint = over.Endpoint
	}
	if over.JunkCount > 0 {
		base.JunkCount, base.JunkMinSize, base.JunkMaxSize = over.JunkCount, over.JunkMinSize, over.JunkMaxSize
	}
	if len(over.JunkI1) > 0 {
		base.JunkI1 = over.JunkI1
	}
}

// LoadConfFile parses a WireGuard/AWG .conf into a Config. It exists so tools
// (cmd/wgbench) can load a config from an arbitrary path — the A/B runs must
// pin an identity without disturbing the app's own override slot.
func LoadConfFile(path string) (Config, error) {
	return loadOverrideConf(path)
}

// loadOverrideConf parses a full WireGuard/AWG .conf (INI) into a Config and
// REQUIRES a complete identity + endpoint. This is the strict path used by
// LoadConfFile (wgbench); LoadIdentity uses the lenient parseOverrideFields +
// merge instead, so a partial file never blanks the aether.toml identity.
func loadOverrideConf(path string) (Config, error) {
	kv, err := readFlatToml(path)
	if err != nil {
		return Config{}, err
	}
	cfg := parseOverrideFields(kv)
	if cfg.PrivateKey == "" || cfg.PeerPublicKey == "" {
		return Config{}, fmt.Errorf("missing PrivateKey or PublicKey")
	}
	if cfg.JunkCount > 0 && (cfg.JunkMinSize <= 0 || cfg.JunkMaxSize <= 0) {
		return Config{}, fmt.Errorf("Jc=%d but Jmin/Jmax missing or non-positive", cfg.JunkCount)
	}
	if cfg.Endpoint == "" {
		return Config{}, fmt.Errorf("missing Endpoint")
	}
	return cfg, nil
}

// parseOverrideFields extracts every field the native tunnel understands from an
// override .conf WITHOUT validating completeness. It is shared by the strict
// loadOverrideConf (a full config is required) and LoadIdentity's lenient merge
// (a partial overlay only contributes the fields it has).
func parseOverrideFields(kv map[string]string) Config {
	cfg := Config{
		PrivateKey:    kv["PrivateKey"],
		PeerPublicKey: kv["PublicKey"],
		MTU:           1280,
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

	// Endpoint (not validated here: a partial override may leave it empty).
	cfg.Endpoint = strings.TrimSpace(kv["Endpoint"])

	// A Reserved line, if present, is intentionally ignored: the WARP client_id
	// is NOT sent in the handshake (see the reserved-bytes note in wgtun.go).

	// AmneziaWG junk decoys. Absent (or Jc=0) means plain WireGuard — the
	// baseline for the anti-DPI A/B.
	cfg.JunkCount = iniInt(kv, "Jc")
	cfg.JunkMinSize = iniInt(kv, "Jmin")
	cfg.JunkMaxSize = iniInt(kv, "Jmax")

	// I1, the fake first packet: either raw hex (an externally generated
	// packet, e.g. warpscout's -i1 output) or one of the profile names from
	// i1gen.go (quic/dns/stun/sip/random). A bad value is logged and skipped —
	// the app layer already treats it the same way, and an optional obfuscation
	// decoration must never turn into a failed connect.
	if v := iniRaw(kv, "I1"); v != "" {
		pkt, err := ParseI1(v, iniRaw(kv, "I1SNI"), nil)
		if err != nil {
			logx.Warnf("[wgtun] I1 in override conf: %v (ignored)", err)
		} else if len(pkt) > 0 {
			cfg.JunkI1 = pkt
			logx.Infof("[wgtun] I1 fake first packet enabled: %d bytes (from override conf)", len(pkt))
		}
	}
	// I2..I5 and J1..J3 are still NOT implemented: AmneziaWG's extra canned
	// packets and its "controlled junk" counters. Say so loudly instead of
	// silently dropping them — an A/B result is meaningless if you think they
	// were applied when they were not.
	for _, k := range []string{"I2", "I3", "I4", "I5", "J1", "J2", "J3"} {
		if iniRaw(kv, k) != "" {
			logx.Warnf("[wgtun] %s in override conf: not implemented yet; ignored", k)
		}
	}
	return cfg
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
