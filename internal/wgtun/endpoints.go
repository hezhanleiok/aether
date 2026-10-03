//go:build wgtun

package wgtun

import (
	"net/netip"
)

// warpPoolsV4 is the Cloudflare WARP IPv4 endpoint pool, taken from warpscout's
// pools.go. WARP endpoints live in these /24 ranges; the native tunnel probes a
// sample of hosts across them so a single dead endpoint never blocks the whole
// connect.
var warpPoolsV4 = []string{
	"8.6.112.0/24",
	"8.34.70.0/24",
	"8.34.146.0/24",
	"8.35.211.0/24",
	"8.39.125.0/24",
	"8.39.204.0/24",
	"8.39.214.0/24",
	"8.47.69.0/24",
	"162.159.192.0/24",
	"162.159.195.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
}

// warpPorts are the UDP ports WARP endpoints listen on, ordered by priority.
// 4500 (IKE) is first: most networks/NATs whitelist it, so a host:4500 handshake
// succeeds far more often than the default 2408. 2408 is WARP's default; 500 and
// 1701 (IKE/L2TP) are fallbacks.
var warpPorts = []int{4500, 2408, 500, 1701}

// probeHosts are the host octets sampled from each /24 pool. .7/.8 are commonly
// populated WARP endpoints (and .7 is what the override .conf used).
var probeHosts = []byte{7, 8}

// buildCandidates returns the ordered endpoint candidate list for a connect.
// The seed (the .conf / pinned endpoint) is always first; then, per port in
// priority order, every pooled /24 contributes its sample hosts. Probing is
// "first handshake wins", so the ordering matters: 4500 is exhausted before 2408
// is tried.
func buildCandidates(seed string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(ep string) {
		if ep == "" || seen[ep] {
			return
		}
		seen[ep] = true
		out = append(out, ep)
	}

	if seed != "" {
		add(seed)
	}

	// Cached endpoints (fastest first) jump ahead of the cold pool probe. They
	// are still handshake-verified by probeEndpoint — this only sets priority.
	for _, ep := range loadCache().orderedAddrs() {
		add(ep)
	}

	for _, port := range warpPorts {
		for _, p := range warpPoolsV4 {
			prefix := netip.MustParsePrefix(p)
			base := prefix.Addr().As4()
			for _, host := range probeHosts {
				base[3] = host
				ap := netip.AddrPortFrom(netip.AddrFrom4(base), uint16(port))
				add(ap.String())
			}
		}
	}
	return out
}
