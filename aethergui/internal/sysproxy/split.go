//go:build windows

package sysproxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// SplitConfig drives the generated PAC file: which destinations go direct.
type SplitConfig struct {
	DirectDomains []string // example.com, *.example.com, keyword:foo
	DirectIPs     []string // CIDRs or bare addresses
	DirectPorts   []string // port:25, port:3000-3010
	BlockDomains  []string // never proxied (sinkholed to 127.0.0.1)
}

// WritePAC renders a PAC file implementing the user's split rules and returns
// its file:// URL for AutoConfigURL.
func WritePAC(dir string, proxyHost string, proxyPort int, cfg SplitConfig) (string, error) {
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {")
	b.WriteString("\n")
	for _, d := range cfg.BlockDomains {
		if cond := hostCond(d); cond != "" {
			fmt.Fprintf(&b, "  if (%s) return \"PROXY 127.0.0.1:9\";\n", cond)
		}
	}
	b.WriteString("  if (isInNet(dnsResolve(host), \"10.0.0.0\", \"255.0.0.0\")) return \"DIRECT\";\n")
	b.WriteString("  if (isInNet(dnsResolve(host), \"172.16.0.0\", \"255.240.0.0\")) return \"DIRECT\";\n")
	b.WriteString("  if (isInNet(dnsResolve(host), \"192.168.0.0\", \"255.255.0.0\")) return \"DIRECT\";\n")
	b.WriteString("  if (isInNet(dnsResolve(host), \"127.0.0.0\", \"255.0.0.0\")) return \"DIRECT\";\n")
	b.WriteString("  if (isInNet(dnsResolve(host), \"169.254.0.0\", \"255.255.0.0\")) return \"DIRECT\";\n")
	for _, d := range cfg.DirectDomains {
		if cond := hostCond(d); cond != "" {
			fmt.Fprintf(&b, "  if (%s) return \"DIRECT\";\n", cond)
		}
	}
	fmt.Fprintf(&b, "  return \"PROXY %s:%d\";\n}\n", proxyHost, proxyPort)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "aether-split.pac")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return "file:///" + strings.ReplaceAll(p, "\\", "/"), nil
}

// hostCond turns one user rule into a PAC condition, mirroring the core's
// domain-rule semantics (example.com, full:, keyword:, regexp:).
func hostCond(rule string) string {
	r := strings.TrimSpace(rule)
	switch {
	case strings.HasPrefix(r, "full:"):
		return fmt.Sprintf("host === %q", strings.TrimPrefix(r, "full:"))
	case strings.HasPrefix(r, "keyword:"):
		return fmt.Sprintf("host.indexOf(%q) >= 0", strings.TrimPrefix(r, "keyword:"))
	case strings.HasPrefix(r, "regexp:"):
		re := strings.TrimPrefix(r, "regexp:")
		return fmt.Sprintf("/%s/.test(host)", strings.ReplaceAll(re, "/", "\\/"))
	case strings.HasPrefix(r, "*."):
		return fmt.Sprintf("host.endsWith(%q)", "."+strings.TrimPrefix(r, "*."))
	case strings.Contains(r, "/"):
		if ip, ipnet, err := net.ParseCIDR(r); err == nil {
			if v4 := ipnet.IP.To4(); v4 != nil {
				m := ipnet.Mask
				mask := fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
				return fmt.Sprintf("isInNet(dnsResolve(host), %q, %q)", ip.String(), mask)
			}
		}
		return ""
	case r == "private":
		return "isPlainHostName(host) || isInNet(dnsResolve(host), \"10.0.0.0\", \"255.0.0.0\")"
	default:
		return fmt.Sprintf("(host === %q || host.endsWith(%q))", r, "."+r)
	}
}

// TakeSplit writes the PAC and installs it (split mode entry point).
func TakeSplit(dir, proxyHost string, proxyPort int, cfg SplitConfig, bypass []string) error {
	pacURL, err := WritePAC(dir, proxyHost, proxyPort, cfg)
	if err != nil {
		return err
	}
	return TakePAC(pacURL, bypass)
}
