// Command aetherwg exports the WARP identity that the Aether core has already
// provisioned (aether.toml) into a wgcf-compatible WireGuard config.
//
// Why this exists: the Aether core registers a WARP account with Cloudflare
// and stores the matched key pair, the reserved bytes and the assigned tunnel
// addresses in aether.toml. Those are exactly the pieces a native WireGuard
// client needs - so instead of re-registering with wgcf, we repackage the
// existing identity and run it at kernel speed (the WireGuard app / wg-quick,
// or wireguard-go + wintun) instead of through Aether's user-space netstack.
//
// Usage:
//
//	aetherwg                           # read the default identity, print the config
//	aetherwg -endpoint 162.159.192.6:2408   # override the endpoint (e.g. warpscout's best)
//	aetherwg -out aether.conf               # write to a file instead of stdout
package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	configPath := flag.String("config", "", "path to aether.toml (default: %LOCALAPPDATA%\\AetherGUI\\aether.toml)")
	endpoint := flag.String("endpoint", "", "override endpoint ip:port (e.g. the fastest one warpscout found)")
	out := flag.String("out", "", "write the config here instead of stdout")
	flag.Parse()

	path := *configPath
	if path == "" {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			base = "."
		}
		path = filepath.Join(base, "AetherGUI", "aether.toml")
	}

	kv, err := readFlatToml(path)
	if err != nil {
		fatal("reading identity: %v", err)
	}

	priv := kv["wg_private_key"]
	peer := kv["wg_peer_public_key"]
	ipv4 := kv["ipv4"]
	ipv6 := kv["ipv6"]
	if priv == "" || peer == "" || ipv4 == "" {
		fatal("aether.toml is missing wg_private_key / wg_peer_public_key / ipv4", nil)
	}

	ep := strings.TrimSpace(*endpoint)
	if ep == "" {
		assigned := kv["assigned_endpoint"]
		if assigned != "" {
			ep = net.JoinHostPort(assigned, "2408") // WARP's default WireGuard port
		}
	}
	if ep == "" {
		fatal("no endpoint: pass -endpoint ip:port", nil)
	}

	reserved, err := decodeReserved(kv["client_id"])
	if err != nil {
		fatal("decoding client_id (WARP reserved): %v", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
	fmt.Fprintf(&b, "Address = %s/32, %s/128\n", ipv4, ipv6)
	fmt.Fprintf(&b, "DNS = 1.1.1.1, 1.0.0.1\n")
	fmt.Fprintf(&b, "MTU = 1280\n") // WARP's own tunnel MTU, what wgcf ships
	fmt.Fprintf(&b, "\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", peer)
	fmt.Fprintf(&b, "AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", ep)
	if reserved != "" {
		fmt.Fprintf(&b, "Reserved = %s\n", reserved)
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(b.String()), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "aetherwg: writing %s: %v\n", *out, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
		return
	}
	fmt.Print(b.String())
}

// decodeReserved turns Aether's base64 client_id (three bytes) into the
// "a,b,c" triple that WireGuard configs use for the WARP reserved field.
func decodeReserved(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	if len(raw) != 3 {
		return "", fmt.Errorf("client_id decodes to %d bytes, want 3", len(raw))
	}
	return fmt.Sprintf("%d,%d,%d", raw[0], raw[1], raw[2]), nil
}

// readFlatToml parses the flat key = "value" lines Aether writes; it is
// deliberately not a full TOML parser.
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

func fatal(format string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "aetherwg: "+format+"\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "aetherwg: "+format+"\n")
	}
	os.Exit(1)
}
