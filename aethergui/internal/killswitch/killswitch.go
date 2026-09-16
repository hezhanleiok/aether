//go:build windows

// Package killswitch blocks non-tunnel egress while the VPN is supposed to be
// up, so traffic can never leak outside the tunnel when it drops. Rules are
// added via netsh advfirewall and named AE-* so Disable removes exactly ours.
package killswitch

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

const (
	group      = "AetherGUI Kill Switch"
	ruleMain   = "AetherGUI Kill Switch"
	ruleCore   = "AetherGUI Kill Switch Allow Core"
	ruleLan    = "AetherGUI Kill Switch Allow LAN"
	ruleLoop   = "AetherGUI Kill Switch Allow Loopback"
	ruleWarp   = "AetherGUI Kill Switch Allow WarpDNS"
)

var (
	mu      sync.Mutex
	enabled bool
)

func netsh(args ...string) (string, error) {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("netsh %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

// Enable adds the block rules. coreExePath is the aether.exe running the
// tunnel; its allow rule must be added BEFORE the general block so the tunnel
// itself keeps working.
func Enable(coreExePath string) error {
	mu.Lock()
	defer mu.Unlock()
	if enabled {
		return nil
	}
	if coreExePath == "" {
		return fmt.Errorf("kill switch needs the core binary path")
	}
	steps := [][]string{
		{"advfirewall", "firewall", "add", "rule",
			"name=" + ruleCore, "dir=out", "program=" + coreExePath, "action=allow"},
		{"advfirewall", "firewall", "add", "rule",
			"name=" + ruleLoop, "dir=out", "remoteip=127.0.0.0/8,::1/128", "action=allow"},
		{"advfirewall", "firewall", "add", "rule",
			"name=" + ruleLan, "dir=out",
			"remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16", "action=allow"},
		{"advfirewall", "firewall", "add", "rule",
			"name=" + ruleWarp, "dir=out",
			"remoteip=162.159.192.0/24,162.159.193.0/24,162.159.195.0/24,162.159.196.0/24,162.159.197.0/24,162.159.198.0/24,162.159.204.0/24,188.114.96.0/24,188.114.97.0/24,188.114.98.0/24,188.114.99.0/24",
			"remoteport=2408,443", "protocol=udp", "action=allow"},
		{"advfirewall", "firewall", "add", "rule",
			"name=" + ruleMain, "dir=out", "action=block"},
	}
	for _, s := range steps {
		if _, err := netsh(s...); err != nil {
			// Roll back what we already added so the machine is not stranded.
			_ = disableLocked()
			return err
		}
	}
	enabled = true
	return nil
}

// Disable removes every rule in the group.
func Disable() error {
	mu.Lock()
	defer mu.Unlock()
	return disableLocked()
}

func disableLocked() error {
	var firstErr error
	for _, name := range []string{ruleMain, ruleCore, ruleLan, ruleLoop, ruleWarp} {
		if _, err := netsh("advfirewall", "firewall", "delete", "rule", "name="+name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	enabled = false
	return firstErr
}

// Enabled reports state.
func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return enabled
}
