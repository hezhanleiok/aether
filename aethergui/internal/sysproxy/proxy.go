//go:build windows

// Package sysproxy takes over the Windows system proxy so every WinINET app
// routes through the local Aether listener without the user touching anything.
//
// Internet Settings lives in HKCU\Software\Microsoft\Windows\CurrentVersion\
// Internet Settings. We set ProxyEnable+ProxyServer, save the previous values,
// and restore them on release. LAN bypass and <local> keep intranet hosts
// direct. A PAC file is generated for split mode so per-domain rules are
// honored by WinINET.
//
// Loopback is deliberately NEVER proxied: the client's own UI is served from
// 127.0.0.1, and a browser that obeys the system proxy would otherwise send
// that request into the tunnel and render a blank window.
package sysproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// Options describes the takeover we want.
type Options struct {
	Server  string   // "127.0.0.1:1820" (the HTTP CONNECT listener)
	Bypass  []string // extra hosts that stay direct
	NoProxy bool     // remove the proxy entirely (direct mode)
}

// saved is the previous state we restore on release.
type saved struct {
	Enable   uint32 `json:"enable"`
	Server   string `json:"server"`
	Override string `json:"override"`
	AutoURL  string `json:"auto_url"`
}

// backup is persisted beside the config so an unclean exit (crash, kill,
// power loss) can still be repaired on the next launch.
type backup struct {
	Prev       saved  `json:"prev"`
	OurServer  string `json:"our_server"`
	OurAutoURL string `json:"our_autoconfig"`
}

// keepLocalBypass must always stay direct: the UI service and every other
// loopback listener of this machine would otherwise be routed into the tunnel.
var keepLocalBypass = []string{"localhost", "127.*", "[::1]", "<local>"}

var (
	mu        sync.Mutex
	snapshot  *saved
	wasTaken  bool
	dataDir   string
	ourServer string
	ourAuto   string
)

const keyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings`

// SetDataDir tells the package where the crash-proof proxy backup lives.
func SetDataDir(dir string) {
	mu.Lock()
	dataDir = dir
	mu.Unlock()
}

func backupPath(dir string) string { return filepath.Join(dir, "proxy-backup.json") }

func readSaved() (saved, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return saved{}, err
	}
	defer k.Close()
	s := saved{}
	enable, _, _ := k.GetIntegerValue("ProxyEnable")
	s.Enable = uint32(enable)
	s.Server, _, _ = k.GetStringValue("ProxyServer")
	s.Override, _, _ = k.GetStringValue("ProxyOverride")
	s.AutoURL, _, _ = k.GetStringValue("AutoConfigURL")
	return s, nil
}

// applyLocked writes the proxy values we own. Caller must hold mu.
func applyLocked(enable uint32, server, override, autoURL string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open internet settings: %w", err)
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", enable); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", server); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", override); err != nil {
		return err
	}
	return k.SetStringValue("AutoConfigURL", autoURL)
}

// persistLocked writes the recovery file. Caller must hold mu.
func persistLocked() {
	if dataDir == "" || snapshot == nil {
		return
	}
	raw, err := json.MarshalIndent(backup{Prev: *snapshot, OurServer: ourServer, OurAutoURL: ourAuto}, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return
	}
	_ = os.WriteFile(backupPath(dataDir), raw, 0o644)
}

// clearPersisted drops the recovery file after a clean release.
func clearPersisted() {
	if dataDir == "" {
		return
	}
	_ = os.Remove(backupPath(dataDir))
}

// Take applies the system proxy. It is idempotent and remembers the previous
// state exactly once (nested calls keep the first snapshot).
func Take(opts Options) error {
	mu.Lock()
	defer mu.Unlock()
	if opts.NoProxy {
		return restoreLocked()
	}
	if !wasTaken {
		s, err := readSaved()
		if err != nil {
			return fmt.Errorf("read internet settings: %w", err)
		}
		snapshot = &s
		wasTaken = true
	}
	bypass := append(append([]string{}, keepLocalBypass...), opts.Bypass...)
	override := strings.Join(bypass, ";")
	if err := applyLocked(1, opts.Server, override, ""); err != nil {
		return err
	}
	ourServer = opts.Server
	ourAuto = ""
	persistLocked()
	return refresh()
}

// Release restores whatever was there before we took over.
func Release() error {
	mu.Lock()
	defer mu.Unlock()
	return restoreLocked()
}

func restoreLocked() error {
	if !wasTaken || snapshot == nil {
		return nil
	}
	if err := applyLocked(snapshot.Enable, snapshot.Server, snapshot.Override, snapshot.AutoURL); err != nil {
		return err
	}
	wasTaken = false
	snapshot = nil
	ourServer = ""
	ourAuto = ""
	clearPersisted()
	return refresh()
}

// Taken reports whether we currently own the system proxy.
func Taken() bool {
	mu.Lock()
	defer mu.Unlock()
	return wasTaken
}

// RecoverStale repairs the system proxy after an unclean exit. It only touches
// the registry when the current values are exactly the ones we installed, so a
// user (or another VPN client) who changed them since is left alone.
// It reports whether a repair happened.
func RecoverStale(dir string) bool {
	if dir == "" {
		return false
	}
	raw, err := os.ReadFile(backupPath(dir))
	if err != nil {
		return false
	}
	var b backup
	if json.Unmarshal(raw, &b) != nil {
		_ = os.Remove(backupPath(dir))
		return false
	}
	cur, err := readSaved()
	if err != nil {
		return false
	}
	ours := (b.OurServer != "" && cur.Server == b.OurServer) ||
		(b.OurAutoURL != "" && cur.AutoURL == b.OurAutoURL)
	if !ours {
		// Settings changed since: the leftover file is meaningless.
		_ = os.Remove(backupPath(dir))
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	if err := applyLocked(b.Prev.Enable, b.Prev.Server, b.Prev.Override, b.Prev.AutoURL); err != nil {
		return false
	}
	_ = os.Remove(backupPath(dir))
	_ = refresh()
	return true
}

// setAutoConfigLocked points WinINET at a PAC url while we own the settings.
// Caller must hold mu.
func setAutoConfigLocked(url string) error {
	if !wasTaken {
		s, err := readSaved()
		if err != nil {
			return fmt.Errorf("read internet settings: %w", err)
		}
		snapshot = &s
		wasTaken = true
	}
	if ourServer == "" {
		ourServer = "127.0.0.1:1"
	}
	if err := applyLocked(1, ourServer, strings.Join(keepLocalBypass, ";"), url); err != nil {
		return err
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.SET_VALUE); err == nil {
		_ = k.SetDWordValue("AutoDetect", 0)
		k.Close()
	}
	ourAuto = url
	persistLocked()
	return refresh()
}

// refresh broadcasts the WinINET change so browsers pick it up immediately.
func refresh() error {
	dll := syscall.NewLazyDLL("wininet.dll")
	p := dll.NewProc("InternetSetOptionW")
	const refreshSetting = 39 // INTERNET_OPTION_SETTINGS_CHANGED
	const refreshRefresh = 37 // INTERNET_OPTION_REFRESH
	r1, _, err := p.Call(0, uintptr(refreshSetting), 0, 0)
	if r1 == 0 {
		return fmt.Errorf("InternetSetOptionW(settings): %v", err)
	}
	r1, _, err = p.Call(0, uintptr(refreshRefresh), 0, 0)
	if r1 == 0 {
		return fmt.Errorf("InternetSetOptionW(refresh): %v", err)
	}
	return nil
}
