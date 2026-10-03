//go:build wgtun

package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/vpn"
	"github.com/aethergui/aethergui/internal/wgtun"
)

// nativeWGHandle is the concrete native-WireGuard session holder in wgtun
// builds. The same field exists in non-wgtun builds as a no-op type, so the
// App struct keeps one shape across build tags.
type nativeWGHandle = *wgtun.Manager

// nativeStackedHandle is the warp-in-warp session holder in wgtun builds
// (no-op type in non-wgtun builds, like nativeWGHandle).
type nativeStackedHandle = *wgtun.StackedTunnel

// nativeWGInterfaceName is the wintun interface name the native backend uses;
// watchguard ignores it (by prefix) so the virtual adapter's create/destroy
// never triggers a reconnect loop.
const nativeWGInterfaceName = wgtun.DefaultInterfaceName

// recoverNativeWGState checks for and cleans up residue left by a previous
// unclean native-WG exit. It must not block start-up (a non-elevated process
// with residue would otherwise be stuck), so callers only log/prompt on error.
func recoverNativeWGState() error {
	return wgtun.RecoverState()
}

// nativeWGResiduePresent reports (read-only) whether native-WG residue exists,
// so the UI warning always reflects the disk's real state rather than a value
// cached at start-up.
func nativeWGResiduePresent() bool {
	return wgtun.ResiduePresent()
}

// useNativeWG reports whether this connect should run the native WireGuard
// backend instead of the core. Only the WireGuard-class modes qualify: the
// WARP identity in aether.toml is what the native tunnel reuses, and MASQUE /
// Gool have no such identity.
func (a *App) useNativeWG(s config.Settings) bool {
	return s.NativeWireGuard && (s.Mode == config.ModeWARP || s.Mode == config.ModeWireGuard)
}

// connectNativeWG starts the native WireGuard tunnel (wintun + wireguard-go +
// routes + DNS) and drives the shared state machine to Connected. It bypasses
// the core entirely: the WARP identity the core provisioned is run at kernel
// speed. Requires elevation (the wintun driver and the HKLM DNS write).
func (a *App) connectNativeWG(ctx context.Context, s config.Settings) error {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	if a.nativeWG != nil && a.nativeWG.Running() {
		return nil
	}
	a.VPN.SetNativeState(vpn.StatusConnecting, s.Mode, "")
	cfg, err := wgtun.LoadIdentity(config.Dir(), s.CustomEndpoint)
	if err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}

	m := &wgtun.Manager{}
	if err := m.Start(ctx, cfg, nil); err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}
	a.nativeWG = m
	a.VPN.SetNativeState(vpn.StatusConnected, s.Mode, "")
	logx.Infof("[app] native WireGuard up (endpoint %s, mtu %d)", cfg.Endpoint, cfg.MTU)
	return nil
}

// disconnectNativeWG tears down the native tunnel and restores routes/DNS.
func (a *App) disconnectNativeWG() {
	if a.nativeWG != nil {
		if err := a.nativeWG.Stop(); err != nil {
			logx.Warnf("[app] native WireGuard stop: %v", err)
		}
		a.nativeWG = nil
	}
}

// newestInnerAccount picks the warp-accounts/*.json file with the most recent
// mtime, so a freshly minted inner account wins over stale ones. Errors are
// returned (not swallowed) — the caller surfaces them as a failed connect.
func newestInnerAccount(dir string) (string, error) {
	dirPath := filepath.Join(dir, "warp-accounts")
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return "", fmt.Errorf("warp-accounts: %w (run aetherregister to mint an inner account)", err)
	}
	type cand struct {
		path string
		mod  int64
	}
	var cands []cand
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cands = append(cands, cand{path: filepath.Join(dirPath, e.Name()), mod: info.ModTime().UnixNano()})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("warp-accounts: no account JSON in %s (run aetherregister to mint an inner account)", dirPath)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod > cands[j].mod })
	return cands[0].path, nil
}

// connectNativeStacked brings up warp-in-warp: outer WARP identity from
// aether.toml, inner from the newest registered account, inner endpoint routed
// through the outer adapter. Drives the same shared state machine the single
// native tunnel uses, so the UI needs no special casing.
// connectEnterHook is a test seam: if non-nil it runs at the very start of the
// native (including stacked) connect, under the connect lock, so tests can
// observe/serialize concurrent connects. Production leaves it nil.
var connectEnterHook func()

func (a *App) connectNativeStacked(ctx context.Context, s config.Settings) error {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	if connectEnterHook != nil {
		connectEnterHook()
	}
	if a.nativeStacked != nil {
		return nil // already up (Up() is idempotent-safe; a second connect is a no-op)
	}
	a.VPN.SetNativeState(vpn.StatusConnecting, s.Mode, "")
	onPhase := func(p string) { a.VPN.SetPhase(p) }

	account, err := newestInnerAccount(config.Dir())
	if err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}

	outerCfg, innerCfg, err := wgtun.BuildStacked(config.Dir(), account)
	if err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}
	st, err := wgtun.NewStackedTunnel(ctx, outerCfg, innerCfg, onPhase)
	if err != nil {
		a.VPN.SetNativeState(vpn.StatusFailed, s.Mode, err.Error())
		return err
	}
	a.nativeStacked = st
	a.VPN.SetNativeState(vpn.StatusConnected, s.Mode, "")
	logx.Infof("[app] stacked warp-in-warp up (outer=%s inner=%s, account %s)",
		outerCfg.Endpoint, innerCfg.Endpoint, filepath.Base(account))
	return nil
}

// disconnectNativeStacked tears the stack down in the reverse order of its
// setup (inner routes/metric/DNS revert → inner device → outer revert).
func (a *App) disconnectNativeStacked() {
	if a.nativeStacked != nil {
		if err := a.nativeStacked.Down(); err != nil {
			logx.Warnf("[app] stacked down: %v", err)
		}
		a.nativeStacked = nil
	}
}
