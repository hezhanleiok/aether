package app

import (
	"github.com/aethergui/aethergui/internal/autostart"
	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/vpn"
)

// Settings returns the live settings snapshot.
func (a *App) SettingsSnapshot() config.Settings { return a.Settings }

// SaveSettings persists the settings and applies everything the GUI owns:
// the log level and the HKCU autostart entry.
func (a *App) SaveSettings(s config.Settings) error {
	// StackedWireGuard (the protocol switch between standard and warp-in-warp)
	// may only change while the tunnel is fully disconnected. The GUI disables
	// the switch while connected/connecting, but reject here too so an
	// out-of-band settings write cannot desync the protocol config from the
	// live tunnel (e.g. UI showing "stacked" while a standard tunnel is up).
	if a.VPN != nil {
		if busy := tunnelBusy(a.VPN.State().Status); busy && s.StackedWireGuard != a.Settings.StackedWireGuard {
			logx.Warnf("[app] stacked_wireguard change rejected while %s (must disconnect first)", a.VPN.State().Status)
			s.StackedWireGuard = a.Settings.StackedWireGuard
		}
	}
	if err := config.Save(s); err != nil {
		return err
	}
	a.Settings = s
	logx.SetLevel(s.LogLevel)
	if s.AutoStart {
		if err := autostart.Enable(s.AutoConnect); err != nil {
			logx.Warnf("[app] autostart enable failed: %v", err)
		}
	} else {
		if err := autostart.Disable(); err != nil {
			logx.Warnf("[app] autostart disable failed: %v", err)
		}
	}
	a.notifyCore()
	return nil
}

// UpdateSettings applies a mutation to the settings and saves the result.
func (a *App) UpdateSettings(mutate func(*config.Settings)) error {
	s := a.Settings
	mutate(&s)
	return a.SaveSettings(s)
}

// tunnelBusy reports whether the tunnel is in a state where flipping the
// protocol (StackedWireGuard) would desync config from the live connection.
// Disconnected and Failed are safe (no tunnel is up); every transitional or up
// state is blocked. There is no distinct "Disconnecting" status — a disconnect
// is synchronous and lands directly on Disconnected.
func tunnelBusy(st vpn.Status) bool {
	switch st {
	case vpn.StatusConnecting, vpn.StatusConnected, vpn.StatusReconnecting,
		vpn.StatusAetherUp, vpn.StatusStartingPsiphon, vpn.StatusPsiphonConnecting,
		vpn.StatusTesting:
		return true
	}
	return false
}

// reconcileStackedWireGuard keeps StackedWireGuard unchanged when the tunnel is
// busy. Pure: returns next with the field reverted to cur when blocked. The GUI
// already disables the switch in that state; this is the backend half of the
// same rule for out-of-band writes.
func reconcileStackedWireGuard(next, cur config.Settings, busy bool) config.Settings {
	if busy && next.StackedWireGuard != cur.StackedWireGuard {
		next.StackedWireGuard = cur.StackedWireGuard
	}
	return next
}
