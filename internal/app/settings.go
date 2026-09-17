package app

import (
	"github.com/aethergui/aethergui/internal/autostart"
	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
)

// Settings returns the live settings snapshot.
func (a *App) SettingsSnapshot() config.Settings { return a.Settings }

// SaveSettings persists the settings and applies everything the GUI owns:
// the log level and the HKCU autostart entry.
func (a *App) SaveSettings(s config.Settings) error {
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
