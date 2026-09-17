//go:build windows

// Package autostart registers the app to launch with Windows (HKCU Run key —
// no admin needed) and remembers whether the "auto connect after logon" flag
// is set for the boot path.
package autostart

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const valueName = "AetherGUI"

// Enable adds the HKCU Run entry (with --connect when autoConnect is set).
func Enable(autoConnect bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	arg := ""
	if autoConnect {
		arg = " --connect"
	}
	// Quote the path so spaces survive.
	cmd := "\"" + exe + "\"" + arg
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open run key: %w", err)
	}
	defer k.Close()
	return k.SetStringValue(valueName, cmd)
}

// Disable removes the entry. A missing value is a success, not an error:
// "not registered" is exactly the state the caller asked for.
func Disable() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open run key: %w", err)
	}
	defer k.Close()
	if err := k.DeleteValue(valueName); err != nil && !errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return err
	}
	return nil
}

// Enabled reports whether the Run entry exists.
func Enabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(valueName)
	return err == nil
}

// WantsAutoConnect checks the Run entry's --connect flag.
func WantsAutoConnect() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(valueName)
	return err == nil && strings.Contains(v, "--connect")
}
