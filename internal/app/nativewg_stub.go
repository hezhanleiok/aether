//go:build !wgtun

package app

import (
	"context"
	"fmt"

	"github.com/aethergui/aethergui/internal/config"
)

// nativeWGHandle is a no-op in non-wgtun builds: the native WireGuard backend
// is compiled out, so the field just keeps the App struct's shape stable.
type nativeWGHandle = struct{}

// nativeStackedHandle is the no-op warp-in-warp session holder (wgtun builds
// use *wgtun.StackedTunnel).
type nativeStackedHandle = struct{}

// nativeWGInterfaceName is empty without the native backend: watchguard then
// ignores nothing.
const nativeWGInterfaceName = ""

// recoverNativeWGState is a no-op without the native backend.
func recoverNativeWGState() error { return nil }

// nativeSessionAlive is always false without the native backend compiled in.
func (a *App) nativeSessionAlive() bool { return false }

// nativeWGResiduePresent is always false without the native backend.
func nativeWGResiduePresent() bool { return false }

// useNativeWG is always false without the backend compiled in, so the core
// path is the only path.
func (a *App) useNativeWG(s config.Settings) bool { return false }

func (a *App) connectNativeWG(ctx context.Context, s config.Settings) error {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	return fmt.Errorf("native WireGuard backend not compiled (build with -tags wgtun)")
}

func (a *App) disconnectNativeWG() {}

func (a *App) connectNativeStacked(ctx context.Context, s config.Settings) error {
	a.connMu.Lock()
	defer a.connMu.Unlock()
	return fmt.Errorf("stacked backend not compiled (build with -tags wgtun)")
}

func (a *App) disconnectNativeStacked() {}
