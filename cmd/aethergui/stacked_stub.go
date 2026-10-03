//go:build !wgtun

package main

import "github.com/aethergui/aethergui/internal/logx"

// runStacked is a no-op stub for non-wgtun builds: warp-in-warp (StackedTunnel)
// only exists when the wgtun build tag is set.
func runStacked(accountPath string) {
	logx.Errorf("[main] -stacked requires a build with the wgtun tag")
}
