//go:build wgtun

package main

import (
	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/wgtun"
)

// runStacked is the -stacked entry point: outer identity from aether.toml, inner
// from the -account JSON, then run the double tunnel until a quit signal
// (Ctrl+C / /api/window/quit) arrives. The deferred st.Down() tears the stack
// down in the correct order (inner routes revert → inner down → outer routes
// revert → outer down).
func runStacked(accountPath string) {
	// runStacked runs before app.New(), which is where logx normally gets
	// initialised — without this the errors below never reach the log file.
	logx.Init("info", config.Dir())

	if accountPath == "" {
		logx.Errorf("[main] -stacked requires -account <path to inner WARP account json>")
		return
	}

	outerCfg, innerCfg, err := wgtun.BuildStacked(config.Dir(), accountPath)
	if err != nil {
		logx.Errorf("[main] stacked config: %v", err)
		return
	}

	st, err := wgtun.NewStackedTunnel(outerCfg, innerCfg)
	if err != nil {
		logx.Errorf("[main] stacked up: %v", err)
		return
	}
	defer func() {
		if err := st.Down(); err != nil {
			logx.Warnf("[main] stacked down: %v", err)
		}
	}()

	logx.Infof("[main] stacked tunnel up (outer=%s inner=%s)", outerCfg.Endpoint, innerCfg.Endpoint)

	// Block until the quit signal; the signal handler (armed in main before this
	// runs) closes quitCh, which returns here and runs the deferred Down.
	<-quitCh
}
