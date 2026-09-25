// aethergui is the Windows VPN client on top of the Aether Core.
//
// Architecture (see ARCHITECTURE.md):
//
//	aethergui.exe (Go shell: native window + tray + local UI service)
//	    └── internal/webbridge  (loopback HTTP + SSE, the UI's only channel)
//	            └── App         (Core Controller, VPN, nodes, proxy, …)
//	                    └── Aether Core (separate process/dll: WARP / WireGuard
//	                        / MASQUE / Gool / MASQUE-in-MASQUE, gateway discovery)
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/aethergui/aethergui/internal/app"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/webbridge"
)

// Version is reported on the about page.
const Version = "1.1.5"

// guiFS holds the embedded frontend for this build.
var guiFS fs.FS

// crashLog persists a panic for post-mortem: the release build has no console,
// so without this a panic looks like a silent flash-exit.
func crashLog(v any) {
	dir := os.Getenv("LOCALAPPDATA")
	if dir == "" {
		dir = "."
	}
	dir = filepath.Join(dir, "AetherGUI")
	_ = os.MkdirAll(dir, 0o755)
	msg := "panic: " + fmt.Sprint(v) + "\n\n" + string(debug.Stack()) + "\n"
	_ = os.WriteFile(filepath.Join(dir, "crash.log"), []byte(msg), 0o644)
}

// quit is closed exactly once when something asks the process to shut down.
var (
	quitOnce sync.Once
	quitCh   = make(chan struct{})
)

func requestQuit() { quitOnce.Do(func() { close(quitCh) }) }

func main() {
	defer func() {
		if v := recover(); v != nil {
			crashLog(v)
			os.Exit(1)
		}
	}()

	var (
		connectFlag = flag.Bool("connect", false, "connect right after launch (used by autostart)")
		uiMode      = flag.String("ui", "auto", "UI host: auto (WebView2 window), window, browser, none (service only)")
		portFlag    = flag.Int("port", 0, "loopback port for the UI service (0 = pick a free one)")
		printURL    = flag.Bool("print-url", false, "print the UI URL to stdout")
	)
	flag.Parse()

	guiFS = uiAssets()

	application, err := app.New()
	if err != nil {
		crashLog(err)
		os.Exit(1)
	}
	defer application.Close()

	bridge := webbridge.New(webbridge.Config{App: application, Assets: guiFS, Version: Version})
	bridge.SetOnQuit(requestQuit)

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(*portFlag)))
	if err != nil {
		crashLog(err)
		os.Exit(1)
	}
	go func() { _ = http.Serve(ln, bridge.Handler()) }()

	url := bridge.URL(ln.Addr().String())
	logx.Infof("[gui] UI service listening on %s", ln.Addr())
	if *printURL {
		fmt.Println(url)
	}

	if *connectFlag || application.Settings.AutoConnect {
		go func() {
			defer func() { _ = recover() }()
			if err := application.Connect(); err != nil {
				logx.Errorf("[main] auto connect failed: %v", err)
			}
		}()
	}

	switch strings.ToLower(*uiMode) {
	case "none":
		// Service-only (headless): useful for remote debugging of the UI.
		logx.Infof("[gui] headless mode – %s", url)
		<-quitCh
	default:
		runUI(application, bridge, url, strings.ToLower(*uiMode))
	}

	logx.Infof("[gui] shutting down")
}
