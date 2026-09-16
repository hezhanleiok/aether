// aethersmoke exercises the Core Controller wiring without a window:
// backend pick, core detect (local only), node seeding, env derivation.
package main

import (
	"fmt"
	"os"

	"github.com/aethergui/aethergui/internal/app"
	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/coremgr"
	"github.com/aethergui/aethergui/internal/node"
	"github.com/aethergui/aethergui/internal/vpn"
)

func main() {
	fmt.Println("== aethersmoke ==")

	// 1. Backend + Controller: local detection only.
	backend := coremgr.NewProcessBackend()
	core := coremgr.NewManager(backend)
	h, err := core.Detect("")
	if err != nil {
		fmt.Println("FAIL detect:", err)
		os.Exit(1)
	}
	fmt.Printf("backend=%s path=%s version=%s health=%s\n", backend.Kind(), core.Path(), core.Version(), h)

	// 2. Node pool.
	pool := node.NewPool()
	pool.Seed()
	fmt.Printf("nodes seeded: %d\n", len(pool.List()))

	// 3. Env derivation for each mode.
	for _, m := range []config.Mode{
		config.ModeMasqueH3, config.ModeMasqueH2, config.ModeWARP,
		config.ModeGool, config.ModeFullVPN, config.ModeSplit,
	} {
		s := config.Defaults()
		s.Mode = m
		env := vpn.EnvFor(s)
		fmt.Printf("%-12s AETHER_PROTOCOL=%s H2=%s\n", m, env["AETHER_PROTOCOL"], env["AETHER_MASQUE_HTTP2"])
	}

	// 4. Full app assembly.
	a, err := app.New()
	if err != nil {
		fmt.Println("FAIL app:", err)
		os.Exit(1)
	}
	defer a.Close()
	fmt.Println("app assembled; core:", a.Core.Path(), a.Core.Version())
	fmt.Printf("state: %s coreRunning=%v\n", a.VPN.State().Status, a.Core.Running())
	fmt.Println("== PASS ==")
}
