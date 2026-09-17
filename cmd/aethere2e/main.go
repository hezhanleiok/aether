// aethere2e: full end-to-end proof through the Core Controller.
// Usage: aethere2e [wireguard|h2|h3|gool|mim] — default h3.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aethergui/aethergui/internal/app"
	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/vpn"

	"golang.org/x/net/proxy"
)

type protoCfg struct {
	Name     string
	Mode     config.Mode
	Protocol string
	UseH2    bool
}

var protos = map[string]protoCfg{
	"wireguard": {Name: "WireGuard", Mode: config.ModeWARP, Protocol: "wg"},
	"h2":        {Name: "MASQUE H2", Mode: config.ModeMasqueH2, Protocol: "masque", UseH2: true},
	"h3":        {Name: "MASQUE H3", Mode: config.ModeMasqueH3, Protocol: "masque"},
	"gool":      {Name: "GOOL", Mode: config.ModeGool, Protocol: "gool"},
	"mim":       {Name: "MASQUE-in-MASQUE", Mode: config.ModeMasqueH3, Protocol: "mim"},
}

func main() {
	which := "h3"
	if len(os.Args) > 1 {
		which = os.Args[1]
	}
	p, ok := protos[which]
	if !ok {
		fmt.Println("unknown proto:", which, "— use wireguard|h2|h3|gool|mim")
		os.Exit(1)
	}
	fmt.Println("== aethere2e [" + p.Name + "] ==")
	a, err := app.New()
	if err != nil {
		fmt.Println("FAIL app:", err)
		os.Exit(1)
	}
	defer a.Close()
	fmt.Printf("core: health=%s version=%q path=%s backend=%s\n",
		a.Core.Health(), a.Core.Version(), a.Core.Path(), a.Core.Backend().Kind())

	s := a.Settings
	s.Mode = p.Mode
	s.Protocol = p.Protocol
	s.UseH2 = p.UseH2
	s.ScanMode = config.ScanTurbo
	s.AutoReconnect = false
	if err := a.VPN.Connect(s); err != nil {
		fmt.Println("FAIL connect:", err)
		os.Exit(1)
	}
	fmt.Println("manager: connecting...")

	deadline := time.Now().Add(6 * time.Minute)
	var state vpn.State
	for time.Now().Before(deadline) {
		state = a.VPN.State()
		if state.Status == vpn.StatusConnected {
			break
		}
		if state.Status == vpn.StatusFailed {
			fmt.Println("FAIL state:", state.Error)
			a.Disconnect()
			os.Exit(1)
		}
		time.Sleep(2 * time.Second)
	}
	if state.Status != vpn.StatusConnected {
		fmt.Println("FAIL: not connected; last =", state.Status)
		a.Disconnect()
		os.Exit(1)
	}
	fmt.Println("manager: CONNECTED")

	socksAddr := fmt.Sprintf("127.0.0.1:%d", s.SocksPort)
	for i := 0; i < 60; i++ {
		if c, err := net.DialTimeout("tcp", socksAddr, time.Second); err == nil {
			c.Close()
			break
		}
		time.Sleep(time.Second)
	}
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		fmt.Println("FAIL socks dialer:", err)
		a.Disconnect()
		os.Exit(1)
	}
	client := &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	trace := fetch(ctx, client, "https://www.cloudflare.com/cdn-cgi/trace")
	warpOn, exitIP := false, ""
	for _, line := range trace {
		if line == "warp=on" {
			warpOn = true
		}
		if strings.HasPrefix(line, "ip=") {
			exitIP = line[3:]
		}
	}
	fmt.Printf("trace: warp=on=%v ip=%s\n", warpOn, exitIP)

	go a.RefreshExitInfo()
	time.Sleep(15 * time.Second)
	st := a.VPN.State()
	fmt.Printf("app state: status=%s exitIP=%s country=%s flag=%s coreRunning=%v\n",
		st.Status, st.ExitIP, st.ExitCountry, st.ExitFlag, st.CoreRunning)

	a.Disconnect()
	time.Sleep(time.Second)
	fmt.Printf("after stop: coreRunning=%v health=%s\n", a.Core.Running(), a.Core.Health())
	if !warpOn {
		fmt.Println("FAIL: warp=on missing")
		os.Exit(1)
	}
	fmt.Println("== E2E PASS [" + p.Name + "] ==")
}

func fetch(ctx context.Context, c *http.Client, url string) []string {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.Do(req)
	if err != nil {
		return []string{"ERR " + err.Error()}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return strings.Split(string(b), "\n")
}
