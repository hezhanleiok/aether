package app

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
)

func jsonDecode(resp *http.Response, out any) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// ApplyDNSGuard logs the DNS routing posture while connected (the core
// resolves inside the tunnel; AETHER_DNS carries custom servers).
func (a *App) ApplyDNSGuard() {
	s := a.Settings
	if !s.DNSLeakGuard {
		return
	}
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if a.VPN.State().Status == "Connected" {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if s.DNSMode == config.DNSCustom || s.DNSMode == config.DNSDoH {
			logx.Infof("[app] DNS mode %s: servers=%v (tunneled by the core)", s.DNSMode, s.DNSServers)
		}
	}()
}
