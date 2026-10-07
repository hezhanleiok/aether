package vpn

import (
	"encoding/json"
	"os"
	"testing"
)

// isolatePsiphonDir points config.Dir() (via LOCALAPPDATA) at a temp dir so the
// overlay writer never touches the real AetherGUI data directory.
func isolatePsiphonDir(t *testing.T) {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())
}

type psiphonOverlayFile struct {
	UpstreamProxyURL     string   `json:"UpstreamProxyURL"`
	LimitTunnelProtocols []string `json:"LimitTunnelProtocols"`
}

func TestWritePsiphonOverlayUsesActualPort(t *testing.T) {
	isolatePsiphonDir(t)
	path, err := WritePsiphonOverlay(12345)
	if err != nil {
		t.Fatalf("WritePsiphonOverlay: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read overlay: %v", err)
	}
	var o psiphonOverlayFile
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("overlay is not valid JSON: %v", err)
	}
	if o.UpstreamProxyURL != "socks5://127.0.0.1:12345" {
		t.Errorf("UpstreamProxyURL = %q, want socks5://127.0.0.1:12345", o.UpstreamProxyURL)
	}
}

func TestWritePsiphonOverlayInvalidPort(t *testing.T) {
	isolatePsiphonDir(t)
	for _, p := range []int{0, -1, 65536, 65537} {
		if _, err := WritePsiphonOverlay(p); err == nil {
			t.Errorf("WritePsiphonOverlay(%d) succeeded, want error", p)
		}
	}
}

func TestWritePsiphonOverlayLimitsProtocols(t *testing.T) {
	isolatePsiphonDir(t)
	path, err := WritePsiphonOverlay(12345)
	if err != nil {
		t.Fatalf("WritePsiphonOverlay: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read overlay: %v", err)
	}
	var o psiphonOverlayFile
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("overlay is not valid JSON: %v", err)
	}

	// Every TCP protocol that honours UpstreamProxyURL must be present.
	// SHADOWSOCKS-OSSH is TCP (TunnelProtocolUsesTCP) and supports upstream
	// proxy (TunnelProtocolSupportsUpstreamProxy), so it is kept.
	want := []string{
		"SSH", "OSSH", "TLS-OSSH", "SHADOWSOCKS-OSSH",
		"UNFRONTED-MEEK-OSSH", "UNFRONTED-MEEK-HTTPS-OSSH", "UNFRONTED-MEEK-SESSION-TICKET-OSSH",
		"FRONTED-MEEK-OSSH", "FRONTED-MEEK-CDN-OSSH", "FRONTED-MEEK-HTTP-OSSH", "FRONTED-MEEK-CDN-HTTP-OSSH",
	}
	got := map[string]bool{}
	for _, p := range o.LimitTunnelProtocols {
		got[p] = true
	}
	if len(o.LimitTunnelProtocols) != len(want) {
		t.Errorf("LimitTunnelProtocols has %d entries, want %d: %v",
			len(o.LimitTunnelProtocols), len(want), o.LimitTunnelProtocols)
	}
	for _, p := range want {
		if !got[p] {
			t.Errorf("missing protocol %q", p)
		}
	}

	// The QUIC (UDP) transports ignore UpstreamProxyURL and must be absent.
	denied := []string{"QUIC-OSSH", "FRONTED-MEEK-QUIC-OSSH", "FRONTED-MEEK-CDN-QUIC-OSSH"}
	for _, p := range denied {
		if got[p] {
			t.Errorf("UDP/QUIC protocol %q must be excluded", p)
		}
	}
}

func TestRemovePsiphonOverlay(t *testing.T) {
	isolatePsiphonDir(t)
	path, err := WritePsiphonOverlay(12345)
	if err != nil {
		t.Fatalf("WritePsiphonOverlay: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("overlay missing after write: %v", err)
	}
	RemovePsiphonOverlay()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("overlay still exists after RemovePsiphonOverlay")
	}
}

func TestRemovePsiphonOverlayIdempotent(t *testing.T) {
	isolatePsiphonDir(t)
	// No overlay written: removing must not error or panic (idempotent).
	RemovePsiphonOverlay()
	RemovePsiphonOverlay()
}
