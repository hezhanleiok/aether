package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsAreComplete(t *testing.T) {
	s := Defaults()
	if s.Mode != ModeAuto {
		t.Errorf("default mode = %s, want auto", s.Mode)
	}
	if s.SocksPort == 0 || s.HTTPProxyPort == 0 {
		t.Error("default listeners must be set")
	}
	if s.IPStack != IPv4Only {
		t.Errorf("default ip stack = %s, want ipv4", s.IPStack)
	}
	if !s.AutoReconnect || !s.DNSLeakGuard || !s.AutoGateway {
		t.Error("safe defaults must be on")
	}
	if len(s.DNSServers) == 0 {
		t.Error("default DNS servers must exist")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	old := Dir()
	setDirForTest(t, dir)
	s := Defaults()
	s.Mode = ModeGool
	s.CachedGateway = "162.159.192.1:2408"
	s.SplitDirect = []string{"example.com", "private"}
	if err := Save(s); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Mode != ModeGool || got.CachedGateway != "162.159.192.1:2408" {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if len(got.SplitDirect) != 2 {
		t.Errorf("split direct len = %d, want 2", len(got.SplitDirect))
	}
	_ = old
	_ = filepath.Join
	_ = os.Getenv
}

// setDirForTest overrides the config dir via env var LOCALAPPDATA for the test.
func setDirForTest(t *testing.T, dir string) {
	t.Setenv("LOCALAPPDATA", dir)
}
