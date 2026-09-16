//go:build windows

package sysproxy

import (
	"os"
	"strings"
	"testing"
)

func TestWritePACDirectAndBlock(t *testing.T) {
	dir := t.TempDir()
	cfg := SplitConfig{
		DirectDomains: []string{"example.com", "*.corp.test", "keyword:internal", "full:exact.example"},
		BlockDomains:  []string{"ads.example"},
	}
	url, err := WritePAC(dir, "127.0.0.1", 1820, cfg)
	if err != nil {
		t.Fatalf("write pac: %v", err)
	}
	if !strings.HasPrefix(url, "file:///") {
		t.Errorf("pac url = %q", url)
	}
	path := strings.TrimPrefix(url, "file:///")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pac: %v", err)
	}
	pac := string(b)
	if !strings.Contains(pac, "PROXY 127.0.0.1:9") {
		t.Error("block rule missing")
	}
	if !strings.Contains(pac, "example.com") || !strings.Contains(pac, ".example.com") {
		t.Error("domain direct rule missing")
	}
	if !strings.Contains(pac, ".corp.test") {
		t.Error("wildcard rule missing")
	}
	if !strings.Contains(pac, "internal") {
		t.Error("keyword rule missing")
	}
	if !strings.Contains(pac, "exact.example") {
		t.Error("full rule missing")
	}
	if !strings.Contains(pac, "PROXY 127.0.0.1:1820") {
		t.Error("default proxy missing")
	}
}

func TestHostCondCIDR(t *testing.T) {
	c := hostCond("10.0.0.0/8")
	if !strings.Contains(c, "isInNet") || !strings.Contains(c, "255.0.0.0") {
		t.Errorf("cidr cond = %q", c)
	}
}
