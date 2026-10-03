package watchguard

import "testing"

// TestWatchguardIgnoresWintun verifies that wintun virtual interfaces (including
// the pool's suffixed names) are excluded from network-change detection, while
// real physical-NIC changes still register. Pure functions, no real interfaces.
func TestWatchguardIgnoresWintun(t *testing.T) {
	ignore := []string{"Xiaohe"}

	withWintun := []string{
		"Ethernet|192.168.1.10/24",
		"Xiaohe|172.16.0.2/32",
		"Xiaohe 2|172.16.0.3/32",
	}
	withoutWintun := []string{
		"Ethernet|192.168.1.10/24",
	}

	filteredWith := filterAddrs(ignore, withWintun)
	filteredWithout := filterAddrs(ignore, withoutWintun)
	if !sameAddrs(filteredWith, filteredWithout) {
		t.Fatalf("wintun interface should be ignored: with=%v without=%v", filteredWith, filteredWithout)
	}

	// A real physical-NIC switch must still be detected.
	changed := filterAddrs(ignore, []string{"WiFi|10.0.0.5/24"})
	if sameAddrs(filteredWith, changed) {
		t.Fatalf("physical NIC change must still be detected: %v", changed)
	}

	// Name matching: exact base, suffixed base, and no over-matching.
	if !matchesIgnore(ignore, "Xiaohe") {
		t.Fatal("exact wintun name should match")
	}
	if !matchesIgnore(ignore, "Xiaohe 3") {
		t.Fatal("suffixed wintun name should match")
	}
	if matchesIgnore(ignore, "XiaoheX") {
		t.Fatal("unrelated name should not match")
	}
}
