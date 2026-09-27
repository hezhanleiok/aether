//go:build windows

package sysproxy

// TakePAC installs a PAC file as the system proxy config (split mode). The
// manual proxy switch stays off — a PAC is honoured on its own, and seeding a
// dead placeholder next to it took the whole system's browsing down.
func TakePAC(pacURL string, bypass []string) error {
	return TakePACOnly(pacURL, bypass)
}

// setAutoConfig points WinINET at a PAC url while we own the settings.
func setAutoConfig(url string) error {
	mu.Lock()
	defer mu.Unlock()
	return setAutoConfigLocked(url)
}
