//go:build windows

package sysproxy

// TakePAC installs a PAC file as the system proxy config (split mode).
func TakePAC(pacURL string, bypass []string) error {
	if !Taken() {
		if err := Take(Options{Server: "127.0.0.1:1", Bypass: bypass}); err != nil {
			return err
		}
	}
	return setAutoConfig(pacURL)
}

// setAutoConfig points WinINET at a PAC url while we own the settings.
func setAutoConfig(url string) error {
	mu.Lock()
	defer mu.Unlock()
	return setAutoConfigLocked(url)
}
