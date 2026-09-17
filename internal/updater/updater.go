// Package updater handles GUI/core update checks and the remote license
// window published in the release repository.
//
// Two independent feeds are consulted:
//
//   - the GUI comes from the publishing repo (version.json at its root), which
//     also carries the license parameters so they can be tuned remotely;
//   - the Aether core comes from the official upstream releases.
//
// A machine that cannot reach the network is never locked out: every check
// fails open.
package updater

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	// ManifestURL is version.json at the root of the publishing repo.
	ManifestURL = "https://raw.githubusercontent.com/hezhanleiok/aether/main/version.json"
	// CoreReleaseAPI is the official Aether core release feed; the pinned tag
	// is appended when resolving which core to install.
	CoreReleaseAPI = "https://api.github.com/repos/CluvexStudio/Aether/releases"

	// DefaultMessage / DefaultContact are used when the manifest omits them.
	DefaultMessage = "软件已到期，请联系作者续期"
	DefaultContact = "Telegram: @xiaoheok\nEmail: hezhanleiok@gmail.com"
)

// Manifest mirrors version.json in the publishing repository.
type Manifest struct {
	GUI struct {
		Version string `json:"version"`
		URL     string `json:"url"`
		Notes   string `json:"notes"`
	} `json:"gui"`
	// Core pins the core release this GUI build is validated against. The
	// core is offered only from here and never straight from upstream, so a
	// newer upstream core can never land before a GUI that supports it.
	Core struct {
		Version string `json:"version"`
		Notes   string `json:"notes"`
	} `json:"core"`
	License struct {
		Enabled   bool   `json:"enabled"`
		Expiry    string `json:"expiry"`     // fixed cutoff, "2006-01-02"
		TrialDays int    `json:"trial_days"` // or days counted from first run
		Message   string `json:"message"`
		Contact   string `json:"contact"`
	} `json:"license"`
}

// UpdateInfo is the result of one check, sent to the UI.
type UpdateInfo struct {
	GUIHas    bool   `json:"gui_has"`
	GUIVer    string `json:"gui_version"`
	GUIURL    string `json:"gui_url"`
	GUINotes  string `json:"gui_notes"`
	CoreHas   bool   `json:"core_has"`
	CoreVer   string `json:"core_version"`
	CoreURL   string `json:"core_url"`
	CoreNotes string `json:"core_notes"`
	CheckedAt string `json:"checked_at"`
	Error     string `json:"error,omitempty"`
}

// License is the state of the remote license window.
type License struct {
	Expired  bool   `json:"expired"`
	DaysLeft int    `json:"days_left"` // -1 means unlimited/unknown
	ExpiryAt string `json:"expiry_at,omitempty"`
	Message  string `json:"message"`
	Contact  string `json:"contact"`
	Offline  bool   `json:"offline"`
}

// systemProxy returns the proxy configured in Internet Settings, if enabled.
// GitHub is not reachable directly on some networks, so update checks must
// honour it.
func systemProxy() *url.URL {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()

	en, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil || en != 1 {
		return nil
	}
	s, _, err := k.GetStringValue("ProxyServer")
	if err != nil {
		return nil
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil
	}
	return u
}

func client(timeout time.Duration) *http.Client {
	tr := &http.Transport{}
	if p := systemProxy(); p != nil {
		tr.Proxy = http.ProxyURL(p)
	} else {
		// The Internet Settings switch is often off even when a local proxy
		// client is running, so fall back to HTTPS_PROXY/HTTP_PROXY.
		tr.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// FetchManifest reads version.json from the publishing repo.
func FetchManifest() (*Manifest, error) {
	resp, err := client(20 * time.Second).Get(ManifestURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest http %d", resp.StatusCode)
	}
	var m Manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// parseVer extracts "2.0.0" out of strings like "v2.0.0" or "aether 2.0.0".
func parseVer(s string) [3]int {
	var v [3]int
	start := -1
	for i, r := range s {
		if r >= '0' && r <= '9' {
			start = i
			break
		}
	}
	if start < 0 {
		return v
	}
	parts := strings.Split(s[start:], ".")
	for i := 0; i < 3 && i < len(parts); i++ {
		n := 0
		for _, r := range parts[i] {
			if r >= '0' && r <= '9' {
				n = n*10 + int(r-'0')
			} else {
				break
			}
		}
		v[i] = n
	}
	return v
}

// newer reports whether a is strictly greater than b.
func newer(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	va, vb := parseVer(a), parseVer(b)
	for i := 0; i < 3; i++ {
		if va[i] != vb[i] {
			return va[i] > vb[i]
		}
	}
	return false
}

// Check compares the running GUI/core against both feeds.
func Check(guiVer, coreVer string) *UpdateInfo {
	info := &UpdateInfo{CheckedAt: time.Now().Format(time.RFC3339)}

	m, err := FetchManifest()
	if err != nil {
		info.Error = err.Error()
		return info // offline: there is nothing to compare against
	}

	if m.GUI.Version != "" && newer(m.GUI.Version, guiVer) {
		info.GUIHas = true
		info.GUIVer = m.GUI.Version
		info.GUIURL = m.GUI.URL
		info.GUINotes = m.GUI.Notes
	}

	// The core follows the pinned release only. An upstream core newer than
	// the GUI was validated against is deliberately left alone, so GUI and
	// core can never drift out of sync.
	if m.Core.Version != "" && newer(m.Core.Version, coreVer) {
		if dl, err := fetchCoreAssetURL(m.Core.Version); err == nil && dl != "" {
			info.CoreHas = true
			info.CoreVer = m.Core.Version
			info.CoreURL = dl
			info.CoreNotes = m.Core.Notes
		}
	}
	return info
}

// fetchCoreAssetURL returns the Windows archive of one official release tag.
func fetchCoreAssetURL(tag string) (string, error) {
	req, err := http.NewRequest("GET", CoreReleaseAPI+"/tags/"+tag, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "AetherVPN")

	resp, err := client(20 * time.Second).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("core release %s: http %d", tag, resp.StatusCode)
	}

	var r struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	for _, a := range r.Assets {
		n := strings.ToLower(a.Name)
		if strings.Contains(n, "windows") && strings.HasSuffix(n, ".zip") {
			return a.URL, nil
		}
	}
	return "", nil
}

// firstRun records (once) when this installation was first started, so a
// trial window can be counted from the user's own beginning.
func firstRun(dir string) time.Time {
	p := filepath.Join(dir, "firstrun")
	if b, err := os.ReadFile(p); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 {
			return time.Unix(n, 0)
		}
	}
	now := time.Now()
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(p, []byte(strconv.FormatInt(now.Unix(), 10)), 0o644)
	return now
}

// LicenseStatus evaluates the remote license window. Offline, disabled or
// unreadable configurations always grant access.
func LicenseStatus(dir string) License {
	m, err := FetchManifest()
	if err != nil {
		return License{Offline: true, DaysLeft: -1}
	}
	lc := m.License
	if !lc.Enabled {
		return License{DaysLeft: -1}
	}

	msg := lc.Message
	if strings.TrimSpace(msg) == "" {
		msg = DefaultMessage
	}
	contact := lc.Contact
	if strings.TrimSpace(contact) == "" {
		contact = DefaultContact
	}

	// A fixed cutoff wins over the rolling trial window.
	if lc.Expiry != "" {
		if t, err := time.Parse("2006-01-02", lc.Expiry); err == nil {
			end := t.AddDate(0, 0, 1) // the expiry day itself is still usable
			if !time.Now().Before(end) {
				return License{Expired: true, Message: msg, Contact: contact, ExpiryAt: lc.Expiry}
			}
			return License{DaysLeft: int(time.Until(end).Hours() / 24), ExpiryAt: lc.Expiry}
		}
	}
	if lc.TrialDays > 0 {
		deadline := firstRun(dir).AddDate(0, 0, lc.TrialDays)
		if !time.Now().Before(deadline) {
			return License{
				Expired:  true,
				Message:  msg,
				Contact:  contact,
				ExpiryAt: deadline.Format("2006-01-02"),
			}
		}
		return License{
			DaysLeft: int(time.Until(deadline).Hours() / 24),
			ExpiryAt: deadline.Format("2006-01-02"),
		}
	}
	return License{DaysLeft: -1}
}

// download fetches url into dest, writing through a .part file first.
func download(rawURL, dest string) error {
	resp, err := client(0).Get(rawURL) // no total timeout: binaries can be large
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

// ApplyGUI downloads the new GUI binary next to the running one and hands the
// swap to a batch script: a running exe cannot overwrite itself.
func ApplyGUI(dlURL, exePath string) error {
	if dlURL == "" {
		return fmt.Errorf("no download url in the manifest")
	}
	newPath := exePath + ".new"
	if err := download(dlURL, newPath); err != nil {
		return err
	}
	bat := filepath.Join(filepath.Dir(exePath), "aether-update.bat")
	script := "@echo off\r\n" +
		"ping -n 3 127.0.0.1 >nul\r\n" +
		"move /Y \"" + newPath + "\" \"" + exePath + "\"\r\n" +
		"start \"\" \"" + exePath + "\"\r\n" +
		"del \"%~f0\"\r\n"
	if err := os.WriteFile(bat, []byte(script), 0o644); err != nil {
		return err
	}
	return exec.Command("cmd", "/c", "start", "", "/min", bat).Start()
}

// ApplyCore downloads the official Windows archive and extracts the core exe
// to corePath+".new"; the caller stops the core, swaps it in and restarts.
func ApplyCore(dlURL, corePath string) error {
	if dlURL == "" {
		return fmt.Errorf("no core download url")
	}
	zipPath := corePath + ".zip"
	if err := download(dlURL, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".exe") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(corePath + ".new")
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		return err
	}
	return fmt.Errorf("no exe inside the core archive")
}
