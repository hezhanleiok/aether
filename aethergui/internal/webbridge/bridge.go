//go:build windows

// Package webbridge exposes the assembled application over a small local HTTP
// API (JSON + Server-Sent Events) so the web UI can drive every real feature:
// connect/disconnect, protocol switching, node selection and latency tests,
// split rules, settings, core management and the live log.
//
// The listener binds to 127.0.0.1 only, and every API call must carry the
// session cookie handed out with the page, so no other local page can reach
// the VPN control surface.
package webbridge

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aethergui/aethergui/internal/app"
	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/vpn"
)

// Bridge is the HTTP front end of the application.
type Bridge struct {
	app     *app.App
	assets  fs.FS
	version string
	token   string

	mu       sync.Mutex
	clients  map[chan []byte]struct{}
	onQuit   func()
	onHide   func()
	lastPing time.Time
}

// Config wires the bridge.
type Config struct {
	App     *app.App
	Assets  fs.FS
	Version string
}

// New builds the bridge and subscribes to every observable subsystem.
func New(cfg Config) *Bridge {
	b := &Bridge{
		app:     cfg.App,
		assets:  cfg.Assets,
		version: cfg.Version,
		token:   randomToken(),
		clients: map[chan []byte]struct{}{},
	}
	a := cfg.App
	a.OnState(func(vpn.State) { b.pushSnapshot() })
	a.OnNodes(func() { b.pushSnapshot() })
	a.OnCore(func() { b.pushSnapshot() })
	a.Traffic.Subscribe(func(app.TrafficSample) { b.pushSnapshot() })
	logx.Subscribe(func(e logx.Entry) { b.push("log", e) })
	return b
}

// SetOnQuit registers the callback triggered by the UI "exit" action.
func (b *Bridge) SetOnQuit(fn func()) { b.onQuit = fn }

// SetOnHide registers the callback triggered by the UI "minimise" action.
func (b *Bridge) SetOnHide(fn func()) { b.onHide = fn }

// Clients reports how many UI instances are attached (the shell watchdog uses
// it to detect a closed window).
func (b *Bridge) Clients() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.clients)
}

// Token is the session token handed to the browser with the page.
func (b *Bridge) Token() string { return b.token }

// URL builds the loopback URL for a listening address.
func (b *Bridge) URL(addr string) string {
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	return "http://" + addr + "/?t=" + b.token
}

func randomToken() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// ---------------------------------------------------------------------------
// fan-out
// ---------------------------------------------------------------------------

func (b *Bridge) push(kind string, payload any) {
	raw, err := json.Marshal(map[string]any{"type": kind, "data": payload})
	if err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.clients {
		select {
		case ch <- raw:
		default: // slow client: the next tick resends the full state
		}
	}
}

func (b *Bridge) pushSnapshot() { b.push("snapshot", b.snapshot()) }

// ---------------------------------------------------------------------------
// routing
// ---------------------------------------------------------------------------

// Handler returns the complete HTTP surface.
func (b *Bridge) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stream", b.guard(b.stream))
	mux.HandleFunc("/api/snapshot", b.guard(b.getSnapshot))
	mux.HandleFunc("/api/logs", b.guard(b.logs))
	mux.HandleFunc("/api/traffic/series", b.guard(b.series))
	mux.HandleFunc("/api/connect", b.guard(b.connect))
	mux.HandleFunc("/api/disconnect", b.guard(b.disconnect))
	mux.HandleFunc("/api/reconnect", b.guard(b.reconnect))
	mux.HandleFunc("/api/protocol", b.guard(b.setProtocol))
	mux.HandleFunc("/api/mode", b.guard(b.setMode))
	mux.HandleFunc("/api/nodes/test", b.guard(b.testNodes))
	mux.HandleFunc("/api/nodes/select", b.guard(b.selectNode))
	mux.HandleFunc("/api/nodes/auto", b.guard(b.autoNode))
	mux.HandleFunc("/api/nodes/probe", b.guard(b.probeNodes))
	mux.HandleFunc("/api/nodes/rescan", b.guard(b.rescan))
	mux.HandleFunc("/api/exit/refresh", b.guard(b.refreshExit))
	mux.HandleFunc("/api/core/detect", b.guard(b.coreDetect))
	mux.HandleFunc("/api/core/restart", b.guard(b.coreRestart))
	mux.HandleFunc("/api/core/stop", b.guard(b.coreStop))
	mux.HandleFunc("/api/settings", b.guard(b.settings))
	mux.HandleFunc("/api/logs/clear", b.guard(b.clearLogs))
	mux.HandleFunc("/api/client-log", b.guard(b.clientLog))
	mux.HandleFunc("/api/system/open", b.guard(b.openExternal))
	mux.HandleFunc("/api/system/reveal", b.guard(b.revealPath))
	mux.HandleFunc("/api/window/hide", b.guard(b.windowHide))
	mux.HandleFunc("/api/window/quit", b.guard(b.windowQuit))
	mux.HandleFunc("/", b.static)
	return mux
}

// guard enforces the loopback session cookie (except for the page itself).
func (b *Bridge) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !b.authorized(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		next(w, r)
	}
}

func (b *Bridge) authorized(r *http.Request) bool {
	if c, err := r.Cookie(cookieName); err == nil && c.Value == b.token {
		return true
	}
	return r.URL.Query().Get("t") == b.token
}

const cookieName = "aether_ui"

// ---------------------------------------------------------------------------
// static assets
// ---------------------------------------------------------------------------

func (b *Bridge) static(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if name == "" || name == "index.html" {
		if r.URL.Query().Get("t") != b.token {
			http.Error(w, "invalid session token", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    b.token,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
			HttpOnly: false,
		})
		name = "index.html"
	}
	if strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(b.assets, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// ---------------------------------------------------------------------------
// read endpoints
// ---------------------------------------------------------------------------

func (b *Bridge) getSnapshot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, b.snapshot())
}

func (b *Bridge) logs(w http.ResponseWriter, r *http.Request) {
	n := 400
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 4000 {
			n = parsed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": logx.Tail(n)})
}

func (b *Bridge) series(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	writeJSON(w, http.StatusOK, map[string]any{
		"range":  rng,
		"points": b.app.Traffic.Series(rng),
	})
}

// stream is the Server-Sent Events feed: one snapshot per second (which
// already carries the fresh traffic counters) plus log lines as they appear.
func (b *Bridge) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan []byte, 16)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.lastPing = time.Now()
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.clients, ch)
		b.mu.Unlock()
	}()

	writeSSE := func(raw []byte) {
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(raw)
		_, _ = w.Write([]byte("\n\n"))
	}

	if raw, err := json.Marshal(map[string]any{"type": "snapshot", "data": b.snapshot()}); err == nil {
		writeSSE(raw)
	}
	flusher.Flush()

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			b.mu.Lock()
			b.lastPing = time.Now()
			b.mu.Unlock()
			raw, err := json.Marshal(map[string]any{"type": "snapshot", "data": b.snapshot()})
			if err != nil {
				continue
			}
			writeSSE(raw)
			flusher.Flush()
		case raw := <-ch:
			writeSSE(raw)
			flusher.Flush()
		}
	}
}

// ---------------------------------------------------------------------------
// actions
// ---------------------------------------------------------------------------

func (b *Bridge) connect(w http.ResponseWriter, r *http.Request) {
	go func() {
		if err := b.app.Connect(); err != nil {
			logx.Errorf("[ui] connect: %v", err)
		}
	}()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) disconnect(w http.ResponseWriter, _ *http.Request) {
	go b.app.Disconnect()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) reconnect(w http.ResponseWriter, _ *http.Request) {
	go b.app.Reconnect()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) setProtocol(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key string `json:"key"`
	}
	if !decode(w, r, &body) {
		return
	}
	p, ok := ProtocolByKey(body.Key)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown protocol " + body.Key})
		return
	}
	if err := b.app.SaveSettings(applyProtocol(b.app.Settings, p)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	logx.Infof("[ui] protocol -> %s", p.Label)
	go b.app.Reconnect()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func applyProtocol(s config.Settings, p Protocol) config.Settings {
	s.Mode = config.Mode(p.Mode)
	s.Protocol = p.Proto
	s.UseH2 = p.UseH2
	return s
}

func (b *Bridge) setMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if !decode(w, r, &body) {
		return
	}
	switch config.Mode(body.Mode) {
	case config.ModeFullVPN, config.ModeProxy, config.ModeSplit, config.ModeDirect:
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown mode " + body.Mode})
		return
	}
	if err := b.app.UpdateSettings(func(s *config.Settings) { s.Mode = config.Mode(body.Mode) }); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	logx.Infof("[ui] routing mode -> %s", body.Mode)
	go b.app.Reconnect()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) testNodes(w http.ResponseWriter, _ *http.Request) {
	b.app.TestAllNodes()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) selectNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string `json:"id"`
		Connect bool   `json:"connect"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := b.app.SelectNode(body.ID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if body.Connect && b.app.VPN.State().Status != vpn.StatusConnected {
		go func() {
			if err := b.app.Connect(); err != nil {
				logx.Errorf("[ui] connect: %v", err)
			}
		}()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) probeNodes(w http.ResponseWriter, _ *http.Request) {
	b.app.ProbeNodes()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) autoNode(w http.ResponseWriter, _ *http.Request) {
	if err := b.app.SelectAutoNode(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) rescan(w http.ResponseWriter, _ *http.Request) {
	b.app.RescanGateways()
	go b.app.Reconnect()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) refreshExit(w http.ResponseWriter, _ *http.Request) {
	go b.app.RefreshExitInfo()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) coreDetect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := b.app.UpdateSettings(func(s *config.Settings) { s.CorePath = strings.TrimSpace(body.Path) }); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	go b.app.Redetect()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) coreRestart(w http.ResponseWriter, _ *http.Request) {
	go func() {
		if err := b.app.RestartCore(); err != nil {
			logx.Errorf("[ui] core restart: %v", err)
		}
	}()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) coreStop(w http.ResponseWriter, _ *http.Request) {
	go func() {
		if err := b.app.StopCore(); err != nil {
			logx.Errorf("[ui] core stop: %v", err)
		}
	}()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// settings merges a partial Settings object onto the stored one: every key the
// UI omits keeps its current value.
func (b *Bridge) settings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, b.app.Settings)
		return
	}
	var patch map[string]json.RawMessage
	if !decode(w, r, &patch) {
		return
	}
	s := b.app.Settings
	raw, _ := json.Marshal(&s)
	var merged map[string]json.RawMessage
	_ = json.Unmarshal(raw, &merged)
	for k, v := range patch {
		merged[k] = v
	}
	raw, _ = json.Marshal(merged)
	if err := json.Unmarshal(raw, &s); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := b.app.SaveSettings(s); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	logx.Infof("[ui] settings saved")
	writeJSON(w, http.StatusOK, b.app.Settings)
}

// clientLog funnels browser-side diagnostics (viewport size, uncaught errors)
// into the same log file, so a broken embedded view is diagnosable without a
// debugger attached.
func (b *Bridge) clientLog(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind string `json:"kind"`
		Data any    `json:"data"`
	}
	if !decode(w, r, &body) {
		return
	}
	raw, _ := json.Marshal(body.Data)
	switch body.Kind {
	case "error":
		logx.Errorf("[ui] %s", raw)
	default:
		logx.Infof("[ui] %s %s", body.Kind, raw)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) clearLogs(w http.ResponseWriter, _ *http.Request) {
	logx.Clear()
	b.pushSnapshot()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) openExternal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URL string `json:"url"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !strings.HasPrefix(body.URL, "http://") && !strings.HasPrefix(body.URL, "https://") {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "only http(s) links"})
		return
	}
	go func() {
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", body.URL).Start()
	}()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) revealPath(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if !decode(w, r, &body) {
		return
	}
	go func() { _ = exec.Command("explorer", body.Path).Start() }()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) windowHide(w http.ResponseWriter, _ *http.Request) {
	if b.onHide != nil {
		go b.onHide()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (b *Bridge) windowQuit(w http.ResponseWriter, _ *http.Request) {
	if b.onQuit != nil {
		go b.onQuit()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad request: " + err.Error()})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
