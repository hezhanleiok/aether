// Package coremgr is the Core Controller: the single owner of the Aether
// Core lifecycle. The GUI never spawns, stops, or configures the core
// directly — it talks to Manager, and Manager decides how the core runs.
//
// Design rules (project requirements):
//   - The core stays a separate entity: it is its own process (or its own
//     library instance), never hard-coded into the GUI.
//   - The GUI owns the core: paths, version checks, lifecycle, arguments,
//     and state are all managed here and exposed through this API.
//   - The interface is modular so the core can be upgraded later: Backend
//     implementations carry every core-specific detail.
//   - No hard-coded repositories, release URLs, or update servers. The user
//     provides the core binary (or dll) via settings or a known local search
//     path; discovery never touches the network.
//   - No auto-update, by design.
package coremgr

import (
	"context"
	"time"
)

// Health is what the GUI shows about the core.
type Health int

const (
	HealthUnknown   Health = iota // not probed yet
	HealthMissing                // no core found at the configured place
	HealthIncompatible           // found, but version probe failed
	HealthReady                  // found and responsive
	HealthRunning                // a core session is up
)

func (h Health) String() string {
	switch h {
	case HealthMissing:
		return "Missing"
	case HealthIncompatible:
		return "Incompatible"
	case HealthReady:
		return "Ready"
	case HealthRunning:
		return "Running"
	default:
		return "Unknown"
	}
}

// CoreEvent is one observable change of the core session.
type CoreEvent struct {
	Kind  string // started|log|identity|connected|scanning|candidate|reconnect|failed|stopped
	Line  string // raw core log line (log events)
	Err   error  // failure detail (failed events)
	When  time.Time
}

// Session is one running core instance, as the GUI sees it.
type Session interface {
	// Stop terminates the session and waits for core exit.
	Stop() error
	// Events streams the session's observable changes. The channel closes
	// when the session ends. It has exactly ONE consumer: the session owner.
	Events() <-chan CoreEvent
	// Done closes when the session has ended (health tracking).
	Done() <-chan struct{}
}

// Backend is the pluggable driver that carries all core-specific knowledge
// (binary path, dll path, argument marshalling, output parsing). Swap it to
// upgrade the core; nothing above this interface changes.
type Backend interface {
	// Kind names the implementation ("process" or "library").
	Kind() string
	// Locate resolves the core the user configured (path override → known
	// local search paths). It never downloads anything.
	Locate(corePath string) (foundPath string, err error)
	// ProbeVersion runs the core's own version report ("aether --version"
	// or aether_version()). Empty string means "present but silent".
	ProbeVersion(ctx context.Context, corePath string) (string, error)
	// Start launches a session with the given AETHER_* environment.
	Start(env map[string]string, workDir string) (Session, error)
}

// Manager is the GUI-facing Core Controller.
type Manager struct {
	backend  Backend
	corePath string // resolved path of the core (exe or dll)
	version  string
	health   Health
	session  Session
	logSink  func(CoreEvent)
}

// NewManager builds the controller over the given backend.
func NewManager(backend Backend) *Manager {
	return &Manager{backend: backend, health: HealthUnknown}
}

// SetLogSink receives every core log line (for the GUI log page).
func (m *Manager) SetLogSink(fn func(CoreEvent)) { m.logSink = fn }

// Backend exposes the active driver.
func (m *Manager) Backend() Backend { return m.backend }

// Path returns the resolved core path ("" until a successful Detect).
func (m *Manager) Path() string { return m.corePath }

// Version returns the probed core version ("" until Detect succeeds).
func (m *Manager) Version() string { return m.version }

// Health returns the last known core health.
func (m *Manager) Health() Health { return m.health }

// Running reports whether a core session is live.
func (m *Manager) Running() bool { return m.session != nil }

// Detect locates the core, probes its version, and updates health. It is
// safe to call at any time and does not touch the network.
func (m *Manager) Detect(corePath string) (Health, error) {
	found, err := m.backend.Locate(corePath)
	if err != nil {
		m.health = HealthMissing
		return m.health, err
	}
	m.corePath = found
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ver, err := m.backend.ProbeVersion(ctx, found)
	if err != nil {
		m.health = HealthIncompatible
		m.version = ""
		return m.health, err
	}
	m.version = ver
	m.health = HealthReady
	return m.health, nil
}

// Start launches the core session. It refuses to run before a successful
// Detect, and refuses double starts. The returned session's Events() channel
// is the single consumer-owned stream: only its owner reads it. The log sink
// is wired into the backend so events are mirrored without competing for the
// channel.
func (m *Manager) Start(env map[string]string, workDir string) (Session, error) {
	if m.health != HealthReady && m.health != HealthRunning {
		return nil, ErrNotReady
	}
	if m.session != nil {
		return nil, ErrAlreadyRunning
	}
	s, err := m.backend.Start(env, workDir)
	if err != nil {
		return nil, err
	}
	m.session = s
	m.health = HealthRunning
	// Mirror events to the log sink through a backend-level tap (no
	// competition for the Events() channel), then track health via Done().
	if t, ok := s.(interface{ SetTap(func(CoreEvent)) }); ok && m.logSink != nil {
		t.SetTap(m.logSink)
	}
	go m.trackSession(s)
	return s, nil
}

// trackSession observes the session through a backend-level tap (not the
// Events() channel, which belongs to the session owner) and resets health
// when the session ends.
func (m *Manager) trackSession(s Session) {
	<-s.Done()
	if m.session == s {
		m.session = nil
	}
	if m.health == HealthRunning {
		m.health = HealthReady
	}
}

// Stop terminates the running session (no-op when idle).
func (m *Manager) Stop() error {
	if m.session == nil {
		return nil
	}
	err := m.session.Stop()
	m.session = nil
	if m.health == HealthRunning {
		m.health = HealthReady
	}
	return err
}

// Restart = Stop + Start with the same environment.
func (m *Manager) Restart(env map[string]string, workDir string) (Session, error) {
	if err := m.Stop(); err != nil {
		return nil, err
	}
	return m.Start(env, workDir)
}
