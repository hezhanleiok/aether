package coremgr

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeBackend is a scriptable backend for controller tests.
type fakeBackend struct {
	kind       string
	locateErr  error
	version    string
	versionErr error
	startErr   error
	env        map[string]string
	events     chan CoreEvent
	stopCalls  int
	tap        func(CoreEvent)
}

func (f *fakeBackend) Kind() string { return f.kind }

func (f *fakeBackend) Locate(p string) (string, error) {
	if f.locateErr != nil {
		return "", f.locateErr
	}
	if p == "" {
		p = "found-core"
	}
	return p, nil
}

func (f *fakeBackend) ProbeVersion(ctx context.Context, p string) (string, error) {
	return f.version, f.versionErr
}

func (f *fakeBackend) Start(env map[string]string, wd string) (Session, error) {
	if f.startErr != nil {
		return nil, f.startErr
	}
	f.env = env
	f.events = make(chan CoreEvent, 16)
	return &fakeSession{b: f, done: make(chan struct{})}, nil
}

type fakeSession struct {
	b    *fakeBackend
	done chan struct{}
}

func (s *fakeSession) Stop() error {
	s.b.stopCalls++
	close(s.b.events)
	close(s.done)
	return nil
}

func (s *fakeSession) Events() <-chan CoreEvent { return s.b.events }

func (s *fakeSession) Done() <-chan struct{} { return s.done }

func (s *fakeSession) SetTap(fn func(CoreEvent)) { s.b.tap = fn }

func TestDetectHappyPath(t *testing.T) {
	b := &fakeBackend{kind: "process", version: "aether 2.0.0"}
	m := NewManager(b)
	h, err := m.Detect("")
	if err != nil || h != HealthReady {
		t.Fatalf("detect = %v, %v", h, err)
	}
	if m.Version() != "aether 2.0.0" {
		t.Errorf("version = %q", m.Version())
	}
	if m.Path() != "found-core" {
		t.Errorf("path = %q", m.Path())
	}
}

func TestDetectMissing(t *testing.T) {
	b := &fakeBackend{kind: "process", locateErr: ErrCoreMissing}
	m := NewManager(b)
	h, err := m.Detect("")
	if h != HealthMissing || !errors.Is(err, ErrCoreMissing) {
		t.Fatalf("detect = %v, %v", h, err)
	}
	if _, err := m.Start(nil, ""); !errors.Is(err, ErrNotReady) {
		t.Errorf("start before ready = %v, want ErrNotReady", err)
	}
}

func TestDetectIncompatible(t *testing.T) {
	b := &fakeBackend{kind: "process", versionErr: errors.New("probe failed")}
	m := NewManager(b)
	h, err := m.Detect("")
	if h != HealthIncompatible || err == nil {
		t.Fatalf("detect = %v, %v", h, err)
	}
	if m.Version() != "" {
		t.Error("version must be empty on failure")
	}
}

func TestStartStopLifecycle(t *testing.T) {
	b := &fakeBackend{kind: "process", version: "v1"}
	m := NewManager(b)
	if _, err := m.Detect(""); err != nil {
		t.Fatal(err)
	}
	_, err := m.Start(map[string]string{"AETHER_PROTOCOL": "masque"}, "wd")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if !m.Running() || m.Health() != HealthRunning {
		t.Fatal("manager must report running")
	}
	if b.env["AETHER_PROTOCOL"] != "masque" {
		t.Errorf("env passthrough broken: %v", b.env)
	}
	if _, err := m.Start(nil, ""); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("double start = %v", err)
	}
	if err := m.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if m.Running() || m.Health() != HealthReady {
		t.Fatal("manager must be ready after stop")
	}
}

func TestRestartKeepsEnv(t *testing.T) {
	b := &fakeBackend{kind: "process", version: "v1"}
	m := NewManager(b)
	_, _ = m.Detect("")
	if _, err := m.Restart(map[string]string{"AETHER_SCAN": "turbo"}, ""); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if b.env["AETHER_SCAN"] != "turbo" {
		t.Errorf("restart env = %v", b.env)
	}
}

func TestLogSinkAndEvents(t *testing.T) {
	b := &fakeBackend{kind: "process", version: "v1"}
	m := NewManager(b)
	var got []string
	m.SetLogSink(func(ev CoreEvent) {
		if ev.Kind == "log" {
			got = append(got, ev.Line)
		}
	})
	_, _ = m.Detect("")
	if _, err := m.Start(nil, ""); err != nil {
		t.Fatal(err)
	}
	fakeEmit := func(kind, line string) {
		ev := CoreEvent{Kind: kind, Line: line}
		if b.tap != nil {
			b.tap(ev)
		}
		b.events <- ev
	}
	fakeEmit("log", "hello core")
	fakeEmit("connected", "")
	if err := m.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if len(got) == 0 || !strings.Contains(got[0], "hello core") {
		t.Errorf("log sink got %v", got)
	}
}
