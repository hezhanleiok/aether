//go:build windows

package coremgr

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"syscall"
)

// LibraryBackend loads libaether.dll at runtime and drives the official C API
// (aether_core_start / aether_job_poll / aether_job_cancel / aether_version).
// This is the documented embedding path (Docs/DOCS.en.md "Using Aether as a
// library"). The dll must be provided by the user; discovery is local only.
type LibraryBackend struct {
	mu    sync.Mutex
	dll   *syscall.LazyDLL
	procs procs
}

type procs struct {
	version    *syscall.LazyProc
	strFree    *syscall.LazyProc
	coreStart  *syscall.LazyProc
	jobPoll    *syscall.LazyProc
	jobCancel  *syscall.LazyProc
	jobFree    *syscall.LazyProc
}

func NewLibraryBackend() *LibraryBackend { return &LibraryBackend{} }

func (b *LibraryBackend) Kind() string { return "library" }

// Locate resolves the dll: explicit path first, then beside the exe, then
// core-bin/. Local only — never downloads.
func (b *LibraryBackend) Locate(corePath string) (string, error) {
	candidates := func() []string {
		var out []string
		if corePath != "" {
			out = append(out, corePath)
		}
		if exe, err := os.Executable(); err == nil {
			d := filepath.Dir(exe)
			out = append(out, filepath.Join(d, "libaether.dll"), filepath.Join(d, "aether.dll"))
		}
		if wd, err := os.Getwd(); err == nil {
			out = append(out,
				filepath.Join(wd, "libaether.dll"),
				filepath.Join(wd, "core-bin", "libaether.dll"))
		}
		return out
	}()
	for _, c := range candidates {
		if fileExists(c) {
			if abs, err := filepath.Abs(c); err == nil {
				return abs, nil
			}
			return c, nil
		}
	}
	return "", fmt.Errorf("%w: no libaether.dll beside the app or in core-bin/", ErrCoreMissing)
}

func (b *LibraryBackend) load(dllPath string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dll != nil {
		return nil
	}
	dll := syscall.NewLazyDLL(dllPath)
	if err := dll.Load(); err != nil {
		return fmt.Errorf("load %s: %w", dllPath, err)
	}
	p := procs{
		version:   dll.NewProc("aether_version"),
		strFree:   dll.NewProc("aether_string_free"),
		coreStart: dll.NewProc("aether_core_start"),
		jobPoll:   dll.NewProc("aether_job_poll"),
		jobCancel: dll.NewProc("aether_job_cancel"),
		jobFree:   dll.NewProc("aether_job_free"),
	}
	for name, proc := range map[string]*syscall.LazyProc{
		"aether_version":    p.version,
		"aether_string_free": p.strFree,
		"aether_core_start": p.coreStart,
		"aether_job_poll":   p.jobPoll,
		"aether_job_cancel": p.jobCancel,
		"aether_job_free":   p.jobFree,
	} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("dll lacks %s: %w", name, err)
		}
	}
	b.dll, b.procs = dll, p
	return nil
}

func (b *LibraryBackend) takeString(p uintptr) string {
	if p == 0 {
		return ""
	}
	defer b.procs.strFree.Call(p)
	return windows.BytePtrToString((*byte)(unsafe.Pointer(p)))
}

// ProbeVersion calls aether_version.
func (b *LibraryBackend) ProbeVersion(ctx context.Context, corePath string) (string, error) {
	if err := b.load(corePath); err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	r1, _, _ := b.procs.version.Call()
	text := b.takeString(r1)
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		return "", fmt.Errorf("version reply: %w", err)
	}
	if ok, _ := m["ok"].(bool); !ok {
		msg, _ := m["error"].(string)
		return "", fmt.Errorf("core version error: %s", msg)
	}
	ver, _ := m["version"].(string)
	if ver == "" {
		ver = "library"
	}
	return ver, nil
}

// librarySession polls a core job.
type librarySession struct {
	id      uint64
	b       *LibraryBackend
	events  chan CoreEvent
	stopped chan struct{}
	once    sync.Once
}

func (s *librarySession) Stop() error {
	s.once.Do(func() {
		s.b.procs.jobCancel.Call(uintptr(s.id))
	})
	return nil
}

func (s *librarySession) Events() <-chan CoreEvent { return s.events }

func (s *librarySession) Done() <-chan struct{} { return s.stopped }

// Start runs aether_core_start with a JSON argv and polls the job.
func (b *LibraryBackend) Start(env map[string]string, workDir string) (Session, error) {
	dllPath := os.Getenv("AETHER_CORE_DLL")
	if dllPath == "" {
		if found, err := b.Locate(""); err == nil {
			dllPath = found
		} else {
			return nil, err
		}
	}
	if err := b.load(dllPath); err != nil {
		return nil, err
	}
	// The library core reads AETHER_* env directly; apply into this process.
	for k, v := range env {
		_ = syscall.Setenv(k, v)
	}
	argv, _ := json.Marshal([]string{})
	pargv, err := syscall.BytePtrFromString(string(argv))
	if err != nil {
		return nil, err
	}
	r1, _, _ := b.procs.coreStart.Call(uintptr(unsafe.Pointer(pargv)))
	var start map[string]any
	if err := json.Unmarshal([]byte(b.takeString(r1)), &start); err != nil {
		return nil, fmt.Errorf("core_start reply: %w", err)
	}
	if ok, _ := start["ok"].(bool); !ok {
		msg, _ := start["error"].(string)
		return nil, fmt.Errorf("core start: %s", msg)
	}
	id := uint64(start["job"].(float64))

	s := &librarySession{id: id, b: b, events: make(chan CoreEvent, 128), stopped: make(chan struct{})}
	go func() {
		defer close(s.events)
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				r, _, _ := b.procs.jobPoll.Call(uintptr(id))
				var poll map[string]any
				if err := json.Unmarshal([]byte(b.takeString(r)), &poll); err != nil {
					s.emit("failed", "poll: "+err.Error())
					return
				}
				state, _ := poll["state"].(string)
				if state == "done" {
					s.emit("stopped", "")
					b.procs.jobFree.Call(uintptr(id))
					return
				}
			}
		}
	}()
	return s, nil
}

func (s *librarySession) emit(kind, line string) {
	select {
	case s.events <- CoreEvent{Kind: kind, Line: line, When: time.Now()}:
	default:
	}
}
