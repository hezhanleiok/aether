//go:build windows

package coremgr

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/aethergui/aethergui/internal/logx"
	"golang.org/x/sys/windows"
)

// ProcessBackend runs the official aether.exe as an independent child
// process. The GUI starts and stops it, passes AETHER_* config through its
// environment, and reads state from its merged stdout/stderr.
type ProcessBackend struct{}

func NewProcessBackend() *ProcessBackend { return &ProcessBackend{} }

func (b *ProcessBackend) Kind() string { return "process" }

// coreJob is a single process-wide job object with KILL_ON_JOB_CLOSE: when
// the GUI process dies for any reason (normal exit, crash, task-kill), Windows
// reaps every aether.exe child it was assigned. Without this, an abrupt GUI
// death orphans the core and it keeps the SOCKS/HTTP ports occupied.
var (
	coreJobOnce sync.Once
	coreJob      windows.Handle
)

func ensureCoreJob() windows.Handle {
	coreJobOnce.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			logx.Warnf("[coremgr] create job failed: %v", err)
			return
		}
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
			logx.Warnf("[coremgr] set job info failed: %v", err)
			windows.CloseHandle(h)
			return
		}
		coreJob = h
	})
	return coreJob
}

// assignToJob puts a started child process into the kill-on-close job.
func assignToJob(p *os.Process) {
	job := ensureCoreJob()
	if job == 0 || p == nil {
		return
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		logx.Warnf("[coremgr] open process for job failed: %v", err)
		return
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		logx.Warnf("[coremgr] assign to job failed: %v", err)
	}
}

// searchDirs are the local places a core may live, in order. Discovery is
// purely local: beside the GUI exe, under the install root, in core-bin/,
// then PATH. Nothing is downloaded.
func searchDirs() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd, filepath.Join(wd, "core-bin"), filepath.Join(wd, "vendor", "core"))
	}
	return dirs
}

// Locate resolves the core: an explicit path wins (AETHER_CORE env, then the
// configured path); otherwise the local search order above; then PATH.
func (b *ProcessBackend) Locate(corePath string) (string, error) {
	if p := os.Getenv("AETHER_CORE"); p != "" {
		return mustExist(p)
	}
	if corePath != "" {
		return mustExist(corePath)
	}
	for _, dir := range searchDirs() {
		cand := filepath.Join(dir, "aether.exe")
		if fileExists(cand) {
			return filepath.Abs(cand)
		}
	}
	if p, err := exec.LookPath("aether.exe"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs, nil
		}
		return p, nil
	}
	return "", fmt.Errorf("%w: no aether.exe beside the app, in core-bin/, or on PATH (set the core path in Settings)", ErrCoreMissing)
}

func mustExist(p string) (string, error) {
	if !fileExists(p) {
		return "", fmt.Errorf("%w: %s", ErrCoreMissing, p)
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs, nil
	}
	return p, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// ProbeVersion runs "aether.exe --version".
func (b *ProcessBackend) ProbeVersion(ctx context.Context, corePath string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, corePath, "--version")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("core version probe failed: %w", err)
	}
	v := strings.TrimSpace(string(out))
	if v == "" {
		return "", fmt.Errorf("core reported no version")
	}
	return v, nil
}

// processSession is one running aether.exe child.
type processSession struct {
	cmd    *exec.Cmd
	events chan CoreEvent
	done   chan struct{}
	tap    func(CoreEvent) // manager log sink (may be nil); sees events without owning the channel
	once   sync.Once
}

// SetTap wires the manager's log sink so it mirrors events without competing
// for the Events() channel (which has exactly one consumer: the owner).
func (s *processSession) SetTap(fn func(CoreEvent)) { s.tap = fn }

func (s *processSession) Stop() error {
	var err error
	s.once.Do(func() {
		if s.cmd != nil && s.cmd.Process != nil {
			err = s.cmd.Process.Kill()
		}
	})
	return err
}

func (s *processSession) Events() <-chan CoreEvent { return s.events }

func (s *processSession) Done() <-chan struct{} { return s.done }

// Start spawns the core with the given environment.
func (b *ProcessBackend) Start(env map[string]string, workDir string) (Session, error) {
	if workDir == "" {
		workDir, _ = os.UserConfigDir()
	}
	_ = os.MkdirAll(workDir, 0o755)

	// The path may be relative (from an earlier Detect in another cwd).
	corePath := os.Getenv("AETHER_CORE")
	if corePath == "" {
		if found, err := b.Locate(""); err == nil {
			corePath = found
		} else {
			return nil, err
		}
	}

	cmd := exec.Command(corePath)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), envSlice(env)...)
	// No console window flash when the GUI (windowsgui subsystem) spawns the
	// console-mode core: CREATE_NO_WINDOW keeps aether.exe fully detached.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("core start: %w", err)
	}
	// Tie the core to the GUI: if the GUI dies, Windows kills the core too
	// (so the SOCKS/HTTP ports are never left occupied by an orphan).
	assignToJob(cmd.Process)

	s := &processSession{cmd: cmd, events: make(chan CoreEvent, 128), done: make(chan struct{})}
	pump := func(r io.ReadCloser) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
		for sc.Scan() {
			line := sc.Text()
			emit(s, "log", line, nil)
			if kind, ok := classify(line); ok {
				emit(s, kind, line, nil)
			}
		}
	}
	go pump(stdout)
	go pump(stderr)
	go func() {
		_ = cmd.Wait()
		close(s.events) // closes Events() after the last buffered event is read
		close(s.done)
	}()
	return s, nil
}

func emit(s *processSession, kind, line string, err error) {
	ev := CoreEvent{Kind: kind, Line: line, Err: err, When: time.Now()}
	if s.tap != nil {
		s.tap(ev)
	}
	select {
	case s.events <- ev:
	default: // drop on overflow: the GUI must never stall the core
	}
}

func envSlice(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

// classify turns one core log line into an event kind. Patterns match the
// observed aether 2.0.0 env_logger format.
var classifyReIdentity = regexp.MustCompile("identity ready")
var classifyReConnected = regexp.MustCompile("socks5 server listening|tunnel validated|" + regexp.QuoteMeta("[+] connected") + "|serving")
var classifyReScan = regexp.MustCompile("hunting for a working|scan mode=")
var classifyReCandidate = regexp.MustCompile("candidate ok")
var classifyReReconnect = regexp.MustCompile("reconnect|retry")

// Aether reports fatal startup failures on stderr as either "[-] ..." or
// "Error: Other(...)".  The latter includes bind failures (for example a
// stale client already owning the SOCKS port) and must never be mistaken for
// a successful connection.
var classifyReFail = regexp.MustCompile(`(?i)(?:\[-\].*)?(failed|error|exhausted|deadline reached|cannot use)`)

func classify(line string) (kind string, ok bool) {
	t := strings.TrimSpace(line)
	switch {
	case classifyReFail.MatchString(t):
		return "failed", true
	case classifyReIdentity.MatchString(t):
		return "identity", true
	case classifyReConnected.MatchString(t):
		return "connected", true
	case classifyReCandidate.MatchString(t):
		return "candidate", true
	case classifyReScan.MatchString(t):
		return "scanning", true
	case classifyReReconnect.MatchString(t):
		return "reconnect", true
	}
	return "", false
}
