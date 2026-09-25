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
	coreJob     windows.Handle
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
// searchDirs lists the local places to look for the core, in order.
//
// The exe's own directory comes first and includes core-bin/: that is where
// the build puts the core, so the client has to find it no matter which
// directory it was launched from (shortcut, command line, scheduled task).
// The working directory is only a fallback.
func searchDirs() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		dirs = append(dirs, exeDir, filepath.Join(exeDir, "core-bin"))
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
		// Psiphon spawns psiphon-tunnel-core.exe, which outlives the core and
		// keeps holding the SOCKS port — the next connect then fails with
		// "port already in use". Nothing else on this machine starts it.
		kill := exec.Command("taskkill", "/F", "/IM", "psiphon-tunnel-core.exe")
		kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if out, kerr := kill.CombinedOutput(); kerr != nil {
			if !strings.Contains(strings.ToLower(string(out)), "not found") {
				logx.Warnf("[coremgr] psiphon cleanup: %v", kerr)
			}
		}
	})
	return err
}

func (s *processSession) Events() <-chan CoreEvent { return s.events }

func (s *processSession) Done() <-chan struct{} { return s.done }

// Start spawns the core with the given environment and no extra arguments.
func (b *ProcessBackend) Start(env map[string]string, workDir string) (Session, error) {
	return b.StartWithArgs(env, nil, workDir)
}

// StartWithArgs spawns the core with both an AETHER_* environment and real
// command line arguments.
//
// Env-only was not enough for Psiphon: the core exposes it purely as flags
// (--psiphon, --psiphon-region CC, --psiphon-mode cdn). Settings still travel
// through the environment; only the mode switch goes on the command line.
func (b *ProcessBackend) StartWithArgs(env map[string]string, args []string, workDir string) (Session, error) {
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

	cmd := exec.Command(corePath, args...)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), envSlice(env)...)
	if len(args) > 0 {
		logx.Infof("[coremgr] starting core with args: %v", args)
	}
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
var classifyReReconnect = regexp.MustCompile("reconnecting|retrying|rescanning")

// H2/MIM transport progress lines. Without these the UI log looks frozen
// during the (long) MASQUE scan + fragmented TLS handshake.
var classifyReProgress = regexp.MustCompile("fragmenting client hello|tls established|selected MASQUE gateway|best MASQUE gateway|MASQUE transport:|\\[h2\\] connecting|outer tunnel validated|inner tunnel validated")

// Psiphon churns through candidate servers: one server's tunnel dying is how
// it reconnects, not the session failing. Those lines must not flip the UI to
// "failed" while psiphon is still up and serving 1819.
var classifyRePsiphonReady = regexp.MustCompile("psiphon is ready|psiphon exit:")
// Psiphon publishes the countries its servers can actually leave from. The
// client's own list is only a convenience: this is the authoritative one.
var classifyRePsiphonRegions = regexp.MustCompile(`psiphon can leave from:\s*([A-Z ,]+)`)

// EgressRegions parses one "psiphon can leave from: DE GB US" line.
func EgressRegions(line string) []string {
	m := classifyRePsiphonRegions.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	var out []string
	for _, f := range strings.Fields(m[1]) {
		out = append(out, strings.Trim(f, ","))
	}
	return out
}
// Psiphon is noisy by nature: it rotates servers, retries meek, and logs an
// accept error whenever a client drops a connection early. None of that means
// the session is down — "psiphon is ready" and the exit line are the only
// signals that matter, so the rest is ignored instead of failing the UI.
var classifyRePsiphonNoise = regexp.MustCompile(`(?i)psiphon.*(meek round trip failed|SOCKS proxy accept error|AcceptSocks|tunnel failed|DoStatusRequest failed|operate tunnel error|close tunnel|connection attempt failed|Config migration|boltdb)`)

// Aether reports fatal startup failures on stderr as either "[-] ..." or
// "Error: Other(...)".  The latter includes bind failures (for example a
// stale client already owning the SOCKS port) and must never be mistaken for
// a successful connection.
var classifyReFail = regexp.MustCompile(`(?i)(?:\[-\].*)?(failed|error|exhausted|deadline reached|cannot use|no usable)`)

func classify(line string) (kind string, ok bool) {
	t := strings.TrimSpace(line)
	switch {
	case classifyReIdentity.MatchString(t):
		return "identity", true
	// Psiphon announces itself differently: there is no tunnel underneath, so
	// "psiphon is ready" is the equivalent of the socks listener coming up.
	case classifyRePsiphonReady.MatchString(t):
		return "connected", true
	case classifyReConnected.MatchString(t):
		return "connected", true
	case classifyReCandidate.MatchString(t):
		return "candidate", true
	case classifyReScan.MatchString(t):
		return "scanning", true
	// H2/MIM transport progress (fragmented handshake, gateway selection).
	// Checked before the failure pattern: "[h2] connecting ... failed" lines
	// are transient retries the core recovers from, not a final failure.
	case classifyReProgress.MatchString(t):
		return "progress", true
	// The core keeps retrying on these lines ("tunnel ended ... reconnecting",
	// "blacklisting and rescanning"); they must surface as a reconnect, not as
	// a final failure — otherwise the UI flips to "failed" while the tunnel
	// is still recovering on its own.
	case classifyReReconnect.MatchString(t):
		return "reconnect", true
	// Psiphon housekeeping (server rotation, meek retries, accept errors):
	// ignore it entirely rather than letting it fail or churn the UI.
	case classifyRePsiphonNoise.MatchString(t):
		return "", false
	case classifyRePsiphonRegions.MatchString(t):
		return "psiphon_regions", true
	case classifyReFail.MatchString(t):
		return "failed", true
	}
	return "", false
}
