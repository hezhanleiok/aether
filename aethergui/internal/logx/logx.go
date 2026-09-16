// Package logx is a tiny leveled logger that keeps a bounded in-memory ring
// for the GUI log page and also mirrors to a file on disk.
package logx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

func (l Level) String() string {
	switch l {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	default:
		return "ERROR"
	}
}

// Entry is one line shown on the log page.
type Entry struct {
	When time.Time `json:"when"`
	Lvl  string    `json:"level"`
	Msg  string    `json:"msg"`
}

const maxEntries = 4000

var (
	mu      sync.Mutex
	entries []Entry
	minLvl  = Info
	file    *os.File
	onChange []func(Entry)
)

// Init sets the minimum level and opens the log file under the config dir.
func Init(level string, dir string) {
	mu.Lock()
	defer mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug", "trace":
		minLvl = Debug
	case "warn":
		minLvl = Warn
	case "error":
		minLvl = Error
	default:
		minLvl = Info
	}
	if dir != "" {
		_ = os.MkdirAll(dir, 0o755)
		p := filepath.Join(dir, "aethergui.log")
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			file = f
		}
	}
}

// FilePath returns the log file location ("" when file logging is off).
func FilePath() string {
	mu.Lock()
	defer mu.Unlock()
	if file == nil {
		return ""
	}
	return file.Name()
}

// Subscribe registers a callback fired on every new entry.
func Subscribe(fn func(Entry)) {
	mu.Lock()
	onChange = append(onChange, fn)
	subs := append([]func(Entry){}, onChange...)
	mu.Unlock()
	_ = subs
}

// SetLevel changes the minimum level at runtime.
func SetLevel(level string) {
	mu.Lock()
	defer mu.Unlock()
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug", "trace":
		minLvl = Debug
	case "warn":
		minLvl = Warn
	case "error":
		minLvl = Error
	default:
		minLvl = Info
	}
}

func log(l Level, format string, args ...any) {
	mu.Lock()
	e := Entry{When: time.Now(), Lvl: l.String(), Msg: fmt.Sprintf(format, args...)}
	entries = append(entries, e)
	if len(entries) > maxEntries {
		entries = entries[len(entries)-maxEntries:]
	}
	f := file
	lvl := minLvl
	_ = lvl
	var subs []func(Entry)
	if l >= minLvl {
		subs = append(subs, onChange...)
	}
	mu.Unlock()
	if f != nil {
		_, _ = f.WriteString(fmt.Sprintf("%s [%s] %s\n", e.When.Format(time.RFC3339), e.Lvl, e.Msg))
	}
	for _, fn := range subs {
		fn(e)
	}
}

func Debugf(format string, args ...any) { log(Debug, format, args...) }
func Infof(format string, args ...any)  { log(Info, format, args...) }
func Warnf(format string, args ...any)  { log(Warn, format, args...) }
func Errorf(format string, args ...any) { log(Error, format, args...) }

// Snapshot returns a copy of the retained entries.
func Snapshot() []Entry {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Entry, len(entries))
	copy(out, entries)
	return out
}

// Tail returns the latest n entries (for the GUI).
func Tail(n int) []Entry {
	mu.Lock()
	defer mu.Unlock()
	if n > len(entries) {
		n = len(entries)
	}
	out := make([]Entry, n)
	copy(out, entries[len(entries)-n:])
	return out
}

// Clear drops every retained entry.
func Clear() {
	mu.Lock()
	entries = nil
	mu.Unlock()
}
