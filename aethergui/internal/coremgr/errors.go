package coremgr

import "errors"

var (
	// ErrNotReady is returned when Start is called before a good Detect.
	ErrNotReady = errors.New("core not ready: run Detect first")
	// ErrAlreadyRunning is returned on double Start.
	ErrAlreadyRunning = errors.New("core session already running")
	// ErrCoreMissing is returned when the configured core path does not exist.
	ErrCoreMissing = errors.New("core binary not found")
)
