//go:build wgtun

package wgtun

import (
	"time"

	"github.com/aethergui/aethergui/internal/logx"
)

// phaseTimer is the monotonic stage clock for ONE native connect session. Every
// stage reports time.Since(t0), so elapsed_ms is cumulative from
// native_connect_start. It is the observable seam the cold-connect A/B
// (P0/P1/P2) is measured through: it changes no behaviour, no timeout, no
// routing — it only prints timestamps.
//
// time.Now() carries a monotonic reading, so time.Since(t0) is wall-clock
// independent (immune to NTP/clock adjustments) exactly as a connect-latency
// measurement must be.
type phaseTimer struct {
	kind string
	t0   time.Time
}

// newPhaseTimer starts the clock and emits native_connect_start.
func newPhaseTimer(kind string) phaseTimer {
	t := phaseTimer{kind: kind, t0: time.Now()}
	t.mark("native_connect_start")
	return t
}

// mark emits one stage timestamp. name is the stage label; elapsed_ms is the
// cumulative elapsed time since native_connect_start.
func (t phaseTimer) mark(name string) {
	logx.Infof("[native] kind=%s phase=%s elapsed_ms=%d", t.kind, name, time.Since(t.t0).Milliseconds())
}

// nativeKind names the transport for the phase logs: "awg" when the AmneziaWG
// obfuscation is on (junk or fake first packet), "wg" for the plain baseline.
// It exists only to make the A/B logs self-describing; it reads no secret.
func nativeKind(cfg Config) string {
	if cfg.JunkCount > 0 || len(cfg.JunkI1) > 0 {
		return "awg"
	}
	return "wg"
}
