//go:build windows

package vpn

import (
	"os/exec"
	"strings"
	"syscall"

	"github.com/aethergui/aethergui/internal/logx"
)

// killOrphanPsiphon terminates psiphon-tunnel-core processes that outlived the
// session which started them.
//
// Why this is needed: the core spawns psiphon-tunnel-core, but a teardown that
// stops and restarts the core (a protocol switch, a reconnect) can leave the
// child behind. The orphan keeps its BoltDB datastore locked and its listeners
// bound, so the next chained connect cannot open the datastore at all:
//
//	psiphon: tryDatastoreOpenDB failed: psiphon.tryDatastoreOpenDB#167: timeout
//	psiphon: error in init: ... psiphon.openDataStore#169 ... timeout
//	psiphon: other: psiphon stopped before it was ready
//
// That is what made every protocol fail after the first successful chained
// connect - and made switching back to the protocol that had just worked fail
// too, because the cause is the leftover process, not the transport.
func killOrphanPsiphon() {
	taskkill, err := exec.LookPath("taskkill")
	if err != nil {
		return
	}
	cmd := exec.Command(taskkill, "/F", "/T", "/IM", "psiphon-tunnel-core.exe")
	// Without this the helper flashes a console window on every connect,
	// disconnect and protocol switch - taskkill is a console program.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	if err != nil {
		// taskkill exits non-zero when there is nothing to kill (128 on a
		// Chinese locale, whose "no such process" message is not the English
		// "not found"); that is the normal case and must stay silent.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 128 {
			return
		}
		if strings.Contains(strings.ToLower(string(out)), "not found") {
			return
		}
		logx.Warnf("[vpn] reaping a leftover psiphon process: %v", err)
		return
	}
	logx.Infof("[vpn] reaped a leftover psiphon process (it was holding the datastore)")
}
