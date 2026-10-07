//go:build wgtun

package wgtun

import (
	"os"
	"testing"
	"time"
)

// writeRawCache writes raw JSON bytes directly to the cache file, bypassing
// save(), to simulate a cache written by an older build.
func writeRawCache(t *testing.T, raw string) {
	t.Helper()
	if err := os.WriteFile(cacheFilePath(), []byte(raw), 0o600); err != nil {
		t.Fatalf("write raw cache: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Schema (v1 -> v2)
// ---------------------------------------------------------------------------

// TestLoadLegacyCacheV1 pins that a version-1 cache (no quality fields) loads
// losslessly: legacy fields survive, and the new fields decode to zero values
// (never forged).
func TestLoadLegacyCacheV1(t *testing.T) {
	defer saveStateDir(t)()

	writeRawCache(t, `{
	  "version": 1,
	  "endpoints": [
	    {"addr": "162.159.195.93:3854", "lastRttMs": 12, "successCount": 3, "failCount": 0, "lastUsed": "2026-10-06T10:00:00Z", "attempts": 4}
	  ],
	  "lastPruned": "2026-10-05T10:00:00Z",
	  "lastGood": "162.159.195.93:3854",
	  "lastGoodAt": "2026-10-06T09:00:00Z"
	}`)

	c := loadCache()
	if len(c.Endpoints) != 1 {
		t.Fatalf("endpoints = %d, want 1", len(c.Endpoints))
	}
	e := c.Endpoints[0]
	if e.Addr != "162.159.195.93:3854" || e.SuccessCount != 3 || e.Attempts != 4 || e.FailCount != 0 || e.LastRttMs != 12 {
		t.Fatalf("legacy fields not preserved: %+v", e)
	}
	if !e.FirstSeen.IsZero() || e.LastHandshakeMs != 0 || e.DataPlaneSuccess != 0 ||
		e.DataPlaneFail != 0 || e.ConsecDPFail != 0 || e.LastSpeedMbps != 0 ||
		!e.LastDataPlaneOK.IsZero() || !e.LastSeen.IsZero() {
		t.Fatalf("quality fields forged from legacy cache: %+v", e)
	}
}

// TestEndpointQualityRoundTrip pins that quality fields survive save -> load and
// the file is written with version 2.
func TestEndpointQualityRoundTrip(t *testing.T) {
	defer saveStateDir(t)()

	now := time.Now()
	c := loadCache()
	c.Endpoints = []endpointEntry{{
		Addr: "a:1", FirstSeen: now, LastHandshakeMs: 400,
		DataPlaneSuccess: 5, DataPlaneFail: 1, ConsecDPFail: 0,
		LastSpeedMbps: 42.5, LastDataPlaneOK: now, LastSeen: now,
	}}
	c.save()

	got := loadCache()
	if got.Version != cacheFileVersion {
		t.Fatalf("version = %d, want %d", got.Version, cacheFileVersion)
	}
	e := got.Endpoints[0]
	if e.LastHandshakeMs != 400 || e.DataPlaneSuccess != 5 || e.DataPlaneFail != 1 ||
		e.ConsecDPFail != 0 || e.LastSpeedMbps != 42.5 {
		t.Fatalf("quality fields lost in round trip: %+v", e)
	}
	if !e.FirstSeen.Equal(now) || !e.LastDataPlaneOK.Equal(now) || !e.LastSeen.Equal(now) {
		t.Fatalf("timestamps lost in round trip: %+v", e)
	}
}

// TestLegacyCachePreservesLastGood pins that LastGood / LastGoodAt survive a v1
// decode (the P4.2 absolute-first anchor must never be dropped by the upgrade).
func TestLegacyCachePreservesLastGood(t *testing.T) {
	defer saveStateDir(t)()

	writeRawCache(t, `{"version":1,"endpoints":[{"addr":"a:1","successCount":1,"attempts":1}],"lastGood":"a:1","lastGoodAt":"2026-10-06T09:00:00Z"}`)
	c := loadCache()
	if c.LastGood != "a:1" {
		t.Fatalf("LastGood = %q, want a:1", c.LastGood)
	}
	if c.LastGoodAt.IsZero() {
		t.Fatal("LastGoodAt lost")
	}
}

// TestLegacyCacheDoesNotForgeQuality pins that a v1 cache produces no
// synthesized quality data after decode.
func TestLegacyCacheDoesNotForgeQuality(t *testing.T) {
	defer saveStateDir(t)()

	writeRawCache(t, `{"version":1,"endpoints":[{"addr":"a:1","successCount":5,"attempts":5}]}`)
	e := loadCache().Endpoints[0]
	if e.DataPlaneSuccess != 0 || e.LastSpeedMbps != 0 || e.LastHandshakeMs != 0 {
		t.Fatalf("quality forged from legacy cache: %+v", e)
	}
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

// TestRecordHandshakeSuccess pins that a successful handshake records the real
// elapsed and advances LastSeen.
func TestRecordHandshakeSuccess(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1"}}}
	c.recordHandshake("a:1", 400, true)
	e := c.Endpoints[0]
	if e.LastHandshakeMs != 400 {
		t.Fatalf("LastHandshakeMs = %d, want 400", e.LastHandshakeMs)
	}
	if e.LastSeen.IsZero() {
		t.Fatal("LastSeen not advanced")
	}
}

// TestRecordHandshakeFailure pins that a failed handshake advances LastSeen but
// does NOT write a bogus latency (a timeout is not a latency measurement).
func TestRecordHandshakeFailure(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1", LastHandshakeMs: 99}}}
	c.recordHandshake("a:1", 0, false)
	e := c.Endpoints[0]
	if e.LastHandshakeMs != 99 {
		t.Fatalf("LastHandshakeMs = %d, want 99 (unchanged on failure)", e.LastHandshakeMs)
	}
	if e.LastSeen.IsZero() {
		t.Fatal("LastSeen not advanced")
	}
}

// TestRecordHandshakePreservesSuccessRate pins that recordHandshake does NOT
// touch SuccessCount/Attempts — those stay recordAttempt's responsibility, so
// the two functions never double-count a success.
func TestRecordHandshakePreservesSuccessRate(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1", Attempts: 3, SuccessCount: 2}}}
	c.recordHandshake("a:1", 400, true)
	e := c.Endpoints[0]
	if e.Attempts != 3 || e.SuccessCount != 2 {
		t.Fatalf("recordHandshake mutated successRate: %+v", e)
	}
}

// TestRecordHandshakeRealLatency pins that recordHandshake writes the handshake
// elapsed into LastHandshakeMs, never into LastRttMs (which is the liveness RTT,
// a different measurement).
func TestRecordHandshakeRealLatency(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1", LastRttMs: 12}}}
	c.recordHandshake("a:1", 400, true)
	e := c.Endpoints[0]
	if e.LastHandshakeMs != 400 {
		t.Fatalf("LastHandshakeMs = %d, want 400", e.LastHandshakeMs)
	}
	if e.LastRttMs != 12 {
		t.Fatalf("LastRttMs = %d, want 12 (must not be clobbered by handshake elapsed)", e.LastRttMs)
	}
}

// ---------------------------------------------------------------------------
// Data plane
// ---------------------------------------------------------------------------

// TestRecordDataPlaneSuccess pins the success path.
func TestRecordDataPlaneSuccess(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1", ConsecDPFail: 3}}}
	c.recordDataPlane("a:1", true)
	e := c.Endpoints[0]
	if e.DataPlaneSuccess != 1 || e.ConsecDPFail != 0 {
		t.Fatalf("success not recorded: %+v", e)
	}
	if e.LastDataPlaneOK.IsZero() || e.LastSeen.IsZero() {
		t.Fatalf("timestamps not advanced: %+v", e)
	}
}

// TestRecordDataPlaneFailure pins the failure path.
func TestRecordDataPlaneFailure(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1"}}}
	c.recordDataPlane("a:1", false)
	e := c.Endpoints[0]
	if e.DataPlaneFail != 1 || e.ConsecDPFail != 1 {
		t.Fatalf("failure not recorded: %+v", e)
	}
	if e.LastSeen.IsZero() {
		t.Fatal("LastSeen not advanced")
	}
}

// TestRecordDataPlaneConsecutiveFailures pins the streak: failures accumulate,
// a success resets it.
func TestRecordDataPlaneConsecutiveFailures(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1"}}}
	c.recordDataPlane("a:1", false)
	c.recordDataPlane("a:1", false)
	c.recordDataPlane("a:1", false)
	if e := c.Endpoints[0]; e.ConsecDPFail != 3 || e.DataPlaneFail != 3 {
		t.Fatalf("streak = %+v, want ConsecDPFail=3 DataPlaneFail=3", e)
	}
	c.recordDataPlane("a:1", true)
	if e := c.Endpoints[0]; e.ConsecDPFail != 0 || e.DataPlaneSuccess != 1 {
		t.Fatalf("streak not reset: %+v", e)
	}
}

// TestRecordDataPlaneDoesNotEvict pins that data-plane failures never evict —
// the entry stays even after many failures (only the failover path may evict).
func TestRecordDataPlaneDoesNotEvict(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1"}}}
	for i := 0; i < 10; i++ {
		c.recordDataPlane("a:1", false)
	}
	if len(c.Endpoints) != 1 {
		t.Fatalf("endpoint evicted by data-plane failures: %d entries", len(c.Endpoints))
	}
}

// TestDataPlaneRetryCountsOnce documents the P5.1 contract: recordDataPlane is
// called ONCE per connect with the FINAL outcome — the 300ms retry attempts
// inside the settle window must never each bump DataPlaneFail. A single call is
// a single increment, so the caller's single-call-per-connect is what keeps
// ConsecDPFail from being inflated by WSAENETUNREACH transients.
func TestDataPlaneRetryCountsOnce(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1"}}}
	c.recordDataPlane("a:1", false) // one final outcome, not N retries
	if e := c.Endpoints[0]; e.DataPlaneFail != 1 {
		t.Fatalf("DataPlaneFail = %d, want 1 (single outcome)", e.DataPlaneFail)
	}
}

// ---------------------------------------------------------------------------
// Speed
// ---------------------------------------------------------------------------

// TestRecordSpeed pins that a measured throughput lands in LastSpeedMbps and
// advances LastSeen, and never touches successRate accounting.
func TestRecordSpeed(t *testing.T) {
	c := &endpointCache{Endpoints: []endpointEntry{{Addr: "a:1", SuccessCount: 2, Attempts: 2}}}
	c.recordSpeed("a:1", 42.5)
	e := c.Endpoints[0]
	if e.LastSpeedMbps != 42.5 {
		t.Fatalf("LastSpeedMbps = %v, want 42.5", e.LastSpeedMbps)
	}
	if e.LastSeen.IsZero() {
		t.Fatal("LastSeen not advanced")
	}
	if e.SuccessCount != 2 || e.Attempts != 2 {
		t.Fatalf("recordSpeed forged successRate: %+v", e)
	}
}

// ---------------------------------------------------------------------------
// LastGood protection + P4.2 ordering regression
// ---------------------------------------------------------------------------

// TestQualityRecordsPreserveLastGood pins that none of the P5.1 collectors
// overwrite or clear LastGood / LastGoodAt.
func TestQualityRecordsPreserveLastGood(t *testing.T) {
	now := time.Now()
	c := &endpointCache{
		LastGood:   "a:1",
		LastGoodAt: now,
		Endpoints:  []endpointEntry{{Addr: "a:1"}},
	}
	c.recordHandshake("a:1", 100, true)
	c.recordDataPlane("a:1", true)
	c.recordSpeed("a:1", 50)
	if c.LastGood != "a:1" || !c.LastGoodAt.Equal(now) {
		t.Fatalf("LastGood changed: %q @ %v", c.LastGood, c.LastGoodAt)
	}
}

// TestLastGoodFirstStillWorksWithQuality pins that lastGoodFirst still promotes
// LastGood on top of a list that carries quality fields (P4.2 unchanged).
func TestLastGoodFirstStillWorksWithQuality(t *testing.T) {
	defer saveStateDir(t)()

	c := loadCache()
	c.LastGood = "b:1"
	c.Endpoints = []endpointEntry{
		{Addr: "a:1", Attempts: 2, SuccessCount: 2},
		{Addr: "b:1", Attempts: 10, SuccessCount: 1, LastSpeedMbps: 500},
	}
	c.save()

	ordered := orderHandshakeCandidates([]liveEndpoint{{Addr: "a:1"}, {Addr: "b:1"}})
	got := lastGoodFirst(ordered)
	if got[0].Addr != "b:1" || got[1].Addr != "a:1" {
		t.Fatalf("LastGood not absolute-first with quality fields: %v", addrs(got))
	}
}
