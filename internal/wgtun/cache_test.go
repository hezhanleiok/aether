//go:build wgtun

package wgtun

import "testing"

func TestEndpointCacheOrder(t *testing.T) {
	var c endpointCache
	c.recordSuccess("a:4500", 120)
	c.recordSuccess("b:4500", 45)
	c.recordSuccess("c:4500", 80)

	got := c.orderedAddrs()
	want := []string{"b:4500", "c:4500", "a:4500"} // fastest first
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestEndpointCacheEviction(t *testing.T) {
	var c endpointCache
	c.recordSuccess("a:4500", 100)
	c.recordFailure("a:4500")
	c.recordFailure("a:4500")
	if len(c.Endpoints) != 1 {
		t.Fatalf("evicted too early after 2 failures: %d", len(c.Endpoints))
	}
	c.recordFailure("a:4500")
	if len(c.Endpoints) != 0 {
		t.Fatalf("not evicted after 3 failures: %d", len(c.Endpoints))
	}
}

func TestEndpointCacheSuccessResetsFail(t *testing.T) {
	var c endpointCache
	c.recordSuccess("a:4500", 100)
	c.recordFailure("a:4500")
	c.recordFailure("a:4500")
	c.recordSuccess("a:4500", 90) // success resets the failure streak
	c.recordFailure("a:4500")
	if len(c.Endpoints) != 1 {
		t.Fatalf("evicted despite a successful reset: %d", len(c.Endpoints))
	}
	if c.Endpoints[0].FailCount != 1 {
		t.Fatalf("fail count = %d, want 1", c.Endpoints[0].FailCount)
	}
}
