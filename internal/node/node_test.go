package node

import (
	"testing"
)

func TestSeedPopulatesRanges(t *testing.T) {
	p := NewPool()
	p.Seed()
	list := p.List()
	if len(list) == 0 {
		t.Fatal("seed produced no nodes")
	}
	for _, n := range list {
		if n.IP == "" || n.Port == 0 {
			t.Errorf("node missing ip/port: %+v", n)
		}
		if n.Status != StAvailable {
			t.Errorf("fresh node status = %s", n.Status)
		}
	}
}

func TestLatencyQualityBuckets(t *testing.T) {
	cases := map[int64]Quality{
		20:  QExcellent,
		86:  QExcellent,
		100: QExcellent,
		101: QGood,
		173: QGood,
		200: QGood,
		201: QMedium,
		400: QMedium,
		401: QPoor,
		900: QPoor,
	}
	for ms, want := range cases {
		if got := LatencyQuality(ms); got != want {
			t.Errorf("LatencyQuality(%d) = %s, want %s", ms, got, want)
		}
	}
}

func TestUpdateLatencyAndSort(t *testing.T) {
	p := NewPool()
	p.Seed()
	nodes := p.List()
	if len(nodes) < 2 {
		t.Skip("need at least two seeded nodes")
	}
	p.UpdateLatency(nodes[0].ID, 300, 300)
	p.UpdateLatency(nodes[1].ID, 50, 50)
	p.SortByLatency()
	sorted := p.List()
	if sorted[0].ID != nodes[1].ID {
		t.Errorf("first after sort = %s, want %s", sorted[0].ID, nodes[1].ID)
	}
	p.UpdateLatency(nodes[0].ID, 0, 0)
	if n, _ := p.Get(nodes[0].ID); n.Status != StUnavailable {
		t.Errorf("zero latency should mark unavailable, got %s", n.Status)
	}
}

func TestMarkConnected(t *testing.T) {
	p := NewPool()
	p.Seed()
	nodes := p.List()
	p.MarkConnected(nodes[0].ID)
	n, _ := p.Get(nodes[0].ID)
	if n.Status != StConnected {
		t.Errorf("status = %s, want Connected", n.Status)
	}
	p.MarkConnected(nodes[1].ID)
	if n, _ := p.Get(nodes[0].ID); n.Status == StConnected {
		t.Error("previous node must lose connected state")
	}
}

func TestFlagFromCode(t *testing.T) {
	if got := FlagFromCode("JP"); got != "🇯🇵" {
		t.Errorf("JP flag = %q", got)
	}
	if got := FlagFromCode("us"); got != "🇺🇸" {
		t.Errorf("us flag = %q", got)
	}
	if got := FlagFromCode("xxx"); got != "🌐" {
		t.Errorf("bad code flag = %q", got)
	}
}
