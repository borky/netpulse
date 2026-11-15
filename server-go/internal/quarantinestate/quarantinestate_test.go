package quarantinestate

import (
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestStore(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := New()
	s.now = func() time.Time { return now }
	s.Update("b", &probe.QuarantineInfo{Enabled: true, Devices: []probe.QuarantineDevice{
		{MAC: "02:00:00:00:00:01", State: "approved"},
		{MAC: "02:00:00:00:00:02", State: "approved", Report: "bogus"},
		{MAC: "not-a-mac", State: "waiting"},
		{MAC: "02:00:00:00:00:03", State: "unknown"},
	}})
	s.Update("a", &probe.QuarantineInfo{Enabled: true, Devices: []probe.QuarantineDevice{
		{MAC: "02-00-00-00-00-01", State: "waiting"},
	}})
	if st, ok := s.Lookup("02:00:00:00:00:01"); !ok || st.State != "waiting" || st.Router != "a" {
		t.Fatalf("the more pressing answer wins: %+v", st)
	}
	if st, ok := s.Lookup("02:00:00:00:00:02"); !ok || st.Report != "" {
		t.Fatalf("an unknown report value: %+v", st)
	}
	if _, ok := s.Lookup("02:00:00:00:00:03"); ok {
		t.Fatal("an unknown state was kept")
	}
	if !s.Listed("b", "02:00:00:00:00:02") || s.Listed("a", "02:00:00:00:00:02") || s.Listed("c", "02:00:00:00:00:02") {
		t.Fatal("Listed answers for another router")
	}
	if snap := s.Snapshot(); len(snap) != 2 || snap[0] != (Entry{MAC: "02:00:00:00:00:01", Router: "a", State: "waiting"}) || snap[1].MAC != "02:00:00:00:00:02" {
		t.Fatalf("snapshot: %+v", snap)
	}
	now = now.Add(maxAge + time.Second)
	if len(s.Snapshot()) != 0 {
		t.Fatal("a stale report is in the snapshot")
	}
	if _, ok := s.Lookup("02:00:00:00:00:01"); ok || s.Listed("b", "02:00:00:00:00:01") {
		t.Fatal("a stale report is still shown")
	}
	var nilStore *Store
	nilStore.Update("a", &probe.QuarantineInfo{Enabled: true})
	if _, ok := nilStore.Lookup("02:00:00:00:00:01"); ok {
		t.Fatal("nil store")
	}
}
