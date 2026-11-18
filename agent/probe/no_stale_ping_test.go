package probe

import (
	"context"
	"testing"
)

// TestNoStalePingSkipsTheRound: with NoStalePing the agent sends no ping and
// reads the ARP table as it is (the embedder keeps its neighbours fresh).
func TestNoStalePingSkipsTheRound(t *testing.T) {
	stale := `192.0.2.10 dev br-lan lladdr 02:00:00:00:00:01 STALE
192.0.2.11 dev br-lan lladdr 02:00:00:00:00:02 STALE
`
	run := &staleArpRunner{neigh: []string{stale, stale}}
	p := NewProber(run, Options{NoStalePing: true})

	_, st, _ := p.probeArp(context.Background())

	if got := run.pinged(); len(got) != 0 {
		t.Fatalf("pinged %v with NoStalePing", got)
	}
	if len(st) != 2 {
		t.Fatalf("stale set changed: %v", st)
	}
}
