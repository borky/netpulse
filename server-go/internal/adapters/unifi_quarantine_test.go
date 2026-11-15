package adapters

import (
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/unifi"
)

// Only listed devices, from a recent read; the AP's model with it.
func TestQuarantineStations(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	inv := &unifiInventory{
		devices: map[string]unifi.Device{"02:00:00:00:00:A1": {MAC: "02:00:00:00:00:A1", Model: "U7 Pro‮!"}},
		stations: map[string]unifi.Station{
			"02:00:00:00:00:01": {MAC: "02:00:00:00:00:01", APMAC: "02:00:00:00:00:A1", Band: "5g", Proto: "ax", NSS: 2},
			"02:00:00:00:00:02": {MAC: "02:00:00:00:00:02", Wired: true},
			"02:00:00:00:00:03": {MAC: "02:00:00:00:00:03", Wired: true},
		},
	}
	macs := []string{"02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:02", "02:00:00:00:00:09"}
	got := quarantineStations(&unifiRead{inv: inv, at: now}, now, macs)
	if len(got) != 2 {
		t.Fatalf("stations: %+v", got)
	}
	if g := got[0]; g.MAC != "02:00:00:00:00:01" || g.APModel != "U7Pro" || g.Band != "5g" || g.Proto != "ax" || g.NSS != 2 || g.Wired {
		t.Fatalf("Wi-Fi: %+v", g)
	}
	if g := got[1]; !g.Wired || g.APModel != "" {
		t.Fatalf("wired: %+v", g)
	}
	if got := quarantineStations(&unifiRead{inv: inv, at: now}, now, nil); got == nil || len(got) != 0 {
		t.Fatalf("a recent read with nothing to tell is an empty list: %v", got)
	}
	if quarantineStations(&unifiRead{inv: inv, at: now.Add(-quarantineStationsMaxAge - time.Second)}, now, macs) != nil {
		t.Fatal("an old read was used")
	}
	if quarantineStations(nil, now, macs) != nil {
		t.Fatal("no read")
	}
}
