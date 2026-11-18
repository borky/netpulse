package httpapi

import (
	"strings"
	"testing"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestNamesForRouterOnlyItsOwnMACs(t *testing.T) {
	p := &probe.Payload{Data: probe.PayloadData{
		Wireless: &probe.WirelessData{Clients: map[string]probe.WirelessClient{"02:00:00:00:00:01": {}}},
		DHCP:     &probe.DHCPData{Leases: []probe.DhcpLease{{MAC: "02:00:00:00:00:02"}}},
		FDB:      &probe.FDBData{MACs: map[string]string{"02:00:00:00:00:03": "lan2"}},
		Arp:      map[string]string{"02:00:00:00:00:04": "192.0.2.4"},
	}}
	all := map[string]string{
		"02:00:00:00:00:01": "Phone", "02:00:00:00:00:02": "Laptop",
		"02:00:00:00:00:03": "NAS", "02:00:00:00:00:04": "Printer",
		"02:00:00:00:00:99": "Another site's TV",
	}
	got := namesForRouter(all, routerMACs(p))
	if len(got) != 4 || got["02:00:00:00:00:99"] != "" || got["02:00:00:00:00:03"] != "NAS" {
		t.Fatalf("names = %v", got)
	}
	// A light push (no MAC sections) or no names known: nothing to send.
	if namesForRouter(all, routerMACs(&probe.Payload{})) != nil || namesForRouter(nil, routerMACs(p)) != nil {
		t.Fatal("names sent with nothing to match")
	}
}

func TestNamesForRouterIsBounded(t *testing.T) {
	all, macs := map[string]string{}, map[string]bool{}
	for i := 0; i < 4096; i++ {
		mac := strings.ToLower(probeMAC(i))
		all[mac] = strings.Repeat("n", 63*4/4) // long names
		macs[mac] = true
	}
	got := namesForRouter(all, macs)
	size := 0
	for m, n := range got {
		size += len(m) + len(n) + 6
	}
	if size > deviceNamesReplyMax || len(got) == 0 {
		t.Fatalf("%d names, %d bytes", len(got), size)
	}
}

func probeMAC(i int) string {
	const hex = "0123456789abcdef"
	b := []byte("02:00:00:00:00:00")
	b[12], b[13] = hex[(i>>12)&15], hex[(i>>8)&15]
	b[15], b[16] = hex[(i>>4)&15], hex[i&15]
	return string(b)
}
