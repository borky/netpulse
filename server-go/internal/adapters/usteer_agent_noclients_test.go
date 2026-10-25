package adapters

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gnacho/netpulse/agent/probe"
)

// An AP with nobody attached must still encode its clients as [], as the
// SSH path does: the Roaming page iterates ap.clients without a guard, and a
// null there throws during render and leaves the whole page blank.
func TestUsteerAPsFromPayloadEmptyAPEncodesClientsAsArray(t *testing.T) {
	p := &probe.Payload{
		Router: "rt-test",
		Data: probe.PayloadData{
			Usteer: &probe.UsteerData{
				SSIDs: map[string]probe.UsteerSSID{
					"test-ssid": {
						APs: []probe.UsteerAP{
							{BSSID: "02:00:00:00:00:01", Freq: 2412, Local: true},
							{BSSID: "02:00:00:00:00:02", Freq: 5180, Clients: 1, Local: true},
						},
						Clients: map[string]probe.UsteerClient{
							"02:00:00:00:10:01": {Signal: -60},
						},
					},
				},
			},
			Wireless: &probe.WirelessData{
				Clients: map[string]probe.WirelessClient{
					"02:00:00:00:10:01": {SignalDbm: -58, Band: "5 GHz"},
				},
			},
		},
	}
	aps, _ := usteerAPsFromPayload("rt-test", p)
	if len(aps) != 2 {
		t.Fatalf("expected 2 APs, got %d", len(aps))
	}
	if len(aps[1].Clients) != 1 {
		t.Fatalf("the 5 GHz AP should keep its client, got %+v", aps[1].Clients)
	}
	b, err := json.Marshal(Usteer{APs: aps, Mesh: []UsteerMesh{}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"clients":null`) {
		t.Fatalf("an AP without clients encoded clients as null: %s", b)
	}
}
