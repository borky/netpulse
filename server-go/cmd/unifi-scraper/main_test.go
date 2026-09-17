package main

import "testing"

func cfgForTest() *Config {
	c := &Config{}
	c.IntervalSec = 300
	return c
}

func TestBuildPayloadSwitchMapsClientsToPorts(t *testing.T) {
	sw := unifiDevice{MAC: "02:00:00:00:00:10", Name: "Switch Rack", Type: "usw", Uptime: 3600}
	sw.Ports = []unifiPort{
		{Idx: 1, Name: "Uplink", Up: true, Speed: 1000, IsUplink: true},
		{Idx: 5, Name: "", Up: false, Speed: 0},
	}
	stas := []unifiSTA{
		{MAC: "02:00:00:00:00:01", IsWired: true, SwMAC: "02:00:00:00:00:10", SwPort: 5},
		// Wired on a different switch: not this device's client.
		{MAC: "02:00:00:00:00:02", IsWired: true, SwMAC: "02:00:00:00:00:99", SwPort: 3},
		// Wireless: belongs to an AP, never to the switch.
		{MAC: "02:00:00:00:00:03", ApMAC: "02:00:00:00:00:20", Radio: "na"},
	}
	p := buildPayload(cfgForTest(), sw, stas)

	if p.Router != "switch-rack" || p.Kind != "external" || p.Interval != 300 {
		t.Fatalf("envelope: %+v", p)
	}
	if p.Data.FDB == nil || len(p.Data.FDB.MACs) != 1 {
		t.Fatalf("fdb: %+v", p.Data.FDB)
	}
	if got := p.Data.FDB.MACs["02:00:00:00:00:01"]; got != "lan5" {
		t.Fatalf("client port = %q, want lan5", got)
	}
	if len(p.Data.FDB.Ports) != 2 {
		t.Fatalf("ports: %+v", p.Data.FDB.Ports)
	}
	// A port with no name still gets a readable label; speed only when up.
	if p.Data.FDB.Ports[0].Label != "Uplink" || p.Data.FDB.Ports[0].Speed != "1 Gbps" {
		t.Fatalf("port 1: %+v", p.Data.FDB.Ports[0])
	}
	if p.Data.FDB.Ports[1].Label != "Port 5" || p.Data.FDB.Ports[1].Speed != "" {
		t.Fatalf("port 5: %+v", p.Data.FDB.Ports[1])
	}
	// A switch has no wireless section.
	if p.Data.Wireless != nil {
		t.Fatalf("switch should send no wireless: %+v", p.Data.Wireless)
	}
}

func TestBuildPayloadAPMapsItsStations(t *testing.T) {
	ap := unifiDevice{MAC: "02:00:00:00:00:20", Name: "AP Living", Type: "uap", Uptime: 120}
	stas := []unifiSTA{
		{MAC: "02:00:00:00:00:03", ApMAC: "02:00:00:00:00:20", Radio: "na", Signal: -52, RxBytes: 10, TxBytes: 20},
		// Signal comes from rssi when the controller leaves signal at 0.
		{MAC: "02:00:00:00:00:04", ApMAC: "02:00:00:00:00:20", Radio: "ng", RSSI: -70},
		// Another AP's station, and a wired client: neither belongs here.
		{MAC: "02:00:00:00:00:05", ApMAC: "02:00:00:00:00:21", Radio: "ng"},
		{MAC: "02:00:00:00:00:06", IsWired: true, SwMAC: "02:00:00:00:00:10", SwPort: 2},
	}
	p := buildPayload(cfgForTest(), ap, stas)

	if p.Data.Wireless == nil || len(p.Data.Wireless.Clients) != 2 {
		t.Fatalf("clients: %+v", p.Data.Wireless)
	}
	c5 := p.Data.Wireless.Clients["02:00:00:00:00:03"]
	if c5.Band != "5 GHz" || c5.SignalDbm != -52 || c5.RxBytes != 10 {
		t.Fatalf("5 GHz client: %+v", c5)
	}
	if c24 := p.Data.Wireless.Clients["02:00:00:00:00:04"]; c24.Band != "2.4 GHz" || c24.SignalDbm != -70 {
		t.Fatalf("2.4 GHz client: %+v", c24)
	}
	if p.Data.FDB != nil {
		t.Fatalf("an AP sends no switch FDB: %+v", p.Data.FDB)
	}
}

func TestSlugForIsStableAndValid(t *testing.T) {
	// The server only accepts ^[a-z0-9][a-z0-9-]{0,63}$.
	cases := map[string]string{
		"Switch Rack":     "switch-rack",
		"AP  Living/Room": "ap--livingroom",
		"":                "unifi-020000000010",
	}
	for name, want := range cases {
		got := slugFor(unifiDevice{Name: name, MAC: "02:00:00:00:00:10"})
		if got != want {
			t.Errorf("slugFor(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestSpeedAndBandLabels(t *testing.T) {
	for mbps, want := range map[int]string{0: "—", -1: "—", 100: "100 Mbps", 1000: "1 Gbps", 2500: "2 Gbps"} {
		if got := speedLabel(mbps); got != want {
			t.Errorf("speedLabel(%d) = %q, want %q", mbps, got, want)
		}
	}
	for radio, want := range map[string]string{"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz", "": "2.4 GHz"} {
		if got := bandLabel(radio); got != want {
			t.Errorf("bandLabel(%q) = %q, want %q", radio, got, want)
		}
	}
}
