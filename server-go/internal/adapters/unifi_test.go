// unifi_test.go — the sealing rules, on made-up fixtures: what the
// controller knows must land on the map without touching what the inference
// or the user already decided.
package adapters

import (
	"testing"

	"github.com/gnacho/netpulse/server-go/internal/unifi"
)

func testInventory() *unifiInventory {
	return &unifiInventory{
		devices: map[string]unifi.Device{
			"02:00:00:00:00:10": {
				MAC: "02:00:00:00:00:10", IP: "192.0.2.10", Name: "Switch Rack", Kind: "switch",
				Ports: []unifi.Port{{Idx: 3, Name: "AP Living"}, {Idx: 5, Name: "Desk"}},
			},
			"02:00:00:00:00:20": {
				MAC: "02:00:00:00:00:20", IP: "192.0.2.20", Name: "AP Living", Kind: "ap",
				UplinkMAC: "02:00:00:00:00:10", UplinkPort: 3,
			},
		},
		clients: map[string]unifi.Client{
			"02:00:00:00:00:01": {MAC: "02:00:00:00:00:01", SwitchMAC: "02:00:00:00:00:10", SwitchPort: 5},
			"02:00:00:00:00:02": {MAC: "02:00:00:00:00:02", APMAC: "02:00:00:00:00:20", Band: "5 GHz", SignalDbm: -52},
			"02:00:00:00:00:99": {MAC: "02:00:00:00:00:99", SwitchMAC: "02:00:00:00:00:10", SwitchPort: 7},
		},
	}
}

func TestApplyUniFiInfraPlacesClientsAndChainsAPs(t *testing.T) {
	devices := []Device{
		{MAC: "02:00:00:00:00:01", Name: "desktop"},
		{MAC: "02:00:00:00:00:02", Name: "phone"},
		{MAC: "02:00:00:00:00:20", Name: "AP Living"}, // the AP is also a device
	}
	dists := applyUniFiInfra(devices, nil, testInventory(), "gateway")

	// A node per box, none for the client the server has never seen.
	if len(dists) != 2 {
		t.Fatalf("nodes: %+v", dists)
	}
	var sw, ap *DistributionNode
	for i := range dists {
		switch dists[i].Mac {
		case "02:00:00:00:00:10":
			sw = &dists[i]
		case "02:00:00:00:00:20":
			ap = &dists[i]
		}
	}
	if sw == nil || ap == nil {
		t.Fatalf("expected a node for the switch and the AP: %+v", dists)
	}
	if sw.Kind != "managed" || sw.Source != "unifi" || sw.RouterID != "gateway" {
		t.Fatalf("switch node: %+v", sw)
	}
	if sw.Name != "Switch Rack" || sw.Ip != "192.0.2.10" || sw.MacCount != 2 {
		t.Fatalf("switch node: %+v", sw)
	}
	// The AP hangs off the switch port the controller reports, with the
	// admin's own port name — the half the router's LLDP cannot see.
	if ap.Parent != sw.ID || ap.Port != "lan3" || ap.PortLabel != "AP Living" {
		t.Fatalf("ap node: %+v", ap)
	}

	// Wired client on its port, with the port's name.
	if devices[0].AttachTo != sw.ID || devices[0].Port != "lan5" || devices[0].PortLabel != "Desk" {
		t.Fatalf("wired client: %+v", devices[0])
	}
	// Wireless client on its AP, with the band the AP reports.
	if devices[1].AttachTo != ap.ID || devices[1].Band != "5 GHz" {
		t.Fatalf("wireless client: %+v", devices[1])
	}
	// The AP's own device entry is infrastructure, not a plain client.
	if devices[2].Infra != "managed-switch" {
		t.Fatalf("ap device: %+v", devices[2])
	}
}

func TestApplyUniFiInfraEnrichesAnExistingNode(t *testing.T) {
	// The LLDP pass already found the switch on the router's port: the seal
	// must fill that node in, not add a second one for the same box.
	dists := []DistributionNode{{
		ID: "dist-gateway-lan2", Kind: "managed", RouterID: "gateway",
		Port: "lan2", Mac: "02:00:00:00:00:10", MacCount: 1,
	}}
	devices := []Device{{MAC: "02:00:00:00:00:01", Name: "desktop"}}
	out := applyUniFiInfra(devices, dists, testInventory(), "gateway")

	switches := 0
	for _, d := range out {
		if d.Mac == "02:00:00:00:00:10" {
			switches++
		}
	}
	if switches != 1 {
		t.Fatalf("the switch was duplicated: %+v", out)
	}
	if out[0].ID != "dist-gateway-lan2" || out[0].Port != "lan2" {
		t.Fatalf("the existing node lost its identity: %+v", out[0])
	}
	if out[0].Name != "Switch Rack" || out[0].Ip != "192.0.2.10" || out[0].Source != "unifi" {
		t.Fatalf("not enriched: %+v", out[0])
	}
	// The client count grows to what the controller sees, never shrinks.
	if out[0].MacCount != 2 {
		t.Fatalf("macCount: %+v", out[0])
	}
	// And the client still lands on the node that was already there.
	if devices[0].AttachTo != "dist-gateway-lan2" || devices[0].Port != "lan5" {
		t.Fatalf("client: %+v", devices[0])
	}
}

func TestApplyUniFiInfraIsANoOpWithoutInventory(t *testing.T) {
	devices := []Device{{MAC: "02:00:00:00:00:01", Name: "desktop", Port: "lan9", AttachTo: "manual"}}
	dists := []DistributionNode{{ID: "kept", Mac: "02:00:00:00:00:77"}}

	for _, inv := range []*unifiInventory{nil, {devices: map[string]unifi.Device{}}} {
		out := applyUniFiInfra(devices, dists, inv, "gateway")
		if len(out) != 1 || out[0].ID != "kept" {
			t.Fatalf("nodes touched: %+v", out)
		}
		if devices[0].AttachTo != "manual" || devices[0].Port != "lan9" {
			t.Fatalf("a device was touched: %+v", devices[0])
		}
	}
}
