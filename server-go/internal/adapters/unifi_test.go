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
	// The AP's own device entry is infrastructure, and specifically an access
	// point: "managed-switch" put a "Managed switch · identified via LLDP"
	// badge on a box that is neither.
	if devices[2].Infra != "ap" {
		t.Fatalf("ap device: %+v", devices[2])
	}
	// Same on the node: kind stays "managed" because it drives the layout,
	// and role is what the box actually is.
	if sw.Role != "switch" || ap.Role != "ap" {
		t.Fatalf("roles: switch=%q ap=%q", sw.Role, ap.Role)
	}
	if ap.Kind != "managed" {
		t.Fatalf("an AP node must stay managed for the layout: %+v", ap)
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
	// An LLDP node the seal recognises also learns what the box is.
	if out[0].Role != "switch" {
		t.Fatalf("role: %+v", out[0])
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

// A station the controller reports is connected: the map only draws online
// devices, so leaving it offline is what left the APs surrounded by nothing.
func TestApplyUniFiInfraMarksReportedClientsOnline(t *testing.T) {
	devices := []Device{
		{MAC: "02:00:00:00:00:01", Name: "desktop", Online: false},
		{MAC: "02:00:00:00:00:02", Name: "phone", Online: false},
		{MAC: "02:00:00:00:00:77", Name: "unknown to the controller", Online: false},
	}
	applyUniFiInfra(devices, nil, testInventory(), "gateway")

	if !devices[0].Online || !devices[1].Online {
		t.Fatalf("clients the controller reports must be online: %+v", devices[:2])
	}
	// One it knows nothing about is left exactly as it was.
	if devices[2].Online {
		t.Fatalf("a device outside the controller was touched: %+v", devices[2])
	}
}

// A container the Proxmox seal already placed under its hypervisor: the
// controller sees its MAC on a switch port, but that port is the HOST's
// cable. Re-parenting it here hung the guests off the switch and undid the
// nesting the PVE inventory had got right.
func TestApplyUniFiInfraLeavesContainersOnTheirHypervisor(t *testing.T) {
	devices := []Device{
		{MAC: "02:00:00:00:00:01", Name: "storage", Infra: "ct",
			AttachTo: "02-00-00-00-00-40", Online: false},
	}
	applyUniFiInfra(devices, nil, testInventory(), "gateway")

	if devices[0].AttachTo != "02-00-00-00-00-40" {
		t.Fatalf("a container was re-parented onto the switch: %+v", devices[0])
	}
	if devices[0].Port != "" || devices[0].PortLabel != "" {
		t.Fatalf("a guest has no port of its own: %+v", devices[0])
	}
	// Presence is still real evidence: the controller sees it talking.
	if !devices[0].Online {
		t.Fatalf("online: %+v", devices[0])
	}
}

// A container the PVE seal could NOT place (host unidentified) still takes
// the switch placement: there is no nesting to protect, and a port is
// better than falling through to the gateway with no evidence at all.
func TestApplyUniFiInfraPlacesAnOrphanContainer(t *testing.T) {
	devices := []Device{{MAC: "02:00:00:00:00:01", Name: "storage", Infra: "ct"}}
	applyUniFiInfra(devices, nil, testInventory(), "gateway")
	if devices[0].AttachTo == "" || devices[0].Port != "lan5" {
		t.Fatalf("an orphan container keeps the switch port: %+v", devices[0])
	}
}

// The negotiated speed of a switch port is real measured data; the links
// table used to print "1 Gbps" on every row for want of it.
func TestApplyUniFiInfraCarriesThePortSpeed(t *testing.T) {
	inv := testInventory()
	// Port 3 carries the AP, port 5 the wired client.
	d := inv.devices["02:00:00:00:00:10"]
	d.Ports = []unifi.Port{
		{Idx: 3, Name: "AP Living", Up: true, Speed: 1000},
		{Idx: 5, Name: "Desk", Up: true, Speed: 2500},
		{Idx: 7, Name: "Down", Up: false, Speed: 0},
	}
	inv.devices["02:00:00:00:00:10"] = d

	devices := []Device{
		{MAC: "02:00:00:00:00:01", Name: "desktop"},
		{MAC: "02:00:00:00:00:02", Name: "phone"},
	}
	dists := applyUniFiInfra(devices, nil, inv, "gateway")

	var ap *DistributionNode
	for i := range dists {
		if dists[i].Mac == "02:00:00:00:00:20" {
			ap = &dists[i]
		}
	}
	if ap == nil || ap.SpeedMbps != 1000 {
		t.Fatalf("ap uplink speed: %+v", ap)
	}
	if devices[0].SpeedMbps != 2500 {
		t.Fatalf("wired client speed: %+v", devices[0])
	}
	// A wireless client has no port and therefore no wire speed.
	if devices[1].SpeedMbps != 0 {
		t.Fatalf("a wireless client got a link speed: %+v", devices[1])
	}
}

// A port the controller reports as down (speed 0) leaves the field unset,
// so the UI says "—" instead of "0 Mbps".
func TestApplyUniFiInfraIgnoresAZeroSpeed(t *testing.T) {
	inv := testInventory()
	d := inv.devices["02:00:00:00:00:10"]
	d.Ports = []unifi.Port{{Idx: 5, Name: "Desk", Up: false, Speed: 0}}
	inv.devices["02:00:00:00:00:10"] = d
	devices := []Device{{MAC: "02:00:00:00:00:01", Name: "desktop"}}
	applyUniFiInfra(devices, nil, inv, "gateway")
	if devices[0].SpeedMbps != 0 {
		t.Fatalf("speed: %+v", devices[0])
	}
}
