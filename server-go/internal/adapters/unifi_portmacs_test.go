package adapters

import (
	"testing"

	"github.com/gnacho/netpulse/server-go/internal/unifi"
)

const (
	pmSwitch = "02:00:00:00:00:F0" // an 8-port switch
	pmAP     = "02:00:00:00:01:FE" // an AP the controller gives no ports for
)

func pmInventory() *unifiInventory {
	ports := make([]unifi.Port, 8)
	for i := range ports {
		ports[i] = unifi.Port{Idx: i + 1}
	}
	return &unifiInventory{
		devices: map[string]unifi.Device{
			pmSwitch: {MAC: pmSwitch, Kind: "switch", Ports: ports},
			pmAP:     {MAC: pmAP, Kind: "ap"},
		},
		clients: map[string]unifi.Client{
			"02:00:00:00:00:F3": {MAC: "02:00:00:00:00:F3", SwitchMAC: pmSwitch, SwitchPort: 3},
		},
	}
}

// bare is what the router knows of a MAC it only learned on a bridge port.
func bare(mac string) Device { return Device{MAC: mac, Name: mac, Band: "cable"} }

func TestUniFiPortMACsFoldsOnlyBareAddressesInRange(t *testing.T) {
	ip := bare("02:00:00:00:00:F4")
	ip.IP = "192.0.2.4"
	named := bare("02:00:00:00:00:F5")
	named.Name = "plug-01"
	override := bare("02:00:00:00:00:F6")
	override.NameOverride = "mine"
	wifi := bare("02:00:00:00:00:F7")
	wifi.Band = "5 GHz"
	mdns := bare("02:00:00:00:00:F2")
	mdns.MdnsServices = []string{"_http._tcp"}

	devices := []Device{
		{MAC: pmSwitch, Name: "switch-01", IP: "192.0.2.50"}, // the switch itself
		bare("02:00:00:00:00:F1"),                            // port 1: folded
		bare("02:00:00:00:00:F8"),                            // port 8: folded (last port)
		bare("02:00:00:00:00:F9"),                            // base + 9: beyond 8 ports
		bare("02:00:00:00:00:EF"),                            // below the base
		bare("02:00:00:00:00:F3"),                            // a client the controller lists
		ip, named, override, wifi, mdns,
		bare("02:00:00:00:02:00"), // AP base + 2 across a byte boundary: folded
		bare("02:00:00:00:02:03"), // AP base + 5: beyond the default span of 4
		bare("02:00:00:00:00:00"), // nowhere near
	}
	got := uniFiPortMACs(devices, pmInventory())
	want := map[string]string{
		"02:00:00:00:00:F1": pmSwitch,
		"02:00:00:00:00:F8": pmSwitch,
		"02:00:00:00:02:00": pmAP,
	}
	if len(got) != len(want) {
		t.Fatalf("folded %v, want %v", got, want)
	}
	for port, owner := range want {
		if got[port] != owner {
			t.Errorf("%s -> %q, want %q", port, got[port], owner)
		}
	}
}

func TestUniFiPortMACsWithoutController(t *testing.T) {
	if got := uniFiPortMACs([]Device{bare("02:00:00:00:00:F1")}, nil); len(got) != 0 {
		t.Fatalf("no inventory folded %v", got)
	}
}

// The fold drops the port address and lists it on its owner, leaving
// everything else as it was.
func TestApplyPortMACFold(t *testing.T) {
	devices := []Device{
		{MAC: pmSwitch, Name: "switch-01"},
		bare("02:00:00:00:00:F2"),
		bare("02:00:00:00:00:F1"),
		{MAC: "02:00:00:00:00:10", Name: "laptop-01"},
	}
	out := applyPortMACFold(devices, map[string]string{
		"02:00:00:00:00:F1": pmSwitch,
		"02:00:00:00:00:F2": pmSwitch,
	})
	if len(out) != 2 || out[0].MAC != pmSwitch || out[1].MAC != "02:00:00:00:00:10" {
		t.Fatalf("out: %+v", out)
	}
	if p := out[0].PortMacs; len(p) != 2 || p[0] != "02:00:00:00:00:F1" || p[1] != "02:00:00:00:00:F2" {
		t.Fatalf("port macs: %v", p)
	}
	if len(devices) != 4 || devices[1].MAC != "02:00:00:00:00:F2" {
		t.Fatal("the input slice was modified")
	}
	if got := applyPortMACFold(devices, nil); len(got) != 4 {
		t.Fatal("nothing to fold must change nothing")
	}
}

// A folded address the registry remembers does not come back as a ghost.
func TestGhostDevicesSkipsFoldedPortMACs(t *testing.T) {
	d := openLiveTestDB(t)
	l := &Live{db: d}
	if _, err := d.Exec("INSERT INTO device_seen (mac, first_seen, last_seen, name) VALUES ('02:00:00:00:00:F1', 1, 2, ''), ('02:00:00:00:00:11', 1, 2, 'laptop-02')"); err != nil {
		t.Fatal(err)
	}
	l.unifi.folded = map[string]string{"02:00:00:00:00:F1": pmSwitch}
	for _, g := range l.ghostDevices(nil) {
		if g.MAC == "02:00:00:00:00:F1" {
			t.Fatal("a folded port address came back as a ghost")
		}
	}
	l.unifi.folded = nil
	found := false
	for _, g := range l.ghostDevices(nil) {
		found = found || g.MAC == "02:00:00:00:00:F1"
	}
	if !found {
		t.Fatal("without the fold the remembered address must be listed again")
	}
}
