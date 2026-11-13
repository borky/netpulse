package adapters

import (
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/db"
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
	got := uniFiPortMACs(devices, pmInventory(), nil)
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
	if got := uniFiPortMACs([]Device{bare("02:00:00:00:00:F1")}, nil, nil); len(got) != 0 {
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

// A remembered port address with no name or IP is not a ghost, even when
// it is not live (its port went down); one with a name or IP is.
func TestGhostDevicesSkipsUniFiPortMACs(t *testing.T) {
	d := openLiveTestDB(t)
	l := &Live{db: d}
	if _, err := d.Exec(`INSERT INTO device_seen (mac, first_seen, last_seen, name, ip) VALUES
		('02:00:00:00:00:F1', 1, 2, '', ''),
		('02:00:00:00:00:F2', 1, 2, 'printer-01', ''),
		('02:00:00:00:00:F3', 1, 2, '', '192.0.2.3')`); err != nil {
		t.Fatal(err)
	}
	ghosts := func() map[string]bool {
		out := map[string]bool{}
		for _, g := range l.ghostDevices(nil) {
			out[g.MAC] = true
		}
		return out
	}
	// No controller: every remembered row is a ghost.
	if g := ghosts(); !g["02:00:00:00:00:F1"] || !g["02:00:00:00:00:F2"] || !g["02:00:00:00:00:F3"] {
		t.Fatalf("without the controller: %v", g)
	}
	inv := pmInventory()
	delete(inv.clients, "02:00:00:00:00:F3")
	l.unifi.inv, l.unifi.at = inv, time.Now()
	saveUniFiTestConfig(t, d)
	g := ghosts()
	if g["02:00:00:00:00:F1"] {
		t.Fatal("a bare port address came back as a ghost")
	}
	if !g["02:00:00:00:00:F2"] || !g["02:00:00:00:00:F3"] {
		t.Fatalf("a remembered name or IP must keep the ghost: %v", g)
	}
}

// A live device the registry remembers a name or an IP for is not folded:
// it is a host whose lease has just expired.
func TestUniFiPortMACsKeepsRememberedHosts(t *testing.T) {
	devices := []Device{bare("02:00:00:00:00:F1"), bare("02:00:00:00:00:F2"), bare("02:00:00:00:00:F4")}
	remembered := map[string]seenRow{
		"02:00:00:00:00:F2": {name: "nas-01"},
		"02:00:00:00:00:F4": {ip: "192.0.2.4"},
	}
	got := uniFiPortMACs(devices, pmInventory(), remembered)
	if len(got) != 1 || got["02:00:00:00:00:F1"] != pmSwitch {
		t.Fatalf("folded %v", got)
	}
	notify := bare("02:00:00:00:00:F5")
	notify.NotifyOffline = true
	lower := bare("02:00:00:00:00:F6")
	lower.Name = "02:00:00:00:00:f6"
	got = uniFiPortMACs([]Device{notify, lower}, pmInventory(), nil)
	if _, ok := got[notify.MAC]; ok {
		t.Fatal("a device with an offline-alert opt-in was folded")
	}
	if _, ok := got[lower.MAC]; !ok {
		t.Fatal("a MAC-shaped name in another case must still count as no name")
	}
}

// saveUniFiTestConfig enables the integration, so the cached inventory a
// test put in place is served (nothing is fetched while the cache is fresh).
func saveUniFiTestConfig(t *testing.T, d *db.DB) {
	t.Helper()
	if err := unifi.SaveConfig(d.DB, unifi.Config{URL: "https://192.0.2.1:8443", Username: "dummy", Password: "dummy-pass"}); err != nil {
		t.Fatal(err)
	}
}
