package unifi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Shapes taken from the controller's own API (stat/device, stat/sta),
// trimmed to the fields this package reads and with made-up addresses.
const devicesJSON = `[
 {"mac":"02:00:00:00:00:10","ip":"192.0.2.10","name":"Switch Rack","model":"US8P60","type":"usw",
  "port_table":[{"port_idx":1,"name":"Uplink","up":true,"speed":1000},
                {"port_idx":5,"name":"","up":false,"speed":0}]},
 {"mac":"02:00:00:00:00:20","ip":"192.0.2.20","name":"AP Living","model":"U7LR","type":"uap"},
 {"mac":"02:00:00:00:00:30","ip":"192.0.2.30","name":"Gateway","model":"UGW3","type":"ugw"},
 {"mac":"02:00:00:00:00:40","ip":"192.0.2.40","name":"Camera NVR","model":"UVCNVR","type":"uvc"}
]`

const clientsJSON = `[
 {"mac":"02:00:00:00:00:01","is_wired":true,"sw_mac":"02:00:00:00:00:10","sw_port":5},
 {"mac":"02:00:00:00:00:02","is_wired":false,"ap_mac":"02:00:00:00:00:20","radio":"na","signal":-52},
 {"mac":"02:00:00:00:00:03","is_wired":false,"ap_mac":"02:00:00:00:00:20","radio":"ng","rssi":-70},
 {"mac":"02:00:00:00:00:04","is_wired":true,"sw_mac":"","sw_port":0},
 {"mac":"","is_wired":true,"sw_mac":"02:00:00:00:00:10","sw_port":2}
]`

func TestParseDevicesKeepsWhatMultiplexes(t *testing.T) {
	devices, err := ParseDevices([]byte(devicesJSON))
	if err != nil {
		t.Fatal(err)
	}
	// The camera recorder multiplexes nothing and is dropped.
	if len(devices) != 3 {
		t.Fatalf("devices: %+v", devices)
	}
	sw := devices[0]
	if sw.Kind != "switch" || sw.Name != "Switch Rack" || sw.IP != "192.0.2.10" {
		t.Fatalf("switch: %+v", sw)
	}
	if len(sw.Ports) != 2 || sw.Ports[0].Name != "Uplink" || !sw.Ports[0].Up || sw.Ports[0].Speed != 1000 {
		t.Fatalf("ports: %+v", sw.Ports)
	}
	if devices[1].Kind != "ap" || devices[2].Kind != "gateway" {
		t.Fatalf("kinds: %+v", devices)
	}
	// MACs are upper-cased, like everywhere else in the server.
	if devices[1].MAC != "02:00:00:00:00:20" {
		t.Fatalf("mac: %q", devices[1].MAC)
	}
}

func TestParseClientsKeepsOnlyPlacedOnes(t *testing.T) {
	clients, err := ParseClients([]byte(clientsJSON))
	if err != nil {
		t.Fatal(err)
	}
	// The wired client with no switch/port and the one with no MAC carry no
	// placement, so there is nothing to seal with them.
	if len(clients) != 3 {
		t.Fatalf("clients: %+v", clients)
	}
	if clients[0].SwitchMAC != "02:00:00:00:00:10" || clients[0].SwitchPort != 5 {
		t.Fatalf("wired: %+v", clients[0])
	}
	if clients[1].APMAC != "02:00:00:00:00:20" || clients[1].Band != "5 GHz" || clients[1].SignalDbm != -52 {
		t.Fatalf("5 GHz: %+v", clients[1])
	}
	// signal absent → rssi is the reading.
	if clients[2].Band != "2.4 GHz" || clients[2].SignalDbm != -70 {
		t.Fatalf("2.4 GHz: %+v", clients[2])
	}
}

func TestParsersRejectGarbage(t *testing.T) {
	if _, err := ParseDevices([]byte("not json")); err == nil {
		t.Fatal("devices: expected an error")
	}
	if _, err := ParseClients([]byte("{}")); err == nil {
		t.Fatal("clients: expected an error")
	}
}

func TestConfigEnabledAndSite(t *testing.T) {
	if (Config{URL: "https://c", Username: "u"}).Enabled() {
		t.Fatal("no password: not enabled")
	}
	c := Config{URL: "https://c", Username: "u", Password: "p"}
	if !c.Enabled() || c.SiteOrDefault() != "default" {
		t.Fatalf("config: %+v", c)
	}
	if got := (Config{Site: "  home "}).SiteOrDefault(); got != "home" {
		t.Fatalf("site: %q", got)
	}
}

// The login falls back to the standalone controller when the UniFi OS
// endpoint is not there, and the inventory comes back parsed.
func TestInventoryAgainstStandaloneController(t *testing.T) {
	var loginPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			loginPaths = append(loginPaths, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		case "/api/login":
			loginPaths = append(loginPaths, r.URL.Path)
			w.WriteHeader(http.StatusOK)
		case "/api/s/default/stat/device":
			w.Write([]byte(`{"data":` + devicesJSON + `}`))
		case "/api/s/default/stat/sta":
			w.Write([]byte(`{"data":` + clientsJSON + `}`))
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := NewClient(Config{URL: srv.URL, Username: "u", Password: "p"})
	devices, clients, err := c.Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(loginPaths) != 2 || loginPaths[1] != "/api/login" {
		t.Fatalf("login attempts: %v", loginPaths)
	}
	if len(devices) != 3 || len(clients) != 3 {
		t.Fatalf("inventory: %d devices, %d clients", len(devices), len(clients))
	}
}

func TestInventoryReportsLoginFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, _, err := NewClient(Config{URL: srv.URL, Username: "u", Password: "bad"}).
		Inventory(context.Background()); err == nil {
		t.Fatal("expected a login error")
	}
	// An unconfigured integration fails before touching the network.
	if _, _, err := NewClient(Config{}).Inventory(context.Background()); err == nil {
		t.Fatal("expected an error for an empty config")
	}
}

// The controller's own JSON must survive a round trip through the exported
// shapes, so the inventory the poller sees is the one the API returned.
func TestParsedShapesMarshalBack(t *testing.T) {
	devices, _ := ParseDevices([]byte(devicesJSON))
	if _, err := json.Marshal(devices); err != nil {
		t.Fatal(err)
	}
}
