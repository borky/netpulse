// Package unifi — read-only client for a UniFi Network controller.
//
// Why: a UniFi switch reports its neighbours only to its own controller, and
// UniFi Network dropped SNMP, so there is nothing for NetPulse to poll and
// the topology stops at the router. The controller holds the missing half —
// which switch port, or which AP, every client sits on — and this package
// reads it, the same way the Proxmox client reads a cluster's inventory to
// seal what L2 cannot tell apart.
//
// Auth: a local read-only account on the controller. The password is stored
// server-side and NEVER travels in API responses (see the sanitised config
// view in the HTTP layer). Only GETs are issued.
//
// TLS: the controller's certificate is self-signed out of the box, so the
// config carries an explicit opt-in to skip verification.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"time"
)

// Config: how to reach the controller (persisted in kv by the server).
type Config struct {
	// URL base, e.g. "https://192.168.1.10:8443" (no trailing slash).
	URL string `json:"url"`
	// Username of a read-only local account.
	Username string `json:"username"`
	// Password never leaves the server: the API exposes only passwordSet.
	Password string `json:"password,omitempty"`
	// Site as the controller names it internally, "default" unless renamed.
	Site string `json:"site"`
	// Insecure accepts the controller's self-signed certificate.
	Insecure bool `json:"insecure"`
}

// Enabled: true when there is enough config to try a poll.
func (c Config) Enabled() bool {
	return c.URL != "" && c.Username != "" && c.Password != ""
}

// SiteOrDefault: the site to query, defaulting to the one every controller
// ships with.
func (c Config) SiteOrDefault() string {
	if strings.TrimSpace(c.Site) == "" {
		return "default"
	}
	return strings.TrimSpace(c.Site)
}

// Device is an adopted UniFi device, reduced to what the topology needs.
type Device struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name"`
	// Model as the controller reports it ("US8P60", "U7LR"…).
	Model string `json:"model"`
	// Kind: "switch" | "ap" | "gateway" | "" for anything else.
	Kind  string `json:"kind"`
	Ports []Port `json:"ports"`
	// UplinkMAC/UplinkPort: the device this one hangs off and the port it
	// occupies there. It is how an AP gets placed on its switch port — the
	// router's LLDP only reaches the first hop.
	UplinkMAC  string `json:"uplinkMac,omitempty"`
	UplinkPort int    `json:"uplinkPort,omitempty"`
}

// Port is one socket of a switch.
type Port struct {
	Idx   int    `json:"idx"`
	Name  string `json:"name"`
	Up    bool   `json:"up"`
	Speed int    `json:"speed"` // Mbps, 0 when down
}

// Client is a station the controller sees, with where it sits: a switch port
// for a wired one, an AP for a wireless one.
type Client struct {
	MAC string `json:"mac"`
	// SwitchMAC/SwitchPort: set for a wired client.
	SwitchMAC  string `json:"switchMac"`
	SwitchPort int    `json:"switchPort"`
	// APMAC/Band/SignalDbm: set for a wireless one.
	APMAC     string `json:"apMac"`
	Band      string `json:"band"`
	SignalDbm int    `json:"signalDbm"`
}

// ---------------------------------------------------------------------------

type ClientAPI struct {
	http *http.Client
	cfg  Config
	// base is the API prefix that answered the login: UniFi OS proxies the
	// network application under /proxy/network, a standalone controller
	// serves it at the root.
	base string
	// Unplaced: after Inventory, the stations the controller listed that
	// ParseClients could not place, by MAC, with the reason. For diagnosis.
	Unplaced map[string]string
	// RawClients: the station list as the controller sent it, kept from the
	// last Inventory for NETPULSE_UNIFI_TRACE.
	RawClients []byte
	// Stations: after Inventory, how each client is connected, for the
	// device quarantine (see ParseStations), from the same single decoding
	// of the station list as the clients.
	Stations map[string]Station
}

// NewClient builds a client; nothing happens until a call is made.
func NewClient(cfg Config) *ClientAPI {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}}
	return &ClientAPI{
		http: &http.Client{Jar: jar, Transport: tr, Timeout: 15 * time.Second},
		cfg:  cfg,
	}
}

// login authenticates and remembers which API layout answered, so the same
// code works against a UDM/cloud key (UniFi OS) and a self-hosted controller.
func (c *ClientAPI) login(ctx context.Context) error {
	if !c.cfg.Enabled() {
		return fmt.Errorf("unifi: incomplete configuration")
	}
	body, _ := json.Marshal(map[string]string{
		"username": c.cfg.Username,
		"password": c.cfg.Password,
	})
	attempts := []struct{ path, base string }{
		{"/api/auth/login", "/proxy/network"}, // UniFi OS
		{"/api/login", ""},                    // standalone controller
	}
	var last error
	for _, a := range attempts {
		req, err := http.NewRequestWithContext(ctx, "POST",
			strings.TrimRight(c.cfg.URL, "/")+a.path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := c.http.Do(req)
		if err != nil {
			last = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		res.Body.Close()
		if res.StatusCode == http.StatusOK {
			c.base = a.base
			return nil
		}
		last = fmt.Errorf("%s: HTTP %d", a.path, res.StatusCode)
	}
	return fmt.Errorf("unifi login: %w", last)
}

// get reads a site endpoint and returns the raw "data" array, so parsing
// lives in functions that can be tested against captured JSON.
func (c *ClientAPI) get(ctx context.Context, endpoint string) (json.RawMessage, error) {
	url := fmt.Sprintf("%s%s/api/s/%s/%s", strings.TrimRight(c.cfg.URL, "/"),
		c.base, c.cfg.SiteOrDefault(), strings.TrimLeft(endpoint, "/"))
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", endpoint, res.StatusCode)
	}
	var wrapper struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&wrapper); err != nil {
		return nil, err
	}
	return wrapper.Data, nil
}

// Inventory logs in and returns the adopted devices and the clients in front
// of them, in one shot: both come from the same session.
func (c *ClientAPI) Inventory(ctx context.Context) ([]Device, []Client, error) {
	if err := c.login(ctx); err != nil {
		return nil, nil, err
	}
	rawDevices, err := c.get(ctx, "stat/device")
	if err != nil {
		return nil, nil, fmt.Errorf("stat/device: %w", err)
	}
	devices, err := ParseDevices(rawDevices)
	if err != nil {
		return nil, nil, fmt.Errorf("stat/device: %w", err)
	}
	rawClients, err := c.get(ctx, "stat/sta")
	if err != nil {
		return nil, nil, fmt.Errorf("stat/sta: %w", err)
	}
	// One decoding serves the placement, the unplaced list and the
	// quarantine's stations (the list can be large).
	var recs []rawStationRec
	if err := json.Unmarshal(rawClients, &recs); err != nil {
		return nil, nil, fmt.Errorf("stat/sta: %w", err)
	}
	clients := clientsFrom(recs)
	c.Unplaced = unplacedFrom(recs)
	c.Stations = stationsFrom(recs)
	c.RawClients = rawClients
	return devices, clients, nil
}

// rawDevice/rawClient mirror the controller's JSON; the exported shapes above
// are what the rest of the server sees.
type rawDevice struct {
	MAC    string `json:"mac"`
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Model  string `json:"model"`
	Type   string `json:"type"`
	Uptime int64  `json:"uptime"`
	Ports  []struct {
		Idx   int    `json:"port_idx"`
		Name  string `json:"name"`
		Up    bool   `json:"up"`
		Speed int    `json:"speed"`
	} `json:"port_table"`
	Uplink struct {
		MAC        string `json:"uplink_mac"`
		RemotePort int    `json:"uplink_remote_port"`
	} `json:"uplink"`
}

type rawClient struct {
	MAC     string `json:"mac"`
	IsWired bool   `json:"is_wired"`
	SwMAC   string `json:"sw_mac"`
	SwPort  int    `json:"sw_port"`
	ApMAC   string `json:"ap_mac"`
	Radio   string `json:"radio"`
	RSSI    int    `json:"rssi"`
	Signal  int    `json:"signal"`
}

// ParseDevices normalises the controller's device list from the raw "data"
// array, so it can be tested against captured JSON without a controller.
func ParseDevices(raw []byte) ([]Device, error) {
	var in []rawDevice
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(in))
	for _, d := range in {
		kind := ""
		switch d.Type {
		case "usw":
			kind = "switch"
		case "uap":
			kind = "ap"
		case "ugw", "udm":
			kind = "gateway"
		}
		if kind == "" {
			continue // nothing else multiplexes clients
		}
		dev := Device{
			MAC:   strings.ToUpper(d.MAC),
			IP:    d.IP,
			Name:  strings.TrimSpace(d.Name),
			Model: d.Model,
			Kind:  kind,
		}
		if d.Uplink.MAC != "" {
			dev.UplinkMAC, dev.UplinkPort = strings.ToUpper(d.Uplink.MAC), d.Uplink.RemotePort
		}
		for _, p := range d.Ports {
			dev.Ports = append(dev.Ports, Port{Idx: p.Idx, Name: strings.TrimSpace(p.Name), Up: p.Up, Speed: p.Speed})
		}
		out = append(out, dev)
	}
	return out, nil
}

// rawStationRec is one station record with every field the parsers below
// read. The extra Wi-Fi fields are raw, so they never make a record fail to
// decode: the list decodes exactly when it decodes as []rawClient.
type rawStationRec struct {
	rawClient
	RadioProto json.RawMessage `json:"radio_proto"`
	NSS        json.RawMessage `json:"nss"`
	IsMLO      json.RawMessage `json:"is_mlo"`
}

// ParseClients normalises the station list, keeping only where each one sits.
func ParseClients(raw []byte) ([]Client, error) {
	var in []rawStationRec
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	return clientsFrom(in), nil
}

func clientsFrom(in []rawStationRec) []Client {
	out := make([]Client, 0, len(in))
	for _, s := range in {
		if s.MAC == "" {
			continue
		}
		c := Client{MAC: strings.ToUpper(s.MAC)}
		if s.IsWired {
			if s.SwMAC == "" || s.SwPort == 0 {
				continue // wired but unplaced: nothing to seal
			}
			c.SwitchMAC, c.SwitchPort = strings.ToUpper(s.SwMAC), s.SwPort
		} else {
			if s.ApMAC == "" {
				continue
			}
			c.APMAC = strings.ToUpper(s.ApMAC)
			c.Band = band(s.Radio)
			c.SignalDbm = s.Signal
			if c.SignalDbm == 0 {
				c.SignalDbm = s.RSSI
			}
		}
		out = append(out, c)
	}
	return out
}

// UnplacedClients lists the stations ParseClients drops, by upper-case MAC,
// with why: a client the controller knows but NetPulse cannot place shows
// as wired (its MAC is only on the router's bridge port), and nothing said
// so before.
func UnplacedClients(raw []byte) map[string]string {
	var in []rawStationRec
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	return unplacedFrom(in)
}

func unplacedFrom(in []rawStationRec) map[string]string {
	out := map[string]string{}
	for _, s := range in {
		mac := strings.ToUpper(s.MAC)
		switch {
		case mac == "":
		case s.IsWired && (s.SwMAC == "" || s.SwPort == 0):
			out[mac] = fmt.Sprintf("wired, no switch port given (sw_mac=%q sw_port=%d, ap_mac=%q)", s.SwMAC, s.SwPort, s.ApMAC)
		case !s.IsWired && s.ApMAC == "":
			out[mac] = "wireless, no AP given"
		}
	}
	return out
}

// RawStation returns the controller's own record for one MAC from a raw
// station list, compacted, or "" when it is not listed.
func RawStation(raw []byte, mac string) string {
	var in []json.RawMessage
	if json.Unmarshal(raw, &in) != nil {
		return ""
	}
	for _, r := range in {
		var s struct {
			MAC string `json:"mac"`
		}
		if json.Unmarshal(r, &s) == nil && strings.EqualFold(s.MAC, mac) {
			return string(r)
		}
	}
	return ""
}

// band maps the controller's radio code to the label the rest of NetPulse
// uses for a client's band.
func band(radio string) string {
	switch radio {
	case "na":
		return "5 GHz"
	case "6e":
		return "6 GHz"
	default:
		return "2.4 GHz"
	}
}

// Station is how one client is connected right now, as the device
// quarantine's copied-MAC detection compares it (see ParseStations). Unlike
// Client it keeps wired clients the controller does not place, and it
// carries the Wi-Fi details Client leaves out.
type Station struct {
	MAC   string // upper-case, like Client
	Wired bool
	// Wi-Fi only: the access point, the band ("2g", "5g", "6g"), the Wi-Fi
	// standard in use ("n", "ac", "ax", "be"), spatial streams and Wi-Fi 7
	// multi-link. Empty or zero when the controller does not say.
	APMAC string
	Band  string
	Proto string
	NSS   int
	MLO   bool
}

// rawStation holds the fields ParseStations reads. The controller does not
// document them and sends some as strings on some versions, so the numeric
// and boolean ones are read loosely.
type rawStation struct {
	MAC        string          `json:"mac"`
	IsWired    json.RawMessage `json:"is_wired"`
	ApMAC      string          `json:"ap_mac"`
	Radio      string          `json:"radio"`
	RadioProto string          `json:"radio_proto"`
	NSS        json.RawMessage `json:"nss"`
	IsMLO      json.RawMessage `json:"is_mlo"`
}

// stationsFrom: the quarantine's view of an already decoded list.
func stationsFrom(in []rawStationRec) map[string]Station {
	out := make(map[string]Station, len(in))
	for _, r := range in {
		if st, ok := stationOf(r.MAC, r.IsWired, r.ApMAC, r.Radio, r.RadioProto, r.NSS, r.IsMLO); ok {
			out[st.MAC] = st
		}
	}
	return out
}

// stationOf builds one station; ok false when there is nothing to say.
func stationOf(mac string, wired bool, apMAC, radio string, proto, nss, mlo json.RawMessage) (Station, bool) {
	if mac == "" {
		return Station{}, false
	}
	st := Station{MAC: strings.ToUpper(mac), Wired: wired}
	if !st.Wired {
		if apMAC == "" {
			return Station{}, false // neither wired nor on an access point: nothing to say
		}
		st.APMAC = strings.ToUpper(apMAC)
		st.Band = stationBand(radio)
		var p string
		if json.Unmarshal(proto, &p) == nil {
			st.Proto = cleanProto(p)
		}
		if n := looseInt(nss); n > 0 && n <= 16 {
			st.NSS = n
		}
		st.MLO = looseBool(mlo)
	}
	return st, true
}

// ParseStations reads the station list for the quarantine, by upper-case
// MAC, record by record: one it cannot read is skipped, not fatal.
func ParseStations(raw []byte) map[string]Station {
	var in []json.RawMessage
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	out := make(map[string]Station, len(in))
	for _, r := range in {
		var s rawStation
		if json.Unmarshal(r, &s) != nil {
			continue
		}
		var p json.RawMessage
		if s.RadioProto != "" {
			p, _ = json.Marshal(s.RadioProto)
		}
		if st, ok := stationOf(s.MAC, looseBool(s.IsWired), s.ApMAC, s.Radio, p, s.NSS, s.IsMLO); ok {
			out[st.MAC] = st
		}
	}
	return out
}

// stationBand: the radio code as a short band, "" when unknown (unlike band,
// which guesses 2.4 GHz: a guess here would read as a change of radio).
func stationBand(radio string) string {
	switch radio {
	case "ng":
		return "2g"
	case "na":
		return "5g"
	case "6e":
		return "6g"
	}
	return ""
}

// cleanProto keeps a Wi-Fi standard code ("ax", "be") and drops anything
// else: it ends up in a router's notices.
func cleanProto(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" || len(p) > 4 {
		return ""
	}
	for _, c := range p {
		if c < 'a' || c > 'z' {
			return ""
		}
	}
	return p
}

func looseBool(raw json.RawMessage) bool {
	switch strings.Trim(strings.ToLower(string(raw)), `"`) {
	case "true", "1":
		return true
	}
	return false
}

func looseInt(raw json.RawMessage) int {
	n, err := strconv.Atoi(strings.Trim(string(raw), `"`))
	if err != nil {
		return 0
	}
	return n
}
