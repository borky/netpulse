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
	clients, err := ParseClients(rawClients)
	if err != nil {
		return nil, nil, fmt.Errorf("stat/sta: %w", err)
	}
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

// ParseClients normalises the station list, keeping only where each one sits.
func ParseClients(raw []byte) ([]Client, error) {
	var in []rawClient
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
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
	return out, nil
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
