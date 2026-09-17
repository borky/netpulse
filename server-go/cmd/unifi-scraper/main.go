// unifi-scraper — turns what a UniFi controller knows into NetPulse agents.
//
// Why this exists: a UniFi switch reports its neighbours only to its own
// controller, and UniFi Network dropped SNMP, so NetPulse's topology stops at
// the router — it can see "a switch hangs off lan2" and nothing past it. The
// controller holds the missing half: which switch port, or which AP, every
// client sits on. This reads that and pushes one external-agent payload
// (#288) per adopted device, so each switch and AP becomes a monitored device
// with its own clients. No server changes: it speaks the ingest contract the
// server already accepts.
//
// Reusable on purpose: nothing about the fleet is hardcoded. It discovers
// every adopted device on the site and provisions an agent slug for each the
// first time it sees it.
//
// Usage: unifi-scraper -config /etc/netpulse/unifi-scraper.json [-once]
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// Config is the file the tool runs off. Secrets live here, so it is expected
// to be root-owned and chmod 600.
type Config struct {
	UniFi struct {
		URL      string `json:"url"`      // https://<controller>
		Username string `json:"username"` // a read-only local account is enough
		Password string `json:"password"`
		Site     string `json:"site"`     // "default" unless the site was renamed
		Insecure bool   `json:"insecure"` // self-signed controller certificate
	} `json:"unifi"`
	NetPulse struct {
		URL      string `json:"url"`      // http://127.0.0.1:3000
		APIToken string `json:"apiToken"` // admin token, only used to create agents
	} `json:"netpulse"`
	// IntervalSec is how often the loop pushes. It is also declared in the
	// payload so the server widens the freshness window instead of marking
	// the device down between pushes.
	IntervalSec int `json:"intervalSec"`
	// StatePath keeps the per-slug agent tokens. Without it every run would
	// rotate the tokens, since creating an agent issues a new one.
	StatePath string `json:"statePath"`
}

type state struct {
	Tokens map[string]string `json:"tokens"` // slug -> agent token
}

func main() {
	cfgPath := flag.String("config", "/etc/netpulse/unifi-scraper.json", "config file")
	once := flag.Bool("once", false, "push a single round and exit")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	st, err := loadState(cfg.StatePath)
	if err != nil {
		log.Fatalf("state: %v", err)
	}

	run := func() {
		if err := round(cfg, st); err != nil {
			log.Printf("round failed: %v", err)
		}
	}
	run()
	if *once {
		return
	}
	tick := time.NewTicker(time.Duration(cfg.IntervalSec) * time.Second)
	defer tick.Stop()
	for range tick.C {
		run()
	}
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	if cfg.UniFi.URL == "" || cfg.NetPulse.URL == "" {
		return nil, fmt.Errorf("unifi.url and netpulse.url are required")
	}
	if cfg.UniFi.Site == "" {
		cfg.UniFi.Site = "default"
	}
	if cfg.IntervalSec <= 0 {
		cfg.IntervalSec = 300
	}
	if cfg.StatePath == "" {
		cfg.StatePath = strings.TrimSuffix(path, ".json") + ".state.json"
	}
	return cfg, nil
}

func loadState(path string) (*state, error) {
	st := &state{Tokens: map[string]string{}}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, st); err != nil {
		return nil, err
	}
	if st.Tokens == nil {
		st.Tokens = map[string]string{}
	}
	return st, nil
}

func (s *state) save(path string) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// ---------------------------------------------------------------------------
// UniFi controller
// ---------------------------------------------------------------------------

type unifiClient struct {
	http *http.Client
	cfg  *Config
	// base is the API prefix that answered the login: UniFi OS proxies the
	// network application under /proxy/network, the older standalone
	// controller serves it at the root.
	base string
}

// unifiDevice is the slice of /stat/device this tool needs.
type unifiDevice struct {
	MAC    string      `json:"mac"`
	Name   string      `json:"name"`
	Model  string      `json:"model"`
	Type   string      `json:"type"` // usw = switch, uap = access point, ugw/udm = gateway
	Uptime float64     `json:"uptime"`
	Ports  []unifiPort `json:"port_table"`
}

// unifiPort is one entry of a switch's port_table.
type unifiPort struct {
	Idx      int    `json:"port_idx"`
	Name     string `json:"name"`
	Up       bool   `json:"up"`
	Speed    int    `json:"speed"` // Mbps, 0 when down
	IsUplink bool   `json:"is_uplink"`
}

// unifiSTA is the slice of /stat/sta this tool needs: where each client sits.
type unifiSTA struct {
	MAC     string `json:"mac"`
	IsWired bool   `json:"is_wired"`
	SwMAC   string `json:"sw_mac"`  // switch the wired client hangs off
	SwPort  int    `json:"sw_port"` // ... and its port
	ApMAC   string `json:"ap_mac"`  // AP the wireless client is associated to
	Radio   string `json:"radio"`   // ng = 2.4 GHz, na = 5 GHz, 6e = 6 GHz
	RSSI    int    `json:"rssi"`
	Signal  int    `json:"signal"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

func newUniFi(cfg *Config) (*unifiClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.UniFi.Insecure}}
	return &unifiClient{
		http: &http.Client{Jar: jar, Transport: tr, Timeout: 20 * time.Second},
		cfg:  cfg,
	}, nil
}

// login tries the UniFi OS endpoint first and falls back to the standalone
// controller, so the same binary works against a UDM/cloud key and against an
// old self-hosted controller.
func (u *unifiClient) login() error {
	body, _ := json.Marshal(map[string]string{
		"username": u.cfg.UniFi.Username,
		"password": u.cfg.UniFi.Password,
	})
	attempts := []struct{ path, base string }{
		{"/api/auth/login", "/proxy/network"}, // UniFi OS
		{"/api/login", ""},                    // standalone controller
	}
	var last error
	for _, a := range attempts {
		req, err := http.NewRequest("POST", strings.TrimRight(u.cfg.UniFi.URL, "/")+a.path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := u.http.Do(req)
		if err != nil {
			last = err
			continue
		}
		io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		res.Body.Close()
		if res.StatusCode == 200 {
			u.base = a.base
			return nil
		}
		last = fmt.Errorf("%s: HTTP %d", a.path, res.StatusCode)
	}
	return fmt.Errorf("unifi login: %w", last)
}

// get reads a site endpoint. The controller wraps everything in {"data": [...]}.
func (u *unifiClient) get(endpoint string, out any) error {
	url := fmt.Sprintf("%s%s/api/s/%s/%s", strings.TrimRight(u.cfg.UniFi.URL, "/"),
		u.base, u.cfg.UniFi.Site, strings.TrimLeft(endpoint, "/"))
	res, err := u.http.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", endpoint, res.StatusCode)
	}
	var wrapper struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&wrapper); err != nil {
		return err
	}
	return json.Unmarshal(wrapper.Data, out)
}

// ---------------------------------------------------------------------------
// Payload building
// ---------------------------------------------------------------------------

var slugStrip = regexp.MustCompile(`[^a-z0-9-]+`)

// slugFor derives the agent slug from the device name, falling back to its
// MAC. The slug is the identity the server knows the device by, so it has to
// stay stable: renaming a device in the controller would otherwise orphan it.
func slugFor(d unifiDevice) string {
	base := strings.ToLower(strings.TrimSpace(d.Name))
	base = slugStrip.ReplaceAllString(strings.ReplaceAll(base, " ", "-"), "")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "unifi-" + strings.ToLower(strings.ReplaceAll(d.MAC, ":", ""))
	}
	if len(base) > 64 {
		base = base[:64]
	}
	return base
}

func speedLabel(mbps int) string {
	switch {
	case mbps <= 0:
		return "—"
	case mbps >= 1000:
		return fmt.Sprintf("%d Gbps", mbps/1000)
	default:
		return fmt.Sprintf("%d Mbps", mbps)
	}
}

func bandLabel(radio string) string {
	switch radio {
	case "na":
		return "5 GHz"
	case "6e":
		return "6 GHz"
	default:
		return "2.4 GHz"
	}
}

// buildPayload turns one adopted device plus the clients in front of it into
// the payload the server ingests. A switch contributes its port table and the
// MAC learned on each port; an AP contributes its associated stations.
func buildPayload(cfg *Config, d unifiDevice, stas []unifiSTA) probe.Payload {
	p := probe.Payload{
		Router:   slugFor(d),
		Ts:       time.Now().Unix(),
		Version:  "unifi-scraper",
		Kind:     "external",
		Interval: cfg.IntervalSec,
	}
	sys := &probe.SysInfo{Uptime: d.Uptime}
	p.Data.System = &probe.SystemData{SysInfo: sys}

	switch d.Type {
	case "usw":
		fdb := &probe.FDBData{MACs: map[string]string{}, Ports: []probe.EthPort{}}
		for _, port := range d.Ports {
			id := fmt.Sprintf("lan%d", port.Idx)
			label := strings.TrimSpace(port.Name)
			if label == "" {
				label = fmt.Sprintf("Port %d", port.Idx)
			}
			ep := probe.EthPort{ID: id, Label: label, Up: port.Up}
			if port.Up {
				ep.Speed = speedLabel(port.Speed)
			}
			fdb.Ports = append(fdb.Ports, ep)
		}
		for _, s := range stas {
			if !s.IsWired || !sameMAC(s.SwMAC, d.MAC) || s.SwPort == 0 {
				continue
			}
			fdb.MACs[strings.ToUpper(s.MAC)] = fmt.Sprintf("lan%d", s.SwPort)
		}
		p.Data.FDB = fdb

	case "uap":
		clients := map[string]probe.WirelessClient{}
		for _, s := range stas {
			if s.IsWired || !sameMAC(s.ApMAC, d.MAC) {
				continue
			}
			signal := s.Signal
			if signal == 0 {
				signal = s.RSSI
			}
			clients[strings.ToUpper(s.MAC)] = probe.WirelessClient{
				SignalDbm: signal,
				Band:      bandLabel(s.Radio),
				RxBytes:   s.RxBytes,
				TxBytes:   s.TxBytes,
			}
		}
		p.Data.Wireless = &probe.WirelessData{Clients: clients, Radios: []probe.Radio{}}
	}
	return p
}

func sameMAC(a, b string) bool {
	return a != "" && strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// ---------------------------------------------------------------------------
// NetPulse ingest
// ---------------------------------------------------------------------------

type netpulseClient struct {
	http *http.Client
	cfg  *Config
	st   *state
}

// tokenFor returns the agent token for a slug, creating the agent the first
// time. Creating one issues a NEW token, so the result is persisted: calling
// it again on every round would rotate the token and lock the device out.
func (n *netpulseClient) tokenFor(slug string) (string, error) {
	if tok, ok := n.st.Tokens[slug]; ok && tok != "" {
		return tok, nil
	}
	if n.cfg.NetPulse.APIToken == "" {
		return "", fmt.Errorf("no token for %q and no netpulse.apiToken to create one", slug)
	}
	body, _ := json.Marshal(map[string]any{"slug": slug})
	req, err := http.NewRequest("POST", strings.TrimRight(n.cfg.NetPulse.URL, "/")+"/api/agents", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+n.cfg.NetPulse.APIToken)
	res, err := n.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != 200 && res.StatusCode != 201 {
		return "", fmt.Errorf("create agent %q: HTTP %d: %s", slug, res.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("create agent %q: no token in response: %s", slug, strings.TrimSpace(string(raw)))
	}
	n.st.Tokens[slug] = out.Token
	if err := n.st.save(n.cfg.StatePath); err != nil {
		return "", fmt.Errorf("save state: %w", err)
	}
	log.Printf("provisioned agent %q", slug)
	return out.Token, nil
}

// push sends one payload, signed the way the ingest endpoint demands:
// HMAC-SHA256 of the exact body, keyed by the agent token.
func (n *netpulseClient) push(p probe.Payload) error {
	token, err := n.tokenFor(p.Router)
	if err != nil {
		return err
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(body)
	req, err := http.NewRequest("POST", strings.TrimRight(n.cfg.NetPulse.URL, "/")+"/api/ingest/agent", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Agent-Signature", hex.EncodeToString(mac.Sum(nil)))
	res, err := n.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode >= 300 {
		return fmt.Errorf("ingest %q: HTTP %d: %s", p.Router, res.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}

// ---------------------------------------------------------------------------

func round(cfg *Config, st *state) error {
	uc, err := newUniFi(cfg)
	if err != nil {
		return err
	}
	if err := uc.login(); err != nil {
		return err
	}
	var devices []unifiDevice
	if err := uc.get("stat/device", &devices); err != nil {
		return fmt.Errorf("stat/device: %w", err)
	}
	var stas []unifiSTA
	if err := uc.get("stat/sta", &stas); err != nil {
		return fmt.Errorf("stat/sta: %w", err)
	}

	np := &netpulseClient{http: &http.Client{Timeout: 20 * time.Second}, cfg: cfg, st: st}
	pushed, failed := 0, 0
	for _, d := range devices {
		// Gateways are the router itself, which already runs its own agent.
		if d.Type != "usw" && d.Type != "uap" {
			continue
		}
		p := buildPayload(cfg, d, stas)
		if err := np.push(p); err != nil {
			log.Printf("push %s (%s): %v", slugFor(d), d.Type, err)
			failed++
			continue
		}
		pushed++
	}
	log.Printf("pushed %d device(s), %d failed, %d clients seen", pushed, failed, len(stas))
	if failed > 0 && pushed == 0 {
		return fmt.Errorf("every push failed")
	}
	return nil
}
