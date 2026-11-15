// unifi.go — seals the topology with what a UniFi controller knows (layer 4,
// after the manual overrides and the Proxmox seal).
//
// The problem it solves: a UniFi switch answers LLDP to the router, so the
// map reaches "a switch hangs off lan2" and stops. Everything behind it —
// which port each wired client occupies, which AP each station is associated
// to, where the APs themselves plug in — lives only in the controller, since
// UniFi Network dropped SNMP and a switch talks to nothing else.
//
// Same shape as the Proxmox seal: a cached read-only inventory plus a pure
// function that applies it over the devices and distribution nodes already
// built, so it can be tested without a controller.
package adapters

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
	"github.com/gnacho/netpulse/server-go/internal/unifi"
)

// unifiInventoryTTL: the controller is local and the call is two GETs, but
// stations move slowly enough that once a minute is plenty.
const unifiInventoryTTL = 60 * time.Second

// unifiInventory is one read of the controller, indexed for sealing.
type unifiInventory struct {
	// devices: infrastructure by MAC (switches and APs).
	devices map[string]unifi.Device
	// clients: placement by client MAC.
	clients map[string]unifi.Client
	// unplaced: stations the controller listed without a place, by MAC.
	unplaced map[string]string
	// stations: how each client is connected, for the device quarantine.
	stations map[string]unifi.Station
}

type unifiCache struct {
	mu   sync.Mutex
	inv  *unifiInventory
	at   time.Time
	last string // last error, to log a repeated failure only once
	// logged: the unplaced-client reason last logged per MAC, so each
	// client's reason is logged once, and again only when it changes.
	logged map[string]string
	// latest: the last good inventory and when it was read, readable
	// without mu (which is held across a controller call): the push
	// handler must never wait for the controller.
	latest atomic.Pointer[unifiRead]
}

type unifiRead struct {
	inv *unifiInventory
	at  time.Time
}

// unifiInventoryCached polls the controller at most once per TTL. A failure
// keeps the previous inventory: a controller reboot should not erase the
// topology, the same way a failed probe keeps the last good data elsewhere.
func (l *Live) unifiInventoryCached() *unifiInventory {
	if l.db == nil {
		return nil
	}
	cfg := unifi.LoadConfig(l.db.DB)
	if !cfg.Enabled() {
		return nil
	}
	l.unifi.mu.Lock()
	defer l.unifi.mu.Unlock()
	if l.unifi.inv != nil && time.Since(l.unifi.at) < unifiInventoryTTL {
		return l.unifi.inv
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	api := unifi.NewClient(cfg)
	devices, clients, err := api.Inventory(ctx)
	if err != nil {
		if msg := err.Error(); msg != l.unifi.last {
			log.Printf("[unifi] inventory failed, keeping the previous one: %v", err)
			l.unifi.last = msg
		}
		l.unifi.at = time.Now() // do not hammer a controller that is down
		return l.unifi.inv
	}
	l.unifi.last = ""
	inv := &unifiInventory{
		devices: make(map[string]unifi.Device, len(devices)),
		clients: make(map[string]unifi.Client, len(clients)),
	}
	for _, d := range devices {
		if d.Kind == "switch" || d.Kind == "ap" {
			inv.devices[d.MAC] = d
		}
	}
	for _, c := range clients {
		inv.clients[c.MAC] = c
	}
	inv.unplaced = api.Unplaced
	inv.stations = unifi.ParseStations(api.RawClients)
	// NETPULSE_UNIFI_TRACE=<mac>[,<mac>]: log the controller's record for
	// those clients at each read, to see what it says about one device.
	for _, mac := range strings.Split(os.Getenv("NETPULSE_UNIFI_TRACE"), ",") {
		if mac = strings.TrimSpace(mac); mac != "" {
			rec := unifi.RawStation(api.RawClients, mac)
			if rec == "" {
				rec = "(not in the controller's station list)"
			}
			log.Printf("[unifi] trace %s: %s", strings.ToUpper(mac), rec)
		}
	}
	l.unifi.inv, l.unifi.at = inv, time.Now()
	l.unifi.latest.Store(&unifiRead{inv: inv, at: l.unifi.at})
	return inv
}

// quarantineStationsMaxAge: an inventory older than this says nothing about
// how a device is connected now (the poller reads it every minute).
const quarantineStationsMaxAge = 5 * time.Minute

// QuarantineStations returns what the controller said, at its last read,
// about the devices macs names that wanted(mac) accepts, for the copied-MAC
// detection of the router's panel. nil when there is no recent read. It
// never calls the controller.
func (l *Live) QuarantineStations(macs []string, wanted func(mac string) bool) []probe.QuarantineStation {
	if l == nil {
		return nil
	}
	return quarantineStations(l.unifi.latest.Load(), time.Now(), macs, wanted)
}

func quarantineStations(r *unifiRead, now time.Time, macs []string, wanted func(string) bool) []probe.QuarantineStation {
	if r == nil || r.inv == nil || now.Sub(r.at) > quarantineStationsMaxAge {
		return nil
	}
	out := []probe.QuarantineStation{}
	seen := map[string]bool{}
	for _, m := range macs {
		key := strings.ToUpper(strings.TrimSpace(m))
		st, ok := r.inv.stations[key]
		if !ok || seen[key] || !wanted(m) {
			continue
		}
		seen[key] = true
		q := probe.QuarantineStation{MAC: strings.ToLower(key), Wired: st.Wired}
		if !st.Wired {
			q.APModel = cleanModel(r.inv.devices[st.APMAC].Model)
			q.Band, q.Proto, q.NSS, q.MLO = st.Band, st.Proto, st.NSS, st.MLO
		}
		out = append(out, q)
	}
	return out
}

// cleanModel keeps a model code ("U7PG2", "U7-Pro") short and plain: it ends
// up in a router's notices.
func cleanModel(m string) string {
	var b strings.Builder
	for _, c := range m {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			b.WriteRune(c)
		}
		if b.Len() >= 24 {
			break
		}
	}
	return b.String()
}

// gatewayID: the id of the router marked as gateway, or "" when there is
// none. The paths that rebuild devices on their own need it to place nodes.
func (l *Live) gatewayID() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.gatewayCfg == nil {
		return ""
	}
	return l.gatewayCfg.ID
}

// sealUniFiInfra applies the controller's inventory over what the poller
// inferred. See applyUniFiInfra for the rules.
func (l *Live) sealUniFiInfra(devices []Device, dists []DistributionNode, gatewayID string) []DistributionNode {
	inv := l.unifiInventoryCached()
	out := applyUniFiInfra(devices, dists, inv, gatewayID)
	l.logUnplacedUniFiClients(devices, inv)
	return out
}

// logUnplacedUniFiClients says, once per client and reason, why a station
// the controller lists was not placed. Such a client keeps what the router
// inferred - a wireless one behind a UniFi AP then shows as wired - and
// nothing else in the logs would say so.
func (l *Live) logUnplacedUniFiClients(devices []Device, inv *unifiInventory) {
	if inv == nil {
		return
	}
	reasons := unplacedUniFiReasons(devices, inv)
	l.unifi.mu.Lock()
	defer l.unifi.mu.Unlock()
	if l.unifi.logged == nil {
		l.unifi.logged = map[string]string{}
	}
	for mac, why := range reasons {
		if l.unifi.logged[mac] != why {
			log.Printf("[unifi] client %s not placed: %s", mac, why)
			l.unifi.logged[mac] = why
		}
	}
	for mac := range l.unifi.logged {
		if _, still := reasons[mac]; !still {
			delete(l.unifi.logged, mac)
		}
	}
}

// unplacedUniFiReasons: for each station of the controller that NetPulse
// also sees but cannot place, why. Clients NetPulse does not see at all are
// left out: there is nothing wrong to show for them.
func unplacedUniFiReasons(devices []Device, inv *unifiInventory) map[string]string {
	seen := make(map[string]bool, len(devices))
	for _, d := range devices {
		seen[d.MAC] = true
	}
	out := map[string]string{}
	for mac, why := range inv.unplaced {
		if seen[mac] {
			out[mac] = "the controller gives no place: " + why
		}
	}
	for mac, c := range inv.clients {
		if !seen[mac] {
			continue
		}
		switch {
		case c.SwitchMAC != "":
			if _, ok := inv.devices[c.SwitchMAC]; !ok {
				out[mac] = "its switch " + c.SwitchMAC + " is not in the controller's switch/AP list"
			}
		case c.APMAC != "":
			if _, ok := inv.devices[c.APMAC]; !ok {
				out[mac] = "its AP " + c.APMAC + " is not in the controller's switch/AP list"
			}
		}
	}
	// Placed on an AP, yet the band did not take: something skipped it or
	// wrote over it.
	for _, d := range devices {
		c, ok := inv.clients[d.MAC]
		if !ok || c.APMAC == "" || out[d.MAC] != "" {
			continue
		}
		if _, known := inv.devices[c.APMAC]; known && d.Band != c.Band {
			out[d.MAC] = fmt.Sprintf("on AP %s at %s per the controller, but its band here is %q (infra=%q attachTo=%q)", c.APMAC, c.Band, d.Band, d.Infra, d.AttachTo)
		}
	}
	return out
}

// applyUniFiInfra is the pure half: it enriches the distribution nodes the
// LLDP/FDB pass already found, adds the ones only the controller knows
// about (an AP behind the switch is invisible to the router), and attaches
// every client to the box and port it actually sits on.
//
// It never removes or renames what the user pinned by hand: this runs after
// the manual overrides, and only fills in.
func applyUniFiInfra(devices []Device, dists []DistributionNode, inv *unifiInventory, gatewayID string) []DistributionNode {
	if inv == nil || len(inv.devices) == 0 {
		return dists
	}
	// Existing nodes by the MAC they were discovered with.
	distByMac := map[string]int{}
	for i, d := range dists {
		if d.Mac != "" {
			distByMac[strings.ToUpper(d.Mac)] = i
		}
	}
	byMAC := make(map[string]int, len(devices))
	for i, d := range devices {
		byMAC[d.MAC] = i
	}

	// How many clients each box carries, for the node's badge.
	count := map[string]int{}
	for _, c := range inv.clients {
		switch {
		case c.SwitchMAC != "":
			count[c.SwitchMAC]++
		case c.APMAC != "":
			count[c.APMAC]++
		}
	}

	// Pass 1: every UniFi box gets a node, enriching one that already exists.
	nodeIDByMac := map[string]string{}
	for mac, dev := range inv.devices {
		if i, ok := distByMac[mac]; ok {
			if dists[i].Name == "" {
				dists[i].Name = dev.Name
			}
			if dists[i].Ip == "" {
				dists[i].Ip = dev.IP
			}
			dists[i].Source = "unifi"
			dists[i].Role = dev.Kind
			if n := count[mac]; n > dists[i].MacCount {
				dists[i].MacCount = n
			}
			nodeIDByMac[mac] = dists[i].ID
			markInfra(devices, byMAC, mac, dev.Kind)
			continue
		}
		id := "unifi-" + strings.ToLower(strings.ReplaceAll(mac, ":", ""))
		dists = append(dists, DistributionNode{
			ID: id, Kind: "managed", Source: "unifi", RouterID: gatewayID,
			Name: dev.Name, Ip: dev.IP, Mac: mac, MacCount: count[mac],
			// Role, not Kind: the map needs "managed" to draw a node rather
			// than a client chip, but it must not call an AP a switch.
			Role: dev.Kind,
		})
		nodeIDByMac[mac] = id
		markInfra(devices, byMAC, mac, dev.Kind)
	}

	// Pass 2: chain the boxes. An AP hangs off the switch port the
	// controller says it does, which is the half the router cannot see.
	for mac, dev := range inv.devices {
		parentID, ok := nodeIDByMac[strings.ToUpper(dev.UplinkMAC)]
		if !ok || parentID == nodeIDByMac[mac] {
			continue
		}
		for i := range dists {
			if dists[i].ID != nodeIDByMac[mac] {
				continue
			}
			dists[i].Parent = parentID
			if dev.UplinkPort > 0 && dists[i].Port == "" {
				dists[i].Port = fmt.Sprintf("lan%d", dev.UplinkPort)
				dists[i].PortLabel = portNameOf(inv, dev.UplinkMAC, dev.UplinkPort)
			}
			// The switch knows the speed: it is what was negotiated on that
			// port. It was being discarded, and the links table printed
			// "1 Gbps" on every row for want of anything better.
			if sp := portSpeedOf(inv, dev.UplinkMAC, dev.UplinkPort); sp > 0 {
				dists[i].SpeedMbps = sp
			}
			break
		}
	}

	// Pass 3: place the clients.
	for mac, c := range inv.clients {
		i, ok := byMAC[mac]
		if !ok {
			continue // the controller knows it, NetPulse has not seen it
		}
		// The controller lists a client because it is associated right now,
		// which is firmer evidence of presence than the ARP entry the server
		// would otherwise rely on. Without this a station on a UniFi AP stays
		// offline — and the map only draws what is online, so the AP shows up
		// with no clients around it.
		devices[i].Online = true
		// A container's parent is its hypervisor, and the Proxmox inventory
		// already said which one. The controller does see its MAC on a
		// switch port, but that port is where the HOST's cable goes: a
		// guest has no cable of its own. Re-parenting it here undid the
		// nesting and hung ten CTs straight off the switch.
		//
		// Only when the PVE seal actually placed it. A container whose host
		// could not be identified has no parent to protect, and the switch
		// port is then better than nothing -- without this it would fall
		// through to the gateway as a wired device with no evidence.
		if (devices[i].Infra == "ct" || devices[i].Infra == "vm") && devices[i].AttachTo != "" {
			continue
		}
		switch {
		case c.SwitchMAC != "":
			id, ok := nodeIDByMac[c.SwitchMAC]
			if !ok {
				continue
			}
			devices[i].AttachTo = id
			devices[i].Port = fmt.Sprintf("lan%d", c.SwitchPort)
			if label := portNameOf(inv, c.SwitchMAC, c.SwitchPort); label != "" {
				devices[i].PortLabel = label
			}
			if sp := portSpeedOf(inv, c.SwitchMAC, c.SwitchPort); sp > 0 {
				devices[i].SpeedMbps = sp
			}
		case c.APMAC != "":
			id, ok := nodeIDByMac[c.APMAC]
			if !ok {
				continue
			}
			devices[i].AttachTo = id
			// The band is what the AP reports, which beats guessing from a
			// bridge table that cannot tell radios apart.
			if c.Band != "" {
				devices[i].Band = c.Band
			}
			// So is the signal. Without it a station behind a UniFi AP had
			// none - drawn as a cable - or kept one remembered from another
			// AP long ago. The controller's is live.
			if c.SignalDbm < 0 {
				sig := c.SignalDbm
				devices[i].SignalDbm = &sig
			}
		}
	}
	return dists
}

// markInfra tags the box's own device entry, when NetPulse also sees it as a
// client, with what it is: infrastructure, and which kind. An access point
// carried the "managed-switch" badge before this, which read "Managed
// switch · identified via LLDP" on a box that is neither.
func markInfra(devices []Device, byMAC map[string]int, mac, kind string) {
	i, ok := byMAC[mac]
	if !ok {
		return
	}
	if kind == "ap" {
		devices[i].Infra = "ap"
		return
	}
	devices[i].Infra = "managed-switch"
}

// portSpeedOf: the speed negotiated on that switch port, in Mbps, or 0 when
// the controller does not report one. Real measured data, unlike the
// "1 Gbps" the links table used to print on every row.
func portSpeedOf(inv *unifiInventory, switchMAC string, port int) int {
	dev, ok := inv.devices[strings.ToUpper(switchMAC)]
	if !ok {
		return 0
	}
	for _, p := range dev.Ports {
		if p.Idx == port {
			return p.Speed
		}
	}
	return 0
}

// portNameOf: the label an admin gave a switch port in the controller, or ""
// when the port has no name (the UI then falls back to "lanN").
func portNameOf(inv *unifiInventory, switchMAC string, port int) string {
	dev, ok := inv.devices[strings.ToUpper(switchMAC)]
	if !ok {
		return ""
	}
	for _, p := range dev.Ports {
		if p.Idx == port {
			return p.Name
		}
	}
	return ""
}
