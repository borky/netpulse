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
	"strings"
	"sync"
	"time"

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
}

type unifiCache struct {
	mu   sync.Mutex
	inv  *unifiInventory
	at   time.Time
	last string // last error, to log a repeated failure only once
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
	devices, clients, err := unifi.NewClient(cfg).Inventory(ctx)
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
	l.unifi.inv, l.unifi.at = inv, time.Now()
	return inv
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
	return applyUniFiInfra(devices, dists, l.unifiInventoryCached(), gatewayID)
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
