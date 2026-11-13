package adapters

// UniFi port MACs.
//
// A UniFi switch sends its control frames (LLDP, spanning tree) from one MAC
// per port: its base MAC plus the port number. The router's bridge learns
// those addresses like any other, and with nothing else known about them
// they were listed as unknown clients - a "device" next to every switch that
// was only the switch itself.
//
// With the controller configured NetPulse knows each switch's and AP's base
// MAC and port count, so such an address can be recognised and folded into
// the device it belongs to. The rule is narrow on purpose: an address is
// folded only when nothing at all says it is a host of its own.

import (
	"sort"
	"strconv"
	"strings"
)

// defaultPortMACSpan is the offset range used for a device the controller
// reports no ports for.
const defaultPortMACSpan = 4

// uniFiPortOwner returns the base MAC of the UniFi switch or AP whose port
// address mac is: 1..N above that device's base MAC, N its port count, and
// listed by the controller neither as a device nor as a client. It says
// nothing about whether something else knows the address as a host; the
// callers check that.
func uniFiPortOwner(mac string, inv *unifiInventory) (string, bool) {
	if inv == nil || len(inv.devices) == 0 {
		return "", false
	}
	if _, listed := inv.devices[mac]; listed {
		return "", false
	}
	if _, listed := inv.clients[mac]; listed {
		return "", false
	}
	v, ok := macValue(mac)
	if !ok {
		return "", false
	}
	owner := ""
	for base, dev := range inv.devices {
		b, ok := macValue(base)
		if !ok {
			continue
		}
		span := uint64(len(dev.Ports))
		if span == 0 {
			span = defaultPortMACSpan
		}
		// The nearest base below wins: where two ranges overlap, the
		// address belongs to the block it is closest to. Deterministic,
		// whatever the map order.
		if v > b && v-b <= span {
			if ob, _ := macValue(owner); owner == "" || b > ob {
				owner = base
			}
		}
	}
	return owner, owner != ""
}

// uniFiPortMACs returns, for each live device that is only a UniFi device's
// port address, the base MAC of that device. Beyond uniFiPortOwner, the
// device must show no sign of being a host (onlyAPortAddress), and the
// registry must not remember a name or an IP for it: a host whose lease
// has just expired has neither right now, and those are restored only
// after this runs.
func uniFiPortMACs(devices []Device, inv *unifiInventory, remembered map[string]seenRow) map[string]string {
	if inv == nil || len(inv.devices) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, d := range devices {
		if !onlyAPortAddress(d) {
			continue
		}
		if r, ok := remembered[d.MAC]; ok && (r.name != "" || r.ip != "") {
			continue
		}
		if owner, ok := uniFiPortOwner(d.MAC, inv); ok {
			out[d.MAC] = owner
		}
	}
	return out
}

// onlyAPortAddress: nothing about the device says it is a host. Any one
// sign - an address, a name, a radio, an announcement, a user's setting -
// keeps it listed.
func onlyAPortAddress(d Device) bool {
	switch {
	case d.IP != "", d.Hostname != "", !isMACLike(d.Name):
		return false
	case d.NameOverride != "", d.TypeOverride != "", d.IconOverride != "", d.NotifyOffline:
		return false
	case len(d.AliasMacs) > 0, d.Lldp != nil:
		return false
	case d.Band != "cable" && d.Band != "—" && d.Band != "":
		return false
	case d.DhcpFingerprint != "", len(d.MdnsServices) > 0, d.Infra != "":
		return false
	}
	return true
}

// macValue reads a colon- or dash-separated MAC as a 48-bit number, so
// "base + N" works across a byte boundary.
func macValue(mac string) (uint64, bool) {
	if !isMACLike(mac) {
		return 0, false
	}
	hex := strings.NewReplacer(":", "", "-", "").Replace(mac)
	v, err := strconv.ParseUint(hex, 16, 64)
	return v, err == nil
}

// foldUniFiPortMACs takes UniFi port addresses out of the live list and
// lists them, read-only, on the device they belong to. It is recomputed on
// every call and stores nothing: without the controller, the addresses are
// listed again as before.
func (l *Live) foldUniFiPortMACs(devices []Device) []Device {
	inv := l.unifiInventoryCached()
	if inv == nil {
		return devices
	}
	var remembered map[string]seenRow
	if l.db != nil {
		if byMac, err := l.seenByMac(); err == nil {
			remembered = make(map[string]seenRow, len(byMac))
			for mac, r := range byMac {
				remembered[normSeenMAC(mac)] = r
			}
		}
	}
	return applyPortMACFold(devices, uniFiPortMACs(devices, inv, remembered))
}

// uniFiGhostIsPortMAC: a remembered address with no name and no IP that is
// a UniFi port address is not listed as an offline ghost. The same rule as
// the live fold, so a port MAC that left the bridge table (its port went
// down) does not come back as an unknown device.
func uniFiGhostIsPortMAC(mac string, r seenRow, inv *unifiInventory, userSet map[string]bool) bool {
	if r.name != "" || r.ip != "" || userSet[mac] {
		return false
	}
	_, ok := uniFiPortOwner(mac, inv)
	return ok
}

// applyPortMACFold is the pure half of foldUniFiPortMACs.
func applyPortMACFold(devices []Device, folded map[string]string) []Device {
	if len(folded) == 0 {
		return devices
	}
	byOwner := map[string][]string{}
	for port, owner := range folded {
		byOwner[owner] = append(byOwner[owner], port)
	}
	out := devices[:0:0]
	for _, d := range devices {
		if _, isPort := folded[d.MAC]; isPort {
			continue
		}
		if ports := byOwner[d.MAC]; len(ports) > 0 {
			d.PortMacs = append([]string(nil), ports...)
			sort.Strings(d.PortMacs)
		}
		out = append(out, d)
	}
	return out
}

// macsTheUserSetUp: every MAC with a manual override of any kind, on the
// allowlist, or in a link the user made. Such a MAC is never hidden as a
// port address: the user said something about it.
func (l *Live) macsTheUserSetUp(links map[string]string) map[string]bool {
	out := map[string]bool{}
	for alias, canonical := range links {
		out[normSeenMAC(alias)] = true
		out[normSeenMAC(canonical)] = true
	}
	if l.db == nil {
		return out
	}
	for _, q := range []string{"SELECT mac FROM device_overrides", "SELECT mac FROM known_macs"} {
		rows, err := l.db.Query(q)
		if err != nil {
			continue
		}
		for rows.Next() {
			var mac string
			if rows.Scan(&mac) == nil {
				out[normSeenMAC(mac)] = true
			}
		}
		rows.Close()
	}
	return out
}
