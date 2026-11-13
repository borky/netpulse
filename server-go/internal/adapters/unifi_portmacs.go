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
		// The lowest base wins, so the answer never depends on map order.
		if v > b && v-b <= span && (owner == "" || base < owner) {
			owner = base
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
func (l *Live) uniFiGhostIsPortMAC(mac string, r seenRow) bool {
	if r.name != "" || r.ip != "" {
		return false
	}
	_, ok := uniFiPortOwner(mac, l.unifiInventoryCached())
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
