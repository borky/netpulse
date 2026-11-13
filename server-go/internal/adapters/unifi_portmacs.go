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

// uniFiPortMACs returns, for each live device that is only a UniFi device's
// port address, the base MAC of that device. A device qualifies when:
//
//   - its MAC is 1..N above the base MAC of a switch or AP the controller
//     lists, N being that device's port count;
//   - the controller lists it neither as a device nor as a client;
//   - it has no IP, no DHCP lease, no name of any kind (a name, an override
//     or a link always wins), no Wi-Fi band, no DHCP fingerprint, no mDNS
//     service and no LLDP neighbour of its own.
func uniFiPortMACs(devices []Device, inv *unifiInventory) map[string]string {
	if inv == nil || len(inv.devices) == 0 {
		return nil
	}
	type base struct {
		mac  string
		val  uint64
		span uint64
	}
	var bases []base
	for mac, dev := range inv.devices {
		v, ok := macValue(mac)
		if !ok {
			continue
		}
		span := uint64(len(dev.Ports))
		if span == 0 {
			span = defaultPortMACSpan
		}
		bases = append(bases, base{mac: mac, val: v, span: span})
	}
	out := map[string]string{}
	for _, d := range devices {
		if !onlyAPortAddress(d) {
			continue
		}
		if _, listed := inv.devices[d.MAC]; listed {
			continue
		}
		if _, listed := inv.clients[d.MAC]; listed {
			continue
		}
		v, ok := macValue(d.MAC)
		if !ok {
			continue
		}
		for _, b := range bases {
			if v > b.val && v-b.val <= b.span {
				out[d.MAC] = b.mac
				break
			}
		}
	}
	return out
}

// onlyAPortAddress: nothing about the device says it is a host. Any one
// sign - an address, a name, a radio, an announcement - keeps it listed.
func onlyAPortAddress(d Device) bool {
	switch {
	case d.IP != "", d.Hostname != "", d.Name != d.MAC:
		return false
	case d.NameOverride != "", d.TypeOverride != "", d.IconOverride != "":
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
// lists them, read-only, on the device they belong to. The set is kept for
// ghostDevices, so a folded address that was remembered before does not
// come back as an offline ghost. It is recomputed on every call: without
// the controller, the addresses are listed again as before.
func (l *Live) foldUniFiPortMACs(devices []Device) []Device {
	folded := uniFiPortMACs(devices, l.unifiInventoryCached())
	l.unifi.mu.Lock()
	l.unifi.folded = folded
	l.unifi.mu.Unlock()
	return applyPortMACFold(devices, folded)
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

// uniFiFolded reports whether a MAC was last folded as a UniFi port address.
func (l *Live) uniFiFolded(mac string) bool {
	l.unifi.mu.Lock()
	defer l.unifi.mu.Unlock()
	_, ok := l.unifi.folded[mac]
	return ok
}
