package httpapi

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// Device names for a router panel (the push reply's "names"): what this
// server calls each device the router itself reported, which the panel
// shows only where it has no name of its own. Building the device list is
// the server's heaviest read: it is rebuilt at most once a minute, in the
// background, while pushes are answered with the previous list (the first
// pushes after a start get none).

const (
	deviceNamesTTL = time.Minute
	// deviceNamesReplyMax bounds the bytes of names in one reply.
	deviceNamesReplyMax = 256 << 10
)

var (
	deviceNamesMu       sync.Mutex
	deviceNamesAt       time.Time
	deviceNamesMap      map[string]string
	deviceNamesBuilding bool
)

func (s *server) deviceNamesForReply(p *probe.Payload) map[string]string {
	src, ok := s.adapter.(interface{ DeviceNames() map[string]string })
	if !ok || p == nil {
		return nil
	}
	deviceNamesMu.Lock()
	all := deviceNamesMap
	if (all == nil || time.Since(deviceNamesAt) > deviceNamesTTL) && !deviceNamesBuilding {
		deviceNamesBuilding = true
		go func() {
			var fresh map[string]string
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[netpulse] device names: %v", r)
				}
				deviceNamesMu.Lock()
				if fresh == nil {
					// A failed build leaves an empty list until the next
					// one is due, not one try per push.
					fresh = map[string]string{}
				}
				deviceNamesMap = fresh
				deviceNamesAt, deviceNamesBuilding = time.Now(), false
				deviceNamesMu.Unlock()
			}()
			fresh = src.DeviceNames()
		}()
	}
	deviceNamesMu.Unlock()
	return namesForRouter(all, routerMACs(p))
}

// routerMACs: every MAC the router reported in this push (its stations,
// leases, bridge table and ARP table). A light push carries none of them:
// it gets no names, the next full one does.
func routerMACs(p *probe.Payload) map[string]bool {
	macs := map[string]bool{}
	add := func(m string) {
		macs[strings.ToLower(strings.TrimSpace(m))] = true
	}
	d := p.Data
	if d.Wireless != nil {
		for m := range d.Wireless.Clients {
			add(m)
		}
	}
	if d.DHCP != nil {
		for _, l := range d.DHCP.Leases {
			add(l.MAC)
		}
	}
	if d.FDB != nil {
		for m := range d.FDB.MACs {
			add(m)
		}
	}
	for m := range d.Arp {
		add(m)
	}
	return macs
}

// namesForRouter: the names of the MACs the router reported, bounded in
// size. nil (nothing sent) before the first list is built or for a push
// without MACs; an empty set when none of them has a name, so the panel
// stops showing names that are gone.
func namesForRouter(all map[string]string, macs map[string]bool) map[string]string {
	if all == nil || len(macs) == 0 {
		return nil
	}
	out := map[string]string{}
	size := 0
	for mac := range macs {
		name, ok := all[mac]
		if !ok {
			continue
		}
		if size += len(mac) + len(name) + 6; size > deviceNamesReplyMax {
			break
		}
		out[mac] = name
	}
	return out
}
