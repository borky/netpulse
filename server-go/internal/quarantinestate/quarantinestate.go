// Package quarantinestate keeps, per router, the device quarantine its panel
// (NetGrip) reports: which devices are approved, which wait for approval,
// and which the copied-MAC detection reports. The device list shows it; the
// router stays the source of truth, and approving happens in its panel.
//
// The agent sends it only over HTTPS with a pinned key (which devices are
// trusted is what someone copying a MAC address wants to know), so it is
// kept only for pushes that arrived over TLS, in memory only, and dropped
// when a router stops refreshing it.
package quarantinestate

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// maxAge: a report not refreshed for this long is no longer shown. Full
// pushes come every 30 s or so; a router that stopped pushing, or turned
// the panel's reporting off with an older agent, must not leave a stale
// "waiting" behind for long.
const maxAge = 10 * time.Minute

// State is one device's quarantine state as one router reports it.
type State struct {
	Router string // the router whose panel manages it
	State  string // "approved" | "waiting"
	Report string // "notice" | "alert" | ""
}

type router struct {
	devices map[string]State // by lowercase MAC
	at      time.Time
}

// Store holds each router's latest report.
type Store struct {
	mu      sync.Mutex
	routers map[string]*router
	now     func() time.Time
}

// New makes an empty store.
func New() *Store { return &Store{routers: map[string]*router{}, now: time.Now} }

// Default is the server-wide store the push handler feeds.
var Default = New()

// Update records a router's report. Call it only for a push that arrived
// over TLS. A report with the quarantine off forgets the router.
func (s *Store) Update(slug string, info *probe.QuarantineInfo) {
	if s == nil || info == nil || slug == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !info.Enabled {
		delete(s.routers, slug)
		return
	}
	r := &router{devices: make(map[string]State, len(info.Devices)), at: s.now()}
	for _, d := range info.Devices {
		mac := normMAC(d.MAC)
		if mac == "" || (d.State != "approved" && d.State != "waiting") {
			continue
		}
		st := State{Router: slug, State: d.State}
		if d.Report == "notice" || d.Report == "alert" {
			st.Report = d.Report
		}
		r.devices[mac] = st
	}
	s.routers[slug] = r
}

// Lookup returns the state of the first of macs any fresh report lists.
// When several routers list one device (two panels), the most pressing
// answer wins: an alert, then a notice, then waiting, then approved.
func (s *Store) Lookup(macs ...string) (State, bool) {
	if s == nil {
		return State{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	slugs := make([]string, 0, len(s.routers))
	for slug, r := range s.routers {
		if now.Sub(r.at) > maxAge {
			delete(s.routers, slug)
			continue
		}
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs) // a tie goes the same way every time
	for _, m := range macs {
		mac := normMAC(m)
		if mac == "" {
			continue
		}
		var best State
		found := false
		for _, slug := range slugs {
			st, ok := s.routers[slug].devices[mac]
			if ok && (!found || rank(st) > rank(best)) {
				best, found = st, true
			}
		}
		if found {
			return best, true
		}
	}
	return State{}, false
}

// Entry is one device in Snapshot.
type Entry struct {
	MAC    string `json:"mac"`
	Router string `json:"router"`
	State  string `json:"state"`
	Report string `json:"report,omitempty"`
}

// Snapshot lists every device of every fresh report, one entry per MAC (the
// most pressing answer when several routers list it), sorted by MAC.
func (s *Store) Snapshot() []Entry {
	out := []Entry{}
	if s == nil {
		return out
	}
	s.mu.Lock()
	macs := map[string]bool{}
	now := s.now()
	for slug, r := range s.routers {
		if now.Sub(r.at) > maxAge {
			delete(s.routers, slug)
			continue
		}
		for mac := range r.devices {
			macs[mac] = true
		}
	}
	s.mu.Unlock()
	for mac := range macs {
		if st, ok := s.Lookup(mac); ok {
			out = append(out, Entry{MAC: mac, Router: st.Router, State: st.State, Report: st.Report})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// Listed reports whether a fresh report from slug lists mac: the server
// tells a router about a device only if that router asked about it.
func (s *Store) Listed(slug, mac string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.routers[slug]
	if r == nil || s.now().Sub(r.at) > maxAge {
		return false
	}
	_, ok := r.devices[normMAC(mac)]
	return ok
}

func rank(s State) int {
	switch {
	case s.Report == "alert":
		return 4
	case s.Report == "notice":
		return 3
	case s.State == "waiting":
		return 2
	default:
		return 1
	}
}

// normMAC: lowercase, colon-separated, or "" for anything that is not a
// 6-octet MAC address.
func normMAC(m string) string {
	m = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(m), "-", ":"))
	if len(m) != 17 {
		return ""
	}
	for i := 0; i < 17; i++ {
		c := m[i]
		if i%3 == 2 {
			if c != ':' {
				return ""
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return m
}
