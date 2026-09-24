package runtime

// FORK: tests for panel.go, a fork-only file.

import (
	"testing"

	"github.com/gnacho/netpulse/agent/probe"
)

// A panel on plain HTTP reports its port and nothing about TLS, so the
// monitoring side keeps talking to it the way it always has.
func TestWithPanelOnPlainHTTP(t *testing.T) {
	p := &probe.Payload{}
	withPanel(p, Options{PanelPort: 8090, PanelSPKI: func() string { return "should-not-be-read" }})
	if p.PanelPort != 8090 || p.PanelTLS || p.PanelSPKI != "" {
		t.Errorf("plain HTTP panel reported port=%d tls=%v spki=%q", p.PanelPort, p.PanelTLS, p.PanelSPKI)
	}
}

// A panel on HTTPS reports the key of the certificate it serves at the time
// of the push, asked fresh each time: a rotated certificate must move the pin
// with it on the very next push.
func TestWithPanelOnHTTPSReportsTheCurrentKey(t *testing.T) {
	current := "aa11"
	opts := Options{PanelPort: 8090, PanelTLS: true, PanelSPKI: func() string { return current }}

	p := &probe.Payload{}
	withPanel(p, opts)
	if !p.PanelTLS || p.PanelSPKI != "aa11" {
		t.Fatalf("HTTPS panel reported tls=%v spki=%q", p.PanelTLS, p.PanelSPKI)
	}

	current = "bb22" // the certificate was regenerated
	p = &probe.Payload{}
	withPanel(p, opts)
	if p.PanelSPKI != "bb22" {
		t.Errorf("after rotation the push still carries %q; the pin would go stale", p.PanelSPKI)
	}
}

// The case a review caught: an HTTPS panel that has no key to report yet -
// its certificate is opened after the agent starts - must still say it is on
// HTTPS. Reporting plain HTTP instead made the monitoring side send the
// executor token in clear to a TLS port. With TLS and no key, it sends
// nothing at all.
func TestWithPanelNeverReportsAnHTTPSPanelAsPlain(t *testing.T) {
	for _, tc := range []struct {
		name string
		spki func() string
	}{
		{"no key yet", func() string { return "" }},
		{"no key source registered", nil},
	} {
		p := &probe.Payload{}
		withPanel(p, Options{PanelPort: 8090, PanelTLS: true, PanelSPKI: tc.spki})
		if !p.PanelTLS {
			t.Errorf("%s: an HTTPS panel was reported as plain HTTP", tc.name)
		}
		if p.PanelSPKI != "" {
			t.Errorf("%s: reported key %q from nowhere", tc.name, p.PanelSPKI)
		}
	}
}
