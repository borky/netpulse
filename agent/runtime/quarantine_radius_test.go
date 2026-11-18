package runtime

import (
	"testing"

	"github.com/gnacho/netpulse/agent/probe"
)

// The RADIUS secret goes only to a server reached over HTTPS with a pinned
// key.
func TestQuarantineRadiusOnlyOverPinnedHTTPS(t *testing.T) {
	for _, c := range []struct {
		server, fp string
		want       bool
	}{
		{"https://monitor.example:3443", "ab12", true},
		{"HTTPS://monitor.example", "ab12", true},
		{"https://monitor.example", "", false},
		{"http://monitor.example:3000", "ab12", false},
		{"", "", false},
	} {
		if got := quarantineRadiusAllowed(Options{Server: c.server, ServerFP: c.fp}); got != c.want {
			t.Errorf("%q fp=%q: %v, want %v", c.server, c.fp, got, c.want)
		}
	}
}

// Stations in a push reply reach the embedder; a reply without them, or one
// that cannot be read, does not call it, and a panic in it is contained.
func TestHandleIngestReply(t *testing.T) {
	var got [][]probe.QuarantineStation
	opts := Options{OnQuarantineStations: func(s []probe.QuarantineStation) { got = append(got, s) }}
	handleIngestReply(opts, []byte(`{"ok":true}`))
	handleIngestReply(opts, []byte(`not json`))
	handleIngestReply(opts, nil)
	if len(got) != 0 {
		t.Fatalf("called without stations: %v", got)
	}
	handleIngestReply(opts, []byte(`{"ok":true,"stations":[{"mac":"02:00:00:00:00:01","wired":false,"band":"5g","proto":"ax","nss":2}]}`))
	if len(got) != 1 || len(got[0]) != 1 || got[0][0].Proto != "ax" || got[0][0].NSS != 2 {
		t.Fatalf("stations: %+v", got)
	}
	opts.OnQuarantineStations = func([]probe.QuarantineStation) { panic("boom") }
	handleIngestReply(opts, []byte(`{"stations":[{"mac":"02:00:00:00:00:01"}]}`))
}

// Names in a reply reach their own callback, independent of the stations:
// one missing, malformed or panicking never affects the other.
func TestHandleIngestReplyNames(t *testing.T) {
	var names []map[string]string
	var stations int
	opts := Options{
		OnQuarantineStations: func([]probe.QuarantineStation) { stations++ },
		OnDeviceNames:        func(m map[string]string) { names = append(names, m) },
	}
	handleIngestReply(opts, []byte(`{"ok":true}`))
	handleIngestReply(opts, []byte(`{"names":"not a map"}`))
	if len(names) != 0 || stations != 0 {
		t.Fatalf("called without data: names %v stations %d", names, stations)
	}
	handleIngestReply(opts, []byte(`{"names":{"02:00:00:00:00:01":"Printer"}}`))
	if len(names) != 1 || names[0]["02:00:00:00:00:01"] != "Printer" || stations != 0 {
		t.Fatalf("names: %v stations %d", names, stations)
	}
	// A panicking names callback does not stop the stations one.
	opts.OnDeviceNames = func(map[string]string) { panic("boom") }
	handleIngestReply(opts, []byte(`{"names":{"02:00:00:00:00:01":"x"},"stations":[{"mac":"02:00:00:00:00:01"}]}`))
	if stations != 1 {
		t.Fatalf("stations callback skipped after a names panic")
	}
	// Only names wanted: stations are ignored without a callback.
	opts = Options{OnDeviceNames: func(m map[string]string) { names = append(names, m) }}
	handleIngestReply(opts, []byte(`{"stations":[{"mac":"02:00:00:00:00:01"}],"names":{"02:00:00:00:00:02":"NAS"}}`))
	if len(names) != 2 {
		t.Fatalf("names-only embedder: %v", names)
	}
}
