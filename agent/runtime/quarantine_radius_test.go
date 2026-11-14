package runtime

import "testing"

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
