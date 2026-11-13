package dhcpfp

import "testing"

func TestLookup(t *testing.T) {
	cases := []struct {
		list    string
		os, typ string
		vendor  string
		wantHit bool
	}{
		{"1,121,3,6,15,114,119,252", "iOS", "movil", "Apple", true},
		{"1,121,3,6,15,108,114,119,162,252", "iOS", "movil", "Apple", true}, // iOS 18, seen live
		{" 1,121,3,6,15,108,114,119,162,252 ", "iOS", "movil", "Apple", true},
		{"1,121,3,6,15,114,119,95,252,44,46", "macOS", "ordenador", "Apple", true},
		{"1,3,6,15,31,33,43,44,46,47,119,121,249,252", "Windows", "ordenador", "", true},
		{"1,121,3,6,15,119,252", "iOS", "movil", "Apple", true},
		{"1,121,3,6,15,119,95,252,44,46", "macOS", "ordenador", "Apple", true},
		{"1,3,6,15,26,28,51,58,59,43", "Android", "movil", "", true},
		{"1,3,6,15,26,28,51,58,59,43,114,108", "Android", "movil", "", true},
		// Not Android: a longer last option, or the same options in
		// another order.
		{"1,3,6,15,26,28,51,58,59,430", "", "", "", false},
		{"1,3,6,15,26,28,51,58,43,59", "", "", "", false},
		// Unknown and empty.
		{"1,3,6", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, c := range cases {
		m, ok := Lookup(c.list)
		if ok != c.wantHit || m.OS != c.os || m.Type != c.typ || m.Manufacturer != c.vendor {
			t.Errorf("Lookup(%q) = %+v, %v; want %s/%s/%s %v", c.list, m, ok, c.os, c.typ, c.vendor, c.wantHit)
		}
	}
}
