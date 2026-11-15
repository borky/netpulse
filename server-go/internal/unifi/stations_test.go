package unifi

import "testing"

// The quarantine's station view: wired ones kept even unplaced, Wi-Fi
// details read loosely, values that would read oddly in a notice dropped.
func TestParseStations(t *testing.T) {
	raw := []byte(`[
		{"mac":"02:00:00:00:00:01","is_wired":false,"ap_mac":"02:00:00:00:00:a1","radio":"na","radio_proto":"ax","nss":2,"is_mlo":false},
		{"mac":"02:00:00:00:00:02","is_wired":false,"ap_mac":"02:00:00:00:00:a1","radio":"6e","radio_proto":"be","nss":"2","is_mlo":"true"},
		{"mac":"02:00:00:00:00:03","is_wired":true},
		{"mac":"02:00:00:00:00:04","is_wired":false},
		{"mac":"02:00:00:00:00:05","is_wired":false,"ap_mac":"02:00:00:00:00:a1","radio":"xx","radio_proto":"a‮b","nss":99},
		{"mac":"","is_wired":true},
		"not a record"
	]`)
	got := ParseStations(raw)
	if len(got) != 4 {
		t.Fatalf("stations: %+v", got)
	}
	if s := got["02:00:00:00:00:01"]; s.Wired || s.APMAC != "02:00:00:00:00:A1" || s.Band != "5g" || s.Proto != "ax" || s.NSS != 2 || s.MLO {
		t.Fatalf("Wi-Fi 6: %+v", s)
	}
	if s := got["02:00:00:00:00:02"]; s.Band != "6g" || s.Proto != "be" || s.NSS != 2 || !s.MLO {
		t.Fatalf("Wi-Fi 7 with string fields: %+v", s)
	}
	if s, ok := got["02:00:00:00:00:03"]; !ok || !s.Wired || s.APMAC != "" {
		t.Fatalf("unplaced wired: %+v", s)
	}
	if _, ok := got["02:00:00:00:00:04"]; ok {
		t.Fatal("a Wi-Fi station with no access point was kept")
	}
	if s := got["02:00:00:00:00:05"]; s.Band != "" || s.Proto != "" || s.NSS != 0 {
		t.Fatalf("odd values were kept: %+v", s)
	}
	if ParseStations([]byte(`{}`)) != nil {
		t.Fatal("not a list")
	}
}
