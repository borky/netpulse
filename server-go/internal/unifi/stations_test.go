package unifi

import (
	"encoding/json"
	"reflect"
	"testing"
)

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

// The one decoding Inventory does gives what the separate parsers give, and
// odd Wi-Fi fields never make the placement fail (it decodes exactly when
// it did before those fields were read).
func TestOneDecodingMatchesTheParsers(t *testing.T) {
	raw := []byte(`[
		{"mac":"02:00:00:00:00:01","is_wired":false,"ap_mac":"02:00:00:00:00:a1","radio":"na","radio_proto":"ax","nss":2,"is_mlo":false},
		{"mac":"02:00:00:00:00:02","is_wired":false,"ap_mac":"02:00:00:00:00:a1","radio":"6e","radio_proto":7,"nss":{"x":1},"is_mlo":[true]},
		{"mac":"02:00:00:00:00:03","is_wired":true,"sw_mac":"02:00:00:00:00:b1","sw_port":4},
		{"mac":"02:00:00:00:00:04","is_wired":true}
	]`)
	var recs []rawStationRec
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatalf("odd Wi-Fi fields failed the decoding: %v", err)
	}
	clients, err := ParseClients(raw)
	if err != nil || !reflect.DeepEqual(clients, clientsFrom(recs)) || len(clients) != 3 {
		t.Fatalf("clients: %+v %v", clients, err)
	}
	if !reflect.DeepEqual(UnplacedClients(raw), unplacedFrom(recs)) {
		t.Fatal("unplaced differ")
	}
	st := stationsFrom(recs)
	if s := st["02:00:00:00:00:01"]; s.Proto != "ax" || s.NSS != 2 || s.Band != "5g" {
		t.Fatalf("station: %+v", s)
	}
	if s := st["02:00:00:00:00:02"]; s.Proto != "" || s.NSS != 0 || s.MLO || s.Band != "6g" {
		t.Fatalf("odd fields were kept: %+v", s)
	}
	if !st["02:00:00:00:00:04"].Wired {
		t.Fatal("an unplaced wired client is missing")
	}
	// The record-by-record parser agrees where both can read a record.
	for mac, want := range ParseStations(raw) {
		if st[mac] != want {
			t.Fatalf("%s: %+v vs %+v", mac, st[mac], want)
		}
	}
	// A list that never decoded still does not.
	if _, err := ParseClients([]byte(`[{"mac":"02:00:00:00:00:05","is_wired":"yes"}]`)); err == nil {
		t.Fatal("a list that failed before now decodes")
	}
}
