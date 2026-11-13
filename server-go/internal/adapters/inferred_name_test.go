package adapters

import "testing"

// A label inferred from the DHCP fingerprint is not stored as a name: it
// would come back as a real one after the lease expires, and its device
// would count as a new named client next to the unknown-device alert.
func TestNoteDevicesSeenSkipsInferredNames(t *testing.T) {
	d := openLiveTestDB(t)
	l := &Live{db: d}
	if _, err := d.Exec("INSERT INTO device_seen (mac, first_seen, last_seen, name) VALUES ('02:00:00:00:00:99', 1, 2, 'seed')"); err != nil {
		t.Fatal(err) // a non-empty table, so first-timers are reported
	}
	first := l.noteDevicesSeen([]Device{
		{MAC: "02:00:00:00:00:30", Online: true, Name: "iOS-0030", NameInferred: true, IP: "192.0.2.30"},
		{MAC: "02:00:00:00:00:31", Online: true, Name: "laptop-01", IP: "192.0.2.31"},
	}, 1000)
	for _, f := range first {
		if f.MAC == "02:00:00:00:00:30" {
			t.Fatal("a device named only by a label was reported as a new named client")
		}
	}
	var name string
	if err := d.QueryRow("SELECT name FROM device_seen WHERE mac = '02:00:00:00:00:30'").Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "" {
		t.Fatalf("stored name %q, want none", name)
	}
}

// With linked MACs, a label ranks with a MAC: a real name replaces it, and
// it only replaces a MAC, carrying its flag.
func TestMergeLinkedDevicesInferredNames(t *testing.T) {
	links := map[string]string{"02:00:00:00:00:41": "02:00:00:00:00:40"}
	out := mergeLinkedDevices([]Device{
		{MAC: "02:00:00:00:00:40", Online: true, Name: "iOS-0040", NameInferred: true},
		{MAC: "02:00:00:00:00:41", Online: true, Name: "phone-01"},
	}, links)
	if out[0].Name != "phone-01" || out[0].NameInferred {
		t.Fatalf("real alias name: %q inferred %v", out[0].Name, out[0].NameInferred)
	}
	out = mergeLinkedDevices([]Device{
		{MAC: "02:00:00:00:00:40", Online: true, Name: "02:00:00:00:00:40"},
		{MAC: "02:00:00:00:00:41", Online: true, Name: "iOS-0041", NameInferred: true},
	}, links)
	if out[0].Name != "iOS-0041" || !out[0].NameInferred {
		t.Fatalf("label over a MAC: %q inferred %v", out[0].Name, out[0].NameInferred)
	}
	out = mergeLinkedDevices([]Device{
		{MAC: "02:00:00:00:00:40", Online: true, Name: "phone-01"},
		{MAC: "02:00:00:00:00:41", Online: true, Name: "iOS-0041", NameInferred: true},
	}, links)
	if out[0].Name != "phone-01" || out[0].NameInferred {
		t.Fatalf("a label must not replace a name: %q inferred %v", out[0].Name, out[0].NameInferred)
	}
}
