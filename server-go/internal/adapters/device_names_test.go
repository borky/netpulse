package adapters

import "testing"

func TestDeviceNamesOfKeepsOnlyRealNames(t *testing.T) {
	devs := []Device{
		{MAC: "02:00:00:00:00:01", Name: "Living Room TV", AliasMacs: []string{"02-00-00-00-00-0A"}},
		{MAC: "02:00:00:00:00:02", Name: "02:00:00:00:00:02"},            // the address itself
		{MAC: "02:00:00:00:00:03", Name: "iOS-6C3E", NameInferred: true}, // a fingerprint label
		{MAC: "02:00:00:00:00:04", Name: "  "},                           // empty
		{MAC: "02:00:00:00:00:05", Name: "AA-BB-CC-DD-EE-FF"},            // another MAC
		{MAC: "not-a-mac", Name: "Ghost"},                                // no usable MAC
	}
	got := deviceNamesOf(devs)
	want := map[string]string{"02:00:00:00:00:01": "Living Room TV", "02:00:00:00:00:0a": "Living Room TV"}
	if len(got) != len(want) {
		t.Fatalf("names = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("names = %v", got)
		}
	}
}

func TestDeviceNamesOfBoundsLength(t *testing.T) {
	long := ""
	for i := 0; i < 100; i++ {
		long += "é"
	}
	got := deviceNamesOf([]Device{{MAC: "02:00:00:00:00:01", Name: long}})
	if n := len([]rune(got["02:00:00:00:00:01"])); n != deviceNameMaxLen {
		t.Fatalf("name kept %d runes", n)
	}
}
