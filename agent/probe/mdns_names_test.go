package probe

import "testing"

func TestMdnsNameIsWeak(t *testing.T) {
	weak := []string{"Android", "android", "", "0123abcd-4567-89ef-0123-456789abcdef", "0123456789abcdef0123", "localhost"}
	strong := []string{"living-room-tv", "laptop-01", "echo-show-5-0f5204", "abc", "printer", "cafe-1234"}
	for _, n := range weak {
		if !MdnsNameIsWeak(n) {
			t.Errorf("%q should be weak", n)
		}
	}
	for _, n := range strong {
		if MdnsNameIsWeak(n) {
			t.Errorf("%q should not be weak", n)
		}
	}
}

// Two host records for one address: the strong one, on every call.
func TestParseMdnsHostsPicksTheSameBestName(t *testing.T) {
	raw := `{"0123abcd-4567-89ef-0123-456789abcdef.local":{"ipv4":"192.0.2.40"},
	         "Android.local":{"ipv4":"192.0.2.40"},
	         "b-name.local":{"ipv4":"192.0.2.41"},
	         "a-name.local":{"ipv4":"192.0.2.41"}}`
	for i := 0; i < 50; i++ {
		h := ParseMdnsHosts([]byte(raw))
		// Both weak: the lexically smaller, so it never flips.
		if h["192.0.2.40"] != "0123abcd-4567-89ef-0123-456789abcdef" {
			t.Fatalf("weak pair: %q", h["192.0.2.40"])
		}
		if h["192.0.2.41"] != "a-name" {
			t.Fatalf("strong pair: %q", h["192.0.2.41"])
		}
	}
	if BetterMdnsName("Android", "living-room") != "living-room" || BetterMdnsName("living-room", "Android") != "living-room" {
		t.Fatal("a strong name must beat a weak one in either order")
	}
}

// The shape `ubus call umdns browse` really returns: service type, then
// instance, then the record with its TXT list.
func TestParseMdnsBrowseUmdnsShape(t *testing.T) {
	raw := `{
	  "_googlecast._tcp": {
	    "Dummy-TV-0123abcd": {
	      "iface": "br-lan", "port": 8009,
	      "host": "0123abcd-4567-89ef-0123-456789abcdef.local",
	      "ipv4": "192.0.2.40",
	      "txt": ["id=0123abcd", "md=BRAVIA 4K Dummy", "fn=Living room\u0007", "rs="]
	    }
	  },
	  "_airplay._tcp": {
	    "Den": {"host": "apple-tv-dummy.local", "ipv4": ["192.0.2.50"], "txt": ["model=AppleTV6,2"]}
	  },
	  "_ipp._tcp": {
	    "Office printer": {"host": "printer-dummy.local", "ipv4": "192.0.2.60", "txt": ["ty=Dummy"]}
	  }
	}`
	dd := ParseMdnsBrowse([]byte(raw))
	if dd == nil {
		t.Fatal("nil")
	}
	tv := dd.DeviceByIP["192.0.2.40"]
	if tv.Name != "Living room" || tv.Model != "BRAVIA 4K Dummy" {
		t.Fatalf("cast device: %+v", tv)
	}
	if atv := dd.DeviceByIP["192.0.2.50"]; atv.Name != "Den" || atv.Model != "AppleTV6,2" {
		t.Fatalf("airplay device: %+v", atv)
	}
	if _, ok := dd.DeviceByIP["192.0.2.60"]; ok {
		t.Fatal("a printer's instance name is not taken as a device name")
	}
	if dd.HostByIP["192.0.2.60"] != "printer-dummy" || dd.HostByIP["192.0.2.50"] != "apple-tv-dummy" {
		t.Fatalf("hosts: %+v", dd.HostByIP)
	}
	if svcs := dd.Services["printer-dummy"]; len(svcs) != 1 || svcs[0] != "_ipp._tcp" {
		t.Fatalf("services keyed by host: %+v", dd.Services)
	}
	if svcs := dd.Services["0123abcd-4567-89ef-0123-456789abcdef"]; len(svcs) != 1 || svcs[0] != "_googlecast._tcp" {
		t.Fatalf("cast services: %+v", dd.Services)
	}
}
