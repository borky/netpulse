package adapters

import (
	"testing"

	"github.com/gnacho/netpulse/agent/probe"
)

// The DHCP parameter request list names the OS of a lease that carries
// nothing else: a private MAC (no OUI) and no hostname. It fills only what
// is missing: a hostname rule keeps its more specific type, and a real OUI
// keeps the hardware maker.
func TestBuildDevicesUsesDhcpFingerprint(t *testing.T) {
	const (
		phone  = "02:00:00:00:00:01" // private MAC, no hostname: only the fingerprint speaks
		tablet = "02:00:00:00:00:02" // private MAC, hostname says tablet
		pc     = "02:00:00:00:00:03" // an unknown list: stays unknown
	)
	l := NewLive(nil, nil, nil, nil)
	polled := map[string]*routerPolled{
		"gw": {
			cfg:      RouterConfig{ID: "gw", IsGateway: true},
			fdb:      map[string]string{phone: "lan1", tablet: "lan1", pc: "lan2"},
			arp:      map[string]string{},
			arpStale: map[string]bool{},
			leases: []DhcpLease{
				{MAC: phone, IP: "192.0.2.10", ParamReqList: "1,121,3,6,15,108,114,119,162,252"},
				{MAC: tablet, IP: "192.0.2.11", Hostname: "ipad-dummy", ParamReqList: "1,121,3,6,15,114,119,252"},
				{MAC: pc, IP: "192.0.2.12", ParamReqList: "1,3,6,15,42,43"},
			},
		},
	}
	byMAC := map[string]Device{}
	for _, d := range l.buildDevices(polled, "") {
		byMAC[d.MAC] = d
	}
	if d := byMAC[phone]; d.Type != "movil" || d.Manufacturer != "Apple" || d.DhcpFingerprint != "iOS" {
		t.Errorf("phone: type %q manufacturer %q fingerprint %q", d.Type, d.Manufacturer, d.DhcpFingerprint)
	}
	if d := byMAC[tablet]; d.Type != "tablet" || d.DhcpFingerprint != "iOS" {
		t.Errorf("tablet: the hostname rule must keep its type; got %q, fingerprint %q", d.Type, d.DhcpFingerprint)
	}
	if d := byMAC[pc]; d.Type != "desconocido" || d.Manufacturer != "" || d.DhcpFingerprint != "" {
		t.Errorf("unknown list: type %q manufacturer %q fingerprint %q", d.Type, d.Manufacturer, d.DhcpFingerprint)
	}
}

// A device with no DHCP hostname takes the name it announces over mDNS
// before any host name, a strong host name before a weak one, and a weak
// one (a UUID, "Android") only when nothing else names it. Its model
// outranks the DHCP vendor class for the type.
func TestBuildDevicesMdnsNameOrderAndModelType(t *testing.T) {
	const (
		tv      = "02:00:00:00:00:10" // Cast name and model, Android vendor class
		speaker = "02:00:00:00:00:11" // a strong host name and a weak one
		box     = "02:00:00:00:00:12" // only a weak host name
		phone   = "02:00:00:00:00:13" // private MAC, nothing but the fingerprint
	)
	l := NewLive(nil, nil, nil, nil)
	polled := map[string]*routerPolled{
		"gw": {
			cfg:      RouterConfig{ID: "gw", IsGateway: true},
			fdb:      map[string]string{tv: "lan1", speaker: "lan1", box: "lan1", phone: "lan1"},
			arp:      map[string]string{},
			arpStale: map[string]bool{},
			leases: []DhcpLease{
				{MAC: tv, IP: "192.0.2.40", VendorClass: "android-dhcp-12", ParamReqList: "1,3,6,15,26,28,51,58,59,43,114"},
				{MAC: speaker, IP: "192.0.2.41"},
				{MAC: box, IP: "192.0.2.42"},
				{MAC: phone, IP: "192.0.2.43", ParamReqList: "1,121,3,6,15,108,114,119,162,252"},
			},
			discovery: &probe.DiscoveryData{
				HostByIP: map[string]string{
					"192.0.2.40": "Android",
					"192.0.2.41": "kitchen-speaker",
					"192.0.2.42": "0123abcd-4567-89ef-0123-456789abcdef",
				},
				DeviceByIP: map[string]probe.MdnsDevice{
					"192.0.2.40": {Name: "Living room", Model: "BRAVIA 4K Dummy"},
				},
			},
		},
	}
	for i := 0; i < 20; i++ {
		byMAC := map[string]Device{}
		for _, d := range l.buildDevices(polled, "") {
			byMAC[d.MAC] = d
		}
		if d := byMAC[tv]; d.Name != "Living room" || d.Type != "tv" || d.NameInferred {
			t.Fatalf("tv: name %q type %q inferred %v", d.Name, d.Type, d.NameInferred)
		}
		if d := byMAC[speaker]; d.Name != "kitchen-speaker" {
			t.Fatalf("speaker: name %q", d.Name)
		}
		if d := byMAC[box]; d.Name != "0123abcd-4567-89ef-0123-456789abcdef" {
			t.Fatalf("box: a weak name is still better than none, got %q", d.Name)
		}
		if d := byMAC[phone]; d.Name != "iOS-0013" || !d.NameInferred || d.Type != "movil" {
			t.Fatalf("phone: name %q inferred %v type %q", d.Name, d.NameInferred, d.Type)
		}
	}
}

// A label inferred from the fingerprint does not make a device known: a new
// phone still raises the unknown-device alert.
func TestInferredNameStillAlertsAsUnknown(t *testing.T) {
	l := liveTestLive()
	l.seenOnlineMacs = true
	d := Device{MAC: "02:00:00:00:00:20", Name: "iOS-0020", NameInferred: true, IP: "192.0.2.50", Online: true}
	for i := 0; i < l.unknownGraceNum; i++ {
		l.trackUnknownDevices([]Device{d}, nil)
	}
	if !l.unknownAlerted[d.MAC] {
		t.Fatal("a device named only by its fingerprint did not alert as unknown")
	}
	named := Device{MAC: "02:00:00:00:00:21", Name: "laptop-01", IP: "192.0.2.51", Online: true}
	for i := 0; i < l.unknownGraceNum; i++ {
		l.trackUnknownDevices([]Device{named}, nil)
	}
	if l.unknownAlerted[named.MAC] {
		t.Fatal("a named device alerted as unknown")
	}
}
