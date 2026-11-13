package adapters

import "testing"

// The DHCP parameter request list names the OS of a lease that carries
// nothing else: a private MAC (no OUI) and no hostname. It fills only what
// is missing: a hostname rule keeps its more specific type, and a real OUI
// keeps the hardware maker.
func TestBuildDevicesUsesDhcpFingerprint(t *testing.T) {
	const (
		phone  = "D2:00:5E:00:53:01" // private MAC, no hostname: only the fingerprint speaks
		tablet = "D2:00:5E:00:53:02" // private MAC, hostname says tablet
		pc     = "D2:00:5E:00:53:03" // an unknown list: stays unknown
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
