package probe

import (
	"context"
	"testing"
)

func TestParseDhcpFingerprints(t *testing.T) {
	out := "aa:bb:cc:dd:ee:01\t1,121,3,6,15,108,114,119,162,252\t\t1794602614\n" +
		"aa:bb:cc:dd:ee:02\t1,3,6,15,31,33,43,44,46,47,119,121,249,252\tMSFT 5.0\t1794602615\n" +
		"garbage line without tabs\n" +
		"not-a-mac\t1,3,6\t\t1\n" +
		"aa:bb:cc:dd:ee:03\t\t\t1\n" + // nothing recorded: skipped
		"aa:bb:cc:dd:ee:04\t1,3,6,15,26,28,51,58,59,43" // half-written last line, no newline
	fps := ParseDhcpFingerprints(out)
	if len(fps) != 3 {
		t.Fatalf("got %d fingerprints: %+v", len(fps), fps)
	}
	if fp := fps["AA:BB:CC:DD:EE:01"]; fp.ParamReqList != "1,121,3,6,15,108,114,119,162,252" || fp.VendorClass != "" {
		t.Fatalf("iOS line: %+v", fp)
	}
	if fp := fps["AA:BB:CC:DD:EE:02"]; fp.VendorClass != "MSFT 5.0" {
		t.Fatalf("windows line: %+v", fp)
	}
	if fp := fps["AA:BB:CC:DD:EE:04"]; fp.ParamReqList != "1,3,6,15,26,28,51,58,59,43" {
		t.Fatalf("truncated line: %+v", fp)
	}
	if len(ParseDhcpFingerprints("")) != 0 {
		t.Fatal("an empty file gives fingerprints")
	}
}

// The fingerprint joins the lease of the same MAC; the ubus vendor class,
// when the firmware reports one, is kept over the hook's.
func TestProbeDHCPAttachesFingerprints(t *testing.T) {
	p := NewProber(fakeRunner{outs: map[string]string{
		CmdDhcpUbus: `{"lease":[` +
			`{"mac":"aa:bb:cc:dd:ee:01","ip":"192.0.2.10","hostname":""},` +
			`{"mac":"aa:bb:cc:dd:ee:02","ip":"192.0.2.11","hostname":"pc","vendorid":"from-ubus"},` +
			`{"mac":"aa:bb:cc:dd:ee:03","ip":"192.0.2.12","hostname":"nohook"}]}`,
		CmdDhcpFingerprints: "aa:bb:cc:dd:ee:01\t1,121,3,6,15,114,119,252\t\t1\n" +
			"aa:bb:cc:dd:ee:02\t1,3,6\tMSFT 5.0\t1\n",
	}}, Options{})
	dd := p.probeDHCP(context.Background())
	if dd == nil || len(dd.Leases) != 3 {
		t.Fatalf("leases: %+v", dd)
	}
	byMac := map[string]DhcpLease{}
	for _, l := range dd.Leases {
		byMac[l.MAC] = l
	}
	if l := byMac["AA:BB:CC:DD:EE:01"]; l.ParamReqList != "1,121,3,6,15,114,119,252" {
		t.Fatalf("fingerprint not attached: %+v", l)
	}
	if l := byMac["AA:BB:CC:DD:EE:02"]; l.ParamReqList != "1,3,6" || l.VendorClass != "from-ubus" {
		t.Fatalf("ubus vendor class must win: %+v", l)
	}
	if l := byMac["AA:BB:CC:DD:EE:03"]; l.ParamReqList != "" {
		t.Fatalf("a lease without a fingerprint got one: %+v", l)
	}
	// Without the hook nothing changes.
	p = NewProber(fakeRunner{outs: map[string]string{
		CmdDhcpUbus: `{"lease":[{"mac":"aa:bb:cc:dd:ee:01","ip":"192.0.2.10","hostname":""}]}`,
	}}, Options{})
	if dd := p.probeDHCP(context.Background()); dd == nil || dd.Leases[0].ParamReqList != "" {
		t.Fatalf("no hook: %+v", dd)
	}
}
