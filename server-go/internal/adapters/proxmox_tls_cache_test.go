package adapters

import (
	"testing"

	"github.com/gnacho/netpulse/server-go/internal/pve"
)

// Changing an instance's TLS settings rebuilds its client at once: before,
// the cache key held only id, URL and token, so turning on "insecure" (or
// pasting a CA or fingerprint) had no effect until the server restarted.
func TestPveClientIsRebuiltWhenTLSSettingsChange(t *testing.T) {
	d := openLiveTestDB(t)
	base := pve.Config{URL: "https://192.0.2.2:8006", TokenID: "dummy-token-id", Secret: "s"}
	save := func(c pve.Config) {
		t.Helper()
		if err := pve.SaveInstances(d.DB, []pve.Instance{{ID: "test-pve", Name: "test", Config: c}}); err != nil {
			t.Fatalf("SaveInstances: %v", err)
		}
	}
	save(base)
	l := NewLive(nil, d, nil, nil)
	first := l.pveClientsCached()[0].c
	if again := l.pveClientsCached()[0].c; again != first {
		t.Fatal("an unchanged config rebuilt its client")
	}

	for name, change := range map[string]func(*pve.Config){
		"insecure":    func(c *pve.Config) { c.Insecure = true },
		"fingerprint": func(c *pve.Config) { c.FingerprintSHA256 = "ab" },
		"ca":          func(c *pve.Config) { c.CAPEM = "-----BEGIN CERTIFICATE-----" },
	} {
		c := base
		change(&c)
		save(c)
		if got := l.pveClientsCached()[0].c; got == first {
			t.Errorf("%s: the client was not rebuilt after the TLS setting changed", name)
		}
		save(base)
		first = l.pveClientsCached()[0].c
	}
}
