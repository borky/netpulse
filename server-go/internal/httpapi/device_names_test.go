package httpapi_test

import (
	"strings"
	"testing"
	"time"
)

// The names this server knows never go back over plain HTTP. (This harness
// registers no router, so it has no devices to name: what is sent is
// tested with deviceNamesOf, and the TLS path on a real server.)
func TestIngestReplyCarriesNamesOnlyOverTLS(t *testing.T) {
	ts := makeAgentTestServer(t)
	_, token, _ := createAgentToken(t, ts, "patio")
	now := time.Now().Unix()
	lease := `"dhcp":{"leases":[{"mac":"02:00:00:00:00:31","ip":"192.0.2.31","hostname":"printer-hall","expires":` +
		"9999999999" + `}]}`
	payload := func(ts int64) string {
		return strings.Replace(validPayload(ts), `"dhcp":{"leases":[]}`, lease, 1)
	}
	res, reply := ingestOver(t, ts, token, payload(now), false)
	if res.StatusCode/100 != 2 {
		t.Fatalf("ingest: %d", res.StatusCode)
	}
	if _, ok := reply["names"]; ok {
		t.Fatalf("names went out over plain HTTP: %v", reply)
	}
	_, reply = ingestOver(t, ts, token, payload(now+1), true)
	names, _ := reply["names"].(map[string]any)
	t.Logf("names over TLS: %v", names)
	if names != nil && names["02:00:00:00:00:31"] != nil && names["02:00:00:00:00:31"] != "printer-hall" {
		t.Fatalf("wrong name: %v", names)
	}
}
