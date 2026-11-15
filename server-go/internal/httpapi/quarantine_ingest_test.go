package httpapi_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/quarantinestate"
)

// ingestOver posts a signed push as if it came over HTTPS (secure) or not.
func ingestOver(t *testing.T, ts *agentTestServer, token, payload string, secure bool) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest/agent", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "192.0.2.51")
	if secure {
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(payload))
	req.Header.Set("X-Agent-Signature", hex.EncodeToString(mac.Sum(nil)))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var reply map[string]any
	_ = json.Unmarshal(b, &reply)
	return res, reply
}

// The quarantine report is kept (memory only, out of the cached push) only
// from a push that came over TLS, and the device list shows it.
func TestIngestKeepsTheQuarantineOnlyOverTLS(t *testing.T) {
	quarantinestate.Default = quarantinestate.New()
	t.Cleanup(func() { quarantinestate.Default = quarantinestate.New() })
	ts := makeAgentTestServer(t)
	_, token, _ := createAgentToken(t, ts, "patio")
	now := time.Now().Unix()
	section := `"fdb":{"macs":{}},"quarantine":{"enabled":true,"devices":[` +
		`{"mac":"02:00:00:00:00:0a","state":"approved","report":"alert"},` +
		`{"mac":"02:00:00:00:00:0b","state":"waiting"}]}`

	res, _ := ingestOver(t, ts, token, strings.Replace(validPayload(now), `"fdb":{"macs":{}}`, section, 1), false)
	if res.StatusCode/100 != 2 {
		t.Fatalf("ingest: %d", res.StatusCode)
	}
	if _, ok := quarantinestate.Default.Lookup("02:00:00:00:00:0b"); ok {
		t.Fatal("a push over plain HTTP reached the quarantine store")
	}

	res, reply := ingestOver(t, ts, token, strings.Replace(validPayload(now+1), `"fdb":{"macs":{}}`, section, 1), true)
	if res.StatusCode/100 != 2 || reply["ok"] != true {
		t.Fatalf("ingest: %d %v", res.StatusCode, reply)
	}
	if _, ok := reply["stations"]; ok {
		t.Fatalf("stations without a UniFi controller: %v", reply)
	}
	p, ok := ts.agents.Fresh("patio")
	if !ok || p.Data.Quarantine != nil {
		t.Fatal("the quarantine stayed in the cached push")
	}
	if st, ok := quarantinestate.Default.Lookup("02:00:00:00:00:0B"); !ok || st.State != "waiting" || st.Router != "patio" {
		t.Fatalf("waiting device: %+v %v", st, ok)
	}
	// The list is served over HTTPS only.
	for _, secure := range []bool{false, true} {
		req, _ := http.NewRequest("GET", ts.URL+"/api/quarantine", nil)
		req.Header.Set("Cookie", "session="+ts.cookie)
		if secure {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Secure  bool                    `json:"secure"`
			Devices []quarantinestate.Entry `json:"devices"`
		}
		_ = json.NewDecoder(res.Body).Decode(&out)
		res.Body.Close()
		if res.StatusCode != 200 || out.Secure != secure {
			t.Fatalf("secure=%v: %d %+v", secure, res.StatusCode, out)
		}
		if !secure && len(out.Devices) != 0 {
			t.Fatalf("the trusted list went out over plain HTTP: %+v", out.Devices)
		}
		if secure && (len(out.Devices) != 2 || out.Devices[0] != (quarantinestate.Entry{MAC: "02:00:00:00:00:0a", Router: "patio", State: "approved", Report: "alert"})) {
			t.Fatalf("list: %+v", out.Devices)
		}
	}

	// Turning the quarantine off clears what is shown.
	res, _ = ingestOver(t, ts, token, strings.Replace(validPayload(now+2), `"fdb":{"macs":{}}`, `"fdb":{"macs":{}},"quarantine":{"enabled":false}`, 1), true)
	if res.StatusCode/100 != 2 {
		t.Fatalf("ingest: %d", res.StatusCode)
	}
	if _, ok := quarantinestate.Default.Lookup("02:00:00:00:00:0b"); ok {
		t.Fatal("the quarantine was turned off and is still shown")
	}
}
