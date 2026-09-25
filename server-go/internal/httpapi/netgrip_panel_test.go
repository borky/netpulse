package httpapi

// FORK: tests for netgrip_panel.go, a fork-only file. Addresses are from the
// documentation ranges and names are invented.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
	"github.com/gnacho/netpulse/server-go/internal/adapters"
	"github.com/gnacho/netpulse/server-go/internal/db"
)

func spkiOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func splitHostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// A panel on HTTPS whose agent reported the key it serves is reached over TLS,
// and the connection is accepted because the key matches.
func TestPanelTargetPinsTheReportedKey(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	scheme, addr, client, err := netgripPanelTarget(host,
		netgripPanel{Port: port, TLS: true, SPKI: spkiOf(t, srv)}, freshReport, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if scheme != "https" {
		t.Fatalf("scheme = %q, want https for a panel serving TLS", scheme)
	}
	resp, err := client.Get(scheme + "://" + addr + "/")
	if err != nil {
		t.Fatalf("the pinned connection to the right key failed: %v", err)
	}
	resp.Body.Close()
}

// The same panel presenting a different key is refused before any request is
// sent: this is what stops the executor token going to whoever answers.
//
// The other key is generated here, not taken from a second httptest server:
// every httptest TLS server shares one built-in certificate, so an earlier
// version of this test compared a key with itself and passed while proving
// nothing.
func TestPanelTargetRefusesAnotherKey(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	otherSPKI := hex.EncodeToString(sum[:])
	if otherSPKI == spkiOf(t, srv) {
		t.Fatal("the two keys are the same; this test would prove nothing")
	}

	_, addr, client, err := netgripPanelTarget(host,
		netgripPanel{Port: port, TLS: true, SPKI: otherSPKI}, freshReport, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get("https://" + addr + "/"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a certificate with a different key must be refused, got err=%v", err)
	}
}

// HTTPS without a key to pin gets nothing. Falling back to skipping
// verification would encrypt the token toward an unauthenticated panel.
func TestPanelTargetNeverSendsTheTokenUnpinned(t *testing.T) {
	_, _, client, err := netgripPanelTarget("192.0.2.1",
		netgripPanel{Port: 8090, TLS: true}, freshReport, 5*time.Second)
	if err == nil || client != nil {
		t.Fatal("a panel on HTTPS with no reported key must not get a client at all")
	}
}

// Over plain HTTP the reported port is used. The old code assumed 8080, while
// NetGrip has defaulted to 8090 since upstream #210.
func TestPanelTargetUsesTheReportedPort(t *testing.T) {
	scheme, addr, _, err := netgripPanelTarget("192.0.2.1",
		netgripPanel{Port: 8090}, freshReport, 5*time.Second)
	if err != nil || scheme != "http" || addr != "192.0.2.1:8090" {
		t.Fatalf("got %s://%s err=%v, want http://192.0.2.1:8090", scheme, addr, err)
	}
}

// An agent that reports nothing about its panel - one that predates these
// fields - is addressed exactly as before.
func TestPanelTargetKeepsUpstreamBehaviourForOlderAgents(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"192.0.2.1", "192.0.2.1:8080"},
		{"192.0.2.1:9000", "192.0.2.1:9000"},
	} {
		scheme, addr, _, err := netgripPanelTarget(tc.host, netgripPanel{}, freshReport, 5*time.Second)
		if err != nil || scheme != "http" || addr != tc.want {
			t.Errorf("host %s: got %s://%s err=%v, want http://%s", tc.host, scheme, addr, err, tc.want)
		}
	}
}

// An agent that has reported, but not recently, may be behind a change of
// scheme: nothing is sent until it reports again.
func TestPanelTargetSendsNothingOnAStaleReport(t *testing.T) {
	if _, _, client, err := netgripPanelTarget("192.0.2.1", netgripPanel{}, staleReport, 5*time.Second); err == nil || client != nil {
		t.Fatal("with a stale report from the router's agent, no client may be built")
	}
}

// A router whose agent has never reported is upstream's case - a token and an
// address, nothing more - and keeps upstream's addressing. Upstream's own
// delegation tests depend on it.
func TestPanelTargetKeepsUpstreamBehaviourWithNoAgent(t *testing.T) {
	scheme, addr, client, err := netgripPanelTarget("192.0.2.1", netgripPanel{}, noAgent, 5*time.Second)
	if err != nil || client == nil || scheme != "http" || addr != "192.0.2.1:8080" {
		t.Fatalf("got %s://%s err=%v, want upstream's http://192.0.2.1:8080", scheme, addr, err)
	}
}

// A pinned panel answering with a redirect to plain http must not receive the
// token a second time, in clear.
func TestPanelTargetDoesNotFollowRedirects(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { plainHits.Add(1) }))
	defer plain.Close()
	panel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/api/executor/apply", http.StatusTemporaryRedirect)
	}))
	defer panel.Close()
	host, port := splitHostPort(t, panel.URL)

	_, addr, client, err := netgripPanelTarget(host,
		netgripPanel{Port: port, TLS: true, SPKI: spkiOf(t, panel)}, freshReport, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/api/executor/apply", nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if plainHits.Load() != 0 {
		t.Fatal("the redirect was followed: the token went to a plain-http address")
	}
}

// panelTestServer is the minimum netgripPanelOf and applyViaNetGrip read: a
// database and the agent registry.
func panelTestServer(t *testing.T) *server {
	t.Helper()
	d, err := db.Open(t.TempDir())
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return &server{db: d, agents: adapters.NewAgentRegistry(90 * time.Second)}
}

func addPanelRouter(t *testing.T, s *server, id, name, host string) {
	t.Helper()
	if _, err := s.db.Exec("INSERT INTO routers (id, name, host, type, is_gateway, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, name, host, "openwrt", 1, time.Now().Unix()); err != nil {
		t.Fatalf("router: %v", err)
	}
}

func addPanelAgent(t *testing.T, s *server, slug, hostname string, port int, tlsOn bool, spki string) {
	t.Helper()
	if _, err := s.db.Exec("INSERT INTO kv (key, value) VALUES (?, ?)", agentTokenKey(slug), "unused-hash"); err != nil {
		t.Fatalf("agent token: %v", err)
	}
	s.agents.Ingest(&probe.Payload{
		Router: slug, Ts: time.Now().Unix(), Version: "test", Kind: "netgrip",
		PanelPort: port, PanelTLS: tlsOn, PanelSPKI: spki,
		Data: probe.PayloadData{System: &probe.SystemData{Board: &probe.BoardInfo{Hostname: hostname}}},
	})
}

// The report comes from the router's own agent: the one whose slug is the
// router id, which is also the id the executor token is stored under.
func TestPanelOfUsesTheRoutersOwnAgent(t *testing.T) {
	s := panelTestServer(t)
	addPanelRouter(t, s, "gw", "router-a", "192.0.2.1")
	addPanelAgent(t, s, "gw", "router-a", 8443, true, "ab12")

	p, r := s.netgripPanelOf("gw")
	if r != freshReport || p.Port != 8443 || !p.TLS || p.SPKI != "ab12" {
		t.Fatalf("got %+v report=%v, want the agent's fresh report", p, r)
	}
	if _, r := s.netgripPanelOf("some-other-router"); r != noAgent {
		t.Errorf("a router with no agent must be noAgent, got %v", r)
	}
}

// The attack a review demonstrated: a second agent claiming the router's host
// name reported "plain HTTP" and, being matched first, got the token sent in
// clear to an HTTPS panel. Another agent's report must not count, whatever it
// claims to be.
func TestPanelOfIgnoresOtherAgentsClaimingTheRouter(t *testing.T) {
	s := panelTestServer(t)
	addPanelRouter(t, s, "gw", "router-a", "192.0.2.1")
	addPanelAgent(t, s, "aaa-impostor", "router-a", 8090, false, "")
	addPanelAgent(t, s, "gw", "router-a", 8090, true, "ab12")

	p, r := s.netgripPanelOf("gw")
	if r != freshReport || !p.TLS || p.SPKI != "ab12" {
		t.Fatalf("got %+v report=%v; another agent's report was used for this router", p, r)
	}
}

// A report that is no longer fresh is not trusted: the panel may have changed
// scheme since, and acting on the old one could send the token in clear. The
// registry's own clock moves time on, so the test does not depend on sleeping.
func TestPanelOfDistrustsAStaleReport(t *testing.T) {
	s := panelTestServer(t)
	now := time.Now()
	s.agents.SetClock(func() time.Time { return now })
	addPanelRouter(t, s, "gw", "router-a", "192.0.2.1")
	addPanelAgent(t, s, "gw", "router-a", 8090, false, "")
	now = now.Add(time.Hour)

	if _, r := s.netgripPanelOf("gw"); r != staleReport {
		t.Fatalf("a report an hour old gave %v, want staleReport", r)
	}
}

// Revoking or uninstalling an agent forgets its report in memory but leaves
// its persisted state and the executor token behind. That router has had an
// agent, so it is stale - not upstream's no-agent case, which sent the token
// to the next plan in clear. A review demonstrated it.
func TestPanelOfTreatsARevokedAgentAsStale(t *testing.T) {
	s := panelTestServer(t)
	addPanelRouter(t, s, "gw", "router-a", "192.0.2.1")
	if _, err := s.db.Exec("INSERT INTO kv (key, value) VALUES (?, ?)", agentStateKey("gw"), `{"payload":{}}`); err != nil {
		t.Fatal(err)
	}
	if _, r := s.netgripPanelOf("gw"); r != staleReport {
		t.Fatalf("a router whose agent was revoked gave %v, want staleReport", r)
	}
}

// Every client sent to the panel carries one request and keeps nothing open:
// a kept connection with no idle timeout on either side, one per plan, leaked
// a goroutine per call.
func TestPanelTargetKeepsNoConnectionOpen(t *testing.T) {
	for _, tc := range []netgripPanel{{Port: 8090}, {Port: 8090, TLS: true, SPKI: "ab12"}} {
		_, _, client, err := netgripPanelTarget("192.0.2.1", tc, freshReport, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		tr, ok := client.Transport.(*http.Transport)
		if !ok || !tr.DisableKeepAlives {
			t.Errorf("tls=%v: the client would keep its connection to the panel open", tc.TLS)
		}
	}
}

// End to end, through the real applyViaNetGrip: the executor token reaches a
// panel whose key matches what its agent reported, and never reaches one that
// presents another key.
func TestApplyViaNetGripDeliversTheTokenOnlyToThePinnedPanel(t *testing.T) {
	var gotToken atomic.Value
	panel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/executor/apply" {
			http.NotFound(w, r)
			return
		}
		gotToken.Store(r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer panel.Close()
	host, port := splitHostPort(t, panel.URL)

	for _, tc := range []struct {
		name      string
		spki      string
		wantApply bool
	}{
		{"the reported key", spkiOf(t, panel), true},
		{"a different key", strings.Repeat("0", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotToken.Store("")
			s := panelTestServer(t)
			addPanelRouter(t, s, "gw", "router-a", host)
			// An impostor claiming the router's host name and plain HTTP,
			// listed before the real agent: it must change nothing.
			addPanelAgent(t, s, "aaa-impostor", "router-a", port, false, "")
			addPanelAgent(t, s, "gw", "router-a", port, true, tc.spki)
			if _, err := s.db.Exec("INSERT INTO kv (key, value) VALUES (?, ?)",
				"netgrip.executor_token.gw", "exec-token-for-test"); err != nil {
				t.Fatal(err)
			}

			ok, err := s.applyViaNetGrip("gw", "plan-1", nil)
			if err != nil {
				t.Fatalf("applyViaNetGrip: %v", err)
			}
			if ok != tc.wantApply {
				t.Fatalf("applied = %v, want %v", ok, tc.wantApply)
			}
			delivered := gotToken.Load().(string) != ""
			if delivered != tc.wantApply {
				t.Fatalf("token delivered = %v, want %v", delivered, tc.wantApply)
			}
		})
	}
}

// End to end, the case a review demonstrated: an agent that had reported
// HTTPS is revoked, its report forgotten but still persisted, and a plan is
// applied. The token must not go out. The same setup with no persisted report
// - upstream's case - still delivers, which shows the harness reaches the
// panel and the refusal is not an accident.
func TestApplyViaNetGripAfterTheAgentIsRevoked(t *testing.T) {
	for _, tc := range []struct {
		name          string
		persisted     bool
		wantDelivered bool
	}{
		{"never had an agent: upstream behaviour", false, true},
		{"agent revoked, report persisted", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got atomic.Value
			got.Store("")
			panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got.Store(r.Header.Get("Authorization"))
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
			}))
			defer panel.Close()

			s := panelTestServer(t)
			// Addressed the way upstream's own delegation tests address a
			// panel: the router's host carries the panel's port.
			addPanelRouter(t, s, "gw", "router-a", panel.Listener.Addr().String())
			if _, err := s.db.Exec("INSERT INTO kv (key, value) VALUES (?, ?)",
				"netgrip.executor_token.gw", "exec-token-for-test"); err != nil {
				t.Fatal(err)
			}
			if tc.persisted {
				if _, err := s.db.Exec("INSERT INTO kv (key, value) VALUES (?, ?)",
					agentStateKey("gw"), `{"payload":{"panelTls":true,"panelSpki":"ab12"}}`); err != nil {
					t.Fatal(err)
				}
			}

			if _, err := s.applyViaNetGrip("gw", "plan-1", nil); err != nil {
				t.Fatalf("applyViaNetGrip: %v", err)
			}
			if delivered := got.Load().(string) != ""; delivered != tc.wantDelivered {
				t.Fatalf("token delivered = %v, want %v", delivered, tc.wantDelivered)
			}
		})
	}
}

// A stored address that already carries a port takes the reported one instead.
func TestPanelTargetReplacesAStoredPort(t *testing.T) {
	_, addr, _, err := netgripPanelTarget("192.0.2.1:22", netgripPanel{Port: 8090}, freshReport, 5*time.Second)
	if err != nil || addr != "192.0.2.1:8090" {
		t.Fatalf("got %q err=%v, want 192.0.2.1:8090", addr, err)
	}
}

// Doubt never sends anything: when the persisted state cannot be read at all,
// the router counts as stale, not as one that never had an agent.
func TestPanelOfTreatsAFailedLookupAsStale(t *testing.T) {
	s := panelTestServer(t)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, r := s.netgripPanelOf("gw"); r != staleReport {
		t.Fatalf("with the database unreadable, got %v, want staleReport", r)
	}
}

// tokenOverSSH answers upstream's executor-token fallback and records whether
// it was asked.
type tokenOverSSH struct{ asked atomic.Bool }

func (f *tokenOverSSH) Run(_, cmd string, _ time.Duration) (string, error) {
	if strings.Contains(cmd, "executor-token") {
		f.asked.Store(true)
		return "exec-token-over-ssh\n", nil
	}
	return "", nil
}

// Upstream's SSH fallback reads the executor token from the router and stores
// it. For a router whose agent has never reported, that would send the token
// over upstream's plain-http path, and every later plan too, once it is
// stored. So the fallback runs only for a router with a report, whose token
// then goes through the pinned path; with a report it still works.
func TestTheSSHTokenFallbackNeedsAnAgentReport(t *testing.T) {
	for _, tc := range []struct {
		name          string
		agent         bool
		wantDelivered bool
	}{
		{"no agent has reported", false, false},
		{"the router's agent reported", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got atomic.Value
			got.Store("")
			panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got.Store(r.Header.Get("Authorization"))
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
			}))
			defer panel.Close()
			host, port := splitHostPort(t, panel.URL)

			s := panelTestServer(t)
			pool := &tokenOverSSH{}
			s.pool = pool
			if tc.agent {
				addPanelRouter(t, s, "gw", "router-a", host)
				addPanelAgent(t, s, "gw", "router-a", port, false, "")
			} else {
				addPanelRouter(t, s, "gw", "router-a", panel.Listener.Addr().String())
			}

			if _, err := s.applyViaNetGrip("gw", "plan-1", nil); err != nil {
				t.Fatalf("applyViaNetGrip: %v", err)
			}
			if delivered := got.Load().(string) != ""; delivered != tc.wantDelivered {
				t.Fatalf("token delivered = %v, want %v", delivered, tc.wantDelivered)
			}
			if pool.asked.Load() != tc.agent {
				t.Fatalf("SSH fallback asked = %v, want %v", pool.asked.Load(), tc.agent)
			}
		})
	}
}
