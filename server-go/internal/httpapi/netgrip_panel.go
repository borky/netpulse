package httpapi

// FORK: this file exists only in the fork, so the change to upstream's
// orchestr.go stays at its single call site.
//
// When a router has a NetGrip executor token, applyViaNetGrip hands the plan's
// operations to the panel's /api/executor/apply with that token attached. It
// used to address the panel as http://<host>:8080 unconditionally. Both halves
// of that were wrong once the panel could serve HTTPS:
//
//   - the port: NetGrip has defaulted to 8090 since upstream #210, and the
//     embedded agent reports the real one (PanelPort) on every push;
//   - the scheme: a panel serving TLS refuses a plaintext request - and the
//     request, token included, has already crossed the network in clear by
//     the time it is refused.
//
// The panel's certificate is self-signed, so it cannot be verified by name,
// and skipping verification would only encrypt the token toward whoever
// answers on the LAN. Instead the connection is pinned to the key the agent
// reports (PanelSPKI): the SPKI of the certificate the panel is serving.
//
// What that pin is worth depends on how the agent reaches this server. With
// the agent on https and pinning this server's key (NETPULSE_SERVER_FP), the
// report cannot be altered in transit and the pin is sound. With the agent on
// plain http, the push is not protected - its signature is keyed with the
// token it carries, so anyone who reads a push can forge one - and an attacker
// on that path could substitute the key. They gain nothing by it, though: on
// that same path the executor token already crosses in clear, in the agent's
// backup uploads. Pinning protects this connection from a passive listener
// either way, and fully once the agent channel is on https.
//
// Every doubtful case sends nothing: a report from the router's own agent that
// is no longer fresh, or a panel on HTTPS with no key to pin. A router whose
// agent has never reported keeps upstream's behaviour, but without the SSH
// token fallback (see netgripTokenFor). The plan then falls back to the
// agent's own channel, exactly as when the panel does not answer.

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// netgripPanel is what a router's embedded agent reports about its panel.
type netgripPanel struct {
	Port int
	TLS  bool
	SPKI string // hex SHA-256 of the served certificate's SubjectPublicKeyInfo
}

// panelReport says how much the router's own agent has told us.
type panelReport int

const (
	// noAgent: no agent for this router has ever reported. This is
	// upstream's case - an executor token and a router address, nothing
	// more - and it keeps upstream's addressing, which upstream's own tests
	// rely on.
	noAgent panelReport = iota
	// freshReport: the agent reported recently; use what it said.
	freshReport
	// staleReport: the agent has reported, but not recently - or has been
	// revoked since, with its report still persisted. The panel may have
	// changed scheme since, so nothing is sent. Reports are persisted and
	// restored at start-up, so this also covers the window after a restart
	// of this server, until the agent's next push.
	staleReport
)

// netgripPanelOf returns what the router's own agent last said about its
// panel, and how far to trust it.
//
// "The router's own agent" is exactly the agent whose slug is routerID. The
// executor token is stored under the id of the agent that authenticated its
// upload, so that is the only report that speaks for this token. An earlier
// version matched agents the way the agents list does - by host name or MAC
// as well - and took the first; a second agent claiming the same host name
// could then report "plain HTTP" for an HTTPS panel and get the token sent in
// clear.
func (s *server) netgripPanelOf(routerID string) (netgripPanel, panelReport) {
	if s.agents == nil {
		return netgripPanel{}, noAgent
	}
	st := s.agents.Snapshot(routerID)
	if st == nil || st.Payload == nil {
		// No report in memory. That is not the same as no agent: revoking
		// or uninstalling an agent forgets its report but leaves both its
		// persisted state and the executor token behind, and treating that
		// as upstream's no-agent case sent the token to the next plan in
		// clear. Only a router with no report anywhere is noAgent; a failed
		// lookup counts as stale, so doubt never sends anything.
		return netgripPanel{}, s.persistedPanelReport(routerID)
	}
	p, fresh := s.agents.Fresh(routerID)
	if !fresh || p == nil {
		return netgripPanel{}, staleReport
	}
	return netgripPanel{Port: p.PanelPort, TLS: p.PanelTLS, SPKI: strings.ToLower(p.PanelSPKI)}, freshReport
}

// persistedPanelReport says whether an agent for routerID has ever reported,
// judging by the state this server persists on every push. It runs after the
// caller's own query has closed; the database has a single connection and a
// query issued while another's rows are open waits forever.
func (s *server) persistedPanelReport(routerID string) panelReport {
	if s.db == nil {
		return noAgent
	}
	var raw string
	switch err := s.db.QueryRow("SELECT value FROM kv WHERE key = ?", agentStateKey(routerID)).Scan(&raw); {
	case err == nil:
		return staleReport
	case errors.Is(err, sql.ErrNoRows):
		return noAgent
	default:
		return staleReport
	}
}

// netgripTokenFor is the executor token to send to routerID's panel, given
// what its agent has reported.
//
// Upstream's netgripExecutorToken falls back to reading the token over SSH,
// and stores what it reads. For a router whose agent has never reported, that
// fallback would put a token on upstream's plain-http path that nothing put
// there before: every other way a token is stored comes from an agent, which
// leaves a report behind. So a router with no report gets only a token that
// was already stored, as before the fallback existed, and a router with a
// report gets the fallback too, since its token then goes through the pinned
// path. Once stored, a token fetched over SSH looks like any other, which is
// why the check is on the report and not on where the token came from.
func (s *server) netgripTokenFor(routerID string, report panelReport) string {
	if report != noAgent {
		return s.netgripExecutorToken(routerID)
	}
	if s.db == nil {
		return ""
	}
	var token string
	_ = s.db.QueryRow("SELECT value FROM kv WHERE key = ?", "netgrip.executor_token."+routerID).Scan(&token)
	return token
}

// netgripPanelTarget is the scheme, address and client for a request to the
// panel on host, or an error saying why nothing should be sent.
//
// A router with no agent, or with an agent that reports nothing about its
// panel - one that predates these fields - keeps upstream's original
// addressing, so it is treated exactly as before.
func netgripPanelTarget(host string, p netgripPanel, report panelReport, timeout time.Duration) (scheme, addr string, client *http.Client, err error) {
	if report == staleReport {
		return "", "", nil, errors.New("this router's agent has not reported recently, and its panel may have " +
			"changed scheme since; not sending the executor token until it does")
	}
	addr = host
	switch {
	case p.Port > 0:
		// The reported port replaces any the stored address carries, rather
		// than being appended to it: "host:port" joined again with a port is
		// not an address, and the apply then failed outright instead of
		// falling back to the agent's channel.
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		addr = net.JoinHostPort(host, fmt.Sprint(p.Port))
	case !strings.Contains(addr, ":"):
		addr += ":8080" // upstream's default, for agents that report no port
	}
	transport := &http.Transport{
		// One request per plan. Keeping the connection would hold it open
		// indefinitely: neither this transport nor the panel's server has an
		// idle timeout, and a new transport is built for every call.
		DisableKeepAlives: true,
	}
	client = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Never follow a redirect with the token on it: a pinned panel that
		// answered 307 to a plain-http address would otherwise receive the
		// token again, in clear. NetGrip never redirects this endpoint.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if !p.TLS {
		return "http", addr, client, nil
	}
	if p.SPKI == "" {
		return "", "", nil, errors.New("the panel serves HTTPS but its agent reported no certificate key to pin; " +
			"not sending the executor token to a panel that cannot be authenticated")
	}
	want := p.SPKI
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The name check is replaced, not dropped: the self-signed
		// certificate names the router by host name or not at all, so the
		// only meaningful check is the key the agent reported.
		InsecureSkipVerify: true, //nolint:gosec // verified by the pin below
		// VerifyConnection rather than VerifyPeerCertificate: it also runs on
		// resumed sessions, so adding a session cache later cannot let a
		// connection skip the pin.
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPanelSPKI(cs, want)
		},
	}
	return "https", addr, client, nil
}

// verifyPanelSPKI accepts the connection only if the leaf certificate's key is
// the one the agent reported. The handshake has already proved the peer holds
// that certificate's private key.
func verifyPanelSPKI(cs tls.ConnectionState, wantHex string) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("netgrip panel presented no certificate")
	}
	sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
	got := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(wantHex)) != 1 {
		return fmt.Errorf("netgrip panel certificate key %s does not match the one its agent reported", got[:16])
	}
	return nil
}
