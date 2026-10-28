package matrix

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/alerts"
	"github.com/gnacho/netpulse/server-go/internal/kvseal"
)

const (
	testRoom  = "!dummyRoomId"
	testToken = "syt_dummy_token"
	testUser  = "@netpulse-bot:example.org"
)

type fakeKV struct {
	mu sync.Mutex
	m  map[string]string
}

func (f *fakeKV) Get(key string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	return v, ok
}

func (f *fakeKV) Set(key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]string{}
	}
	f.m[key] = value
	return nil
}

func newSealer(t *testing.T) *kvseal.Sealer {
	t.Helper()
	s, err := kvseal.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testNotifier(srv *httptest.Server) *Notifier {
	n := newNotifier(nil, nil)
	n.client = srv.Client()
	return n
}

func TestSendPutsToTheRoomWithTheToken(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotType string
	var got message
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.EscapedPath()
		gotAuth, gotType = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, `{"event_id":"$e"}`)
	}))
	defer srv.Close()

	n := testNotifier(srv)
	defer n.Close()
	cfg := Config{Server: srv.URL, RoomID: testRoom, Token: testToken}
	if err := n.send(cfg, "txn-1", message{MsgType: "m.text", Body: "Router: WAN down"}); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %s", gotMethod)
	}
	if want := "/_matrix/client/v3/rooms/%21dummyRoomId/send/m.room.message/txn-1"; gotPath != want {
		t.Errorf("path = %s, want %s", gotPath, want)
	}
	if gotAuth != "Bearer "+testToken || gotType != "application/json" {
		t.Errorf("headers = %q / %q", gotAuth, gotType)
	}
	if got.MsgType != "m.text" || got.Body != "Router: WAN down" {
		t.Errorf("content = %+v", got)
	}
}

func TestRoomIDWithServerPartIsEscaped(t *testing.T) {
	if got := roomPath("!abc:example.org"); got != "%21abc%3Aexample.org" {
		t.Fatalf("roomPath = %s", got)
	}
}

func TestRetryReusesTheTransactionID(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		n := len(paths)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"errcode":"M_LIMIT_EXCEEDED","error":"slow down","retry_after_ms":10}`)
			return
		}
		_, _ = io.WriteString(w, `{"event_id":"$e"}`)
	}))
	defer srv.Close()

	n := testNotifier(srv)
	defer n.Close()
	cfg := Config{Server: srv.URL, RoomID: testRoom, Token: testToken}
	start := time.Now()
	if err := n.sendWithRetry(cfg, alerts.AlertEvent{Title: "t", Urgent: true}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != paths[1] {
		t.Fatalf("a retry must reuse the transaction id: %v", paths)
	}
	if time.Since(start) > time.Second {
		t.Fatal("retry_after_ms was not honoured")
	}
	if a, b := n.newTxnID(), n.newTxnID(); a == b {
		t.Fatal("two messages got the same transaction id")
	}
}

func TestNoRetryOnForbidden(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"errcode":"M_FORBIDDEN","error":"not in room"}`)
	}))
	defer srv.Close()

	n := testNotifier(srv)
	defer n.Close()
	err := n.sendWithRetry(Config{Server: srv.URL, RoomID: testRoom, Token: testToken}, alerts.AlertEvent{Title: "t"})
	if err == nil || calls != 1 {
		t.Fatalf("err=%v calls=%d, want one call and an error", err, calls)
	}
	if !strings.Contains(err.Error(), "M_FORBIDDEN") {
		t.Errorf("error lost the errcode: %v", err)
	}
}

func TestRetryableClassification(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&apiError{Status: 500}, true},
		{&apiError{Status: 502}, true},
		{&apiError{Status: 429}, true},
		{&apiError{Status: 401}, false},
		{&apiError{Status: 404}, false},
	} {
		if got := isRetryable(c.err); got != c.want {
			t.Errorf("isRetryable(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestTransportErrorHidesTheRoomID(t *testing.T) {
	n := newNotifier(nil, nil)
	defer n.Close()
	// Port 1 on loopback: nothing listens there, the dial fails at once.
	err := n.send(Config{Server: "http://127.0.0.1:1", RoomID: testRoom, Token: testToken}, "txn", message{MsgType: "m.text", Body: "x"})
	if err == nil {
		t.Fatal("expected a dial error")
	}
	if strings.Contains(err.Error(), "dummyRoomId") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("error leaks the room id or token: %v", err)
	}
	if !isRetryable(err) {
		t.Errorf("connection refused should be retryable: %v", err)
	}
}

func TestBuildMessage(t *testing.T) {
	urgent := buildMessage(alerts.AlertEvent{Title: "WAN <down>", Description: "a & b", RouterID: "rt-test", Urgent: true, Ts: 1})
	if urgent.MsgType != "m.text" {
		t.Errorf("urgent msgtype = %s", urgent.MsgType)
	}
	if !strings.Contains(urgent.Body, "WAN <down>") || !strings.Contains(urgent.Body, "rt-test") {
		t.Errorf("plain body = %q", urgent.Body)
	}
	if urgent.Format != "org.matrix.custom.html" || !strings.Contains(urgent.FormattedBody, "<b>WAN &lt;down&gt;</b>") || !strings.Contains(urgent.FormattedBody, "a &amp; b") {
		t.Errorf("html body not escaped: %q", urgent.FormattedBody)
	}
	if quiet := buildMessage(alerts.AlertEvent{Title: "t", Ts: 1}); quiet.MsgType != "m.notice" {
		t.Errorf("non-urgent msgtype = %s, want m.notice", quiet.MsgType)
	}
	long := buildMessage(alerts.AlertEvent{Title: strings.Repeat("é", 5000), Ts: 1})
	if len(long.Body) > maxMsgLen || long.FormattedBody != "" {
		t.Errorf("long message: body %d bytes, html kept=%v", len(long.Body), long.FormattedBody != "")
	}
}

func TestConfigIsStoredSealed(t *testing.T) {
	kv := &fakeKV{}
	s := newSealer(t)
	in := Config{Server: "https://matrix.example.org/", RoomID: testRoom, Token: testToken, Enabled: true, UrgentOnly: false}
	if err := SaveConfig(kv, s, in); err != nil {
		t.Fatal(err)
	}
	for key, v := range kv.m {
		for _, secret := range []string{"matrix.example.org", "dummyRoomId", testToken} {
			if strings.Contains(v, secret) {
				t.Fatalf("kv %s holds %q in the clear: %q", key, secret, v)
			}
		}
	}
	got := LoadConfig(kv, s)
	if got.Server != "https://matrix.example.org" || got.RoomID != testRoom || got.Token != testToken {
		t.Fatalf("round trip = %+v", got)
	}
	if !got.Enabled || got.UrgentOnly || got.Unreadable {
		t.Fatalf("flags = %+v", got)
	}
}

func TestAnotherKeyLeavesTheConfigUnreadable(t *testing.T) {
	kv := &fakeKV{}
	if err := SaveConfig(kv, newSealer(t), Config{Server: "https://matrix.example.org", RoomID: testRoom, Token: testToken, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(kv, newSealer(t))
	if !got.Unreadable || got.Configured() {
		t.Fatalf("a foreign key must yield an unreadable, unconfigured channel: %+v", got)
	}
	if err := SendTest(kv, newSealer(t)); err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("SendTest = %v", err)
	}
}

func TestNormalize(t *testing.T) {
	ok := Config{Server: "https://matrix.example.org", RoomID: testRoom, Token: testToken}
	if _, err := Normalize(ok); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	if _, err := Normalize(Config{}); err != nil {
		t.Fatalf("an empty config (clear) must be valid: %v", err)
	}
	for name, c := range map[string]Config{
		"missing token": {Server: ok.Server, RoomID: ok.RoomID},
		"ftp scheme":    {Server: "ftp://matrix.example.org", RoomID: ok.RoomID, Token: ok.Token},
		"no scheme":     {Server: "matrix.example.org", RoomID: ok.RoomID, Token: ok.Token},
		"credentials":   {Server: "https://user:pass@example.org", RoomID: ok.RoomID, Token: ok.Token},
		"alias":         {Server: ok.Server, RoomID: "#room:example.org", Token: ok.Token},
		"spaced token":  {Server: ok.Server, RoomID: ok.RoomID, Token: "a b"},
	} {
		if _, err := Normalize(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidate(t *testing.T) {
	joined := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"errcode":"M_UNKNOWN_TOKEN","error":"bad"}`)
			return
		}
		switch r.URL.EscapedPath() {
		case "/_matrix/client/v3/account/whoami":
			_, _ = io.WriteString(w, `{"user_id":"`+testUser+`"}`)
		case "/_matrix/client/v3/rooms/%21dummyRoomId/joined_members":
			if !joined {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"errcode":"M_FORBIDDEN","error":"not a member"}`)
				return
			}
			_, _ = io.WriteString(w, `{"joined":{"`+testUser+`":{}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	n := testNotifier(srv)
	defer n.Close()
	cfg := Config{Server: srv.URL, RoomID: testRoom, Token: testToken}
	if user, err := n.validate(cfg); err != nil || user != testUser {
		t.Fatalf("validate = %q, %v", user, err)
	}
	joined = false
	if _, err := n.validate(cfg); err == nil || !strings.Contains(err.Error(), "has not joined") {
		t.Fatalf("not joined: %v", err)
	}
	cfg.Token = "syt_wrong"
	if _, err := n.validate(cfg); err == nil || !strings.Contains(err.Error(), "refused the access token") {
		t.Fatalf("bad token: %v", err)
	}
}

func TestWorkerSendsOnlyWhenEnabledAndConfigured(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		_, _ = io.WriteString(w, `{"event_id":"$e"}`)
	}))
	defer srv.Close()

	kv := &fakeKV{}
	s := newSealer(t)
	if err := SaveConfig(kv, s, Config{Server: srv.URL, RoomID: testRoom, Token: testToken, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	n := newNotifier(kv, s)
	n.client = srv.Client()
	n.wg.Add(1)
	go n.worker()
	// The worker reads the config when it takes an event, so wait for the
	// queue to drain before flipping the switch.
	waitFor := func(cond func() bool) {
		deadline := time.Now().Add(2 * time.Second)
		for !cond() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	n.Notify(alerts.AlertEvent{Title: "while disabled", Urgent: true})
	waitFor(func() bool { return len(n.queue) == 0 })
	time.Sleep(50 * time.Millisecond)
	_ = kv.Set(kvKeyEnabled, "true")
	n.Notify(alerts.AlertEvent{Title: "while enabled", Urgent: true})
	waitFor(func() bool { mu.Lock(); defer mu.Unlock(); return calls >= 1 })
	n.Close()
	n.Close() // idempotent
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (only the event sent while enabled)", calls)
	}
}

func TestPlainHTTPOnlyForLocalHomeservers(t *testing.T) {
	for server, want := range map[string]bool{
		"http://matrix.example.org":  false,
		"http://198.51.100.7:8008":   false,
		"http://localhost:8008":      true,
		"http://127.0.0.1:8008":      true,
		"http://10.0.0.5:8008":       true,
		"https://matrix.example.org": true,
	} {
		_, err := Normalize(Config{Server: server, RoomID: testRoom, Token: testToken})
		if got := err == nil; got != want {
			t.Errorf("%s: accepted=%v, want %v (%v)", server, got, want, err)
		}
	}
}

func TestLogSafeKeepsRoomAndHostOutOfTheJournal(t *testing.T) {
	err := fmt.Errorf("max retries: %w", &apiError{Status: 403, ErrCode: "M_FORBIDDEN", Message: "User @bot:example.org not in room !dummyRoomId:example.org"})
	if got := LogSafe(err); got != "status 403 M_FORBIDDEN" {
		t.Errorf("LogSafe(api) = %q", got)
	}
	n := newNotifier(nil, nil)
	defer n.Close()
	sendErr := n.send(Config{Server: "http://127.0.0.1:1", RoomID: testRoom, Token: testToken}, "txn", message{MsgType: "m.text", Body: "x"})
	if got := LogSafe(sendErr); got != "transport: connection refused" {
		t.Errorf("LogSafe(dial) = %q", got)
	}
	dnsErr := &transportError{err: &net.DNSError{Err: "no such host", Name: "matrix.example.org"}}
	if got := LogSafe(dnsErr); strings.Contains(got, "example.org") || got != "transport: dns lookup failed" {
		t.Errorf("LogSafe(dns) = %q", got)
	}
}

func TestSendTestWithoutSealerNamesTheKeyFile(t *testing.T) {
	err := SendTest(&fakeKV{}, nil)
	if err == nil || !strings.Contains(err.Error(), kvseal.KeyFile) {
		t.Fatalf("SendTest(nil sealer) = %v", err)
	}
}
