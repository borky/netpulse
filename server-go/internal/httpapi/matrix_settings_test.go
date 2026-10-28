package httpapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const (
	mxRoom  = "!dummyRoomId"
	mxToken = "syt_dummy_token"
	mxUser  = "@netpulse-bot:example.org"
)

// fakeHomeserver answers whoami, joined_members and send for mxToken only,
// and records the send calls it got.
func fakeHomeserver(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var sends []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+mxToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"errcode":"M_UNKNOWN_TOKEN","error":"unknown token"}`)
			return
		}
		p := r.URL.EscapedPath()
		switch {
		case p == "/_matrix/client/v3/account/whoami":
			_, _ = io.WriteString(w, `{"user_id":"`+mxUser+`"}`)
		case p == "/_matrix/client/v3/rooms/%21dummyRoomId/joined_members":
			_, _ = io.WriteString(w, `{"joined":{"`+mxUser+`":{}}}`)
		case r.Method == http.MethodPut && strings.HasPrefix(p, "/_matrix/client/v3/rooms/%21dummyRoomId/send/m.room.message/"):
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			sends = append(sends, string(b))
			mu.Unlock()
			_, _ = io.WriteString(w, `{"event_id":"$e"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), sends...)
	}
}

func TestMatrixSettingsFlow(t *testing.T) {
	hs, sends := fakeHomeserver(t)
	srv := makeTestServer(t)
	_, cookie, _ := loginCookie(t, srv.URL, "admin", "test123456")
	if cookie == "" {
		t.Fatal("login returned no cookie")
	}

	res, body := wanSpeedRequest(t, "GET", srv.URL, "/api/settings/matrix", cookie, "")
	if res.StatusCode != http.StatusOK || body["tokenSet"] != false || body["server"] != "" {
		t.Fatalf("empty GET: %d %v", res.StatusCode, body)
	}

	res, body = wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/matrix", cookie,
		`{"server":"`+hs.URL+`/","roomId":"`+mxRoom+`","token":"`+mxToken+`","enabled":true,"urgentOnly":false}`)
	if res.StatusCode != http.StatusOK || body["userId"] != mxUser {
		t.Fatalf("PUT: %d %v", res.StatusCode, body)
	}

	// Nothing sensitive in the clear in the database.
	rows, err := srv.db.Query("SELECT key, value FROM kv WHERE key LIKE 'matrix.%'")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for rows.Next() {
		var k, v string
		_ = rows.Scan(&k, &v)
		seen++
		for _, secret := range []string{mxToken, "dummyRoomId", strings.TrimPrefix(hs.URL, "http://")} {
			if strings.Contains(v, secret) {
				t.Errorf("kv %s holds %q in the clear", k, secret)
			}
		}
	}
	rows.Close()
	if seen < 3 {
		t.Fatalf("only %d matrix kv rows written", seen)
	}

	res, body = wanSpeedRequest(t, "GET", srv.URL, "/api/settings/matrix", cookie, "")
	if res.StatusCode != http.StatusOK || body["server"] != hs.URL || body["roomId"] != mxRoom ||
		body["tokenSet"] != true || body["enabled"] != true || body["urgentOnly"] != false {
		t.Fatalf("GET after save: %v", body)
	}
	if _, leaked := body["token"]; leaked {
		t.Fatalf("GET returned the token: %v", body)
	}

	// A blank token keeps the stored one (validation still passes).
	res, body = wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/matrix", cookie, `{"enabled":true,"urgentOnly":true}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PUT keeping the token: %d %v", res.StatusCode, body)
	}

	res, _ = wanSpeedRequest(t, "POST", srv.URL, "/api/settings/matrix/test", cookie, "")
	if res.StatusCode != http.StatusOK || len(sends()) != 1 {
		t.Fatalf("test send: %d, sends %v", res.StatusCode, sends())
	}

	// A token the homeserver refuses is not stored.
	res, _ = wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/matrix", cookie, `{"token":"syt_wrong","enabled":true}`)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad token PUT: %d", res.StatusCode)
	}
	res, _ = wanSpeedRequest(t, "POST", srv.URL, "/api/settings/matrix/test", cookie, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the refused token replaced the good one: test send %d", res.StatusCode)
	}

	// Pointing the channel at another homeserver without retyping the token
	// is refused before that server is contacted.
	var otherHits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { otherHits++ }))
	defer other.Close()
	res, body = wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/matrix", cookie, `{"server":"`+other.URL+`","enabled":true}`)
	if res.StatusCode != http.StatusBadRequest || otherHits != 0 {
		t.Fatalf("server change without token: %d %v, other server hit %d times", res.StatusCode, body, otherHits)
	}

	res, _ = wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/matrix", cookie, `{"clear":true}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("clear: %d", res.StatusCode)
	}
	_, body = wanSpeedRequest(t, "GET", srv.URL, "/api/settings/matrix", cookie, "")
	if body["tokenSet"] != false || body["server"] != "" || body["roomId"] != "" || body["enabled"] != false {
		t.Fatalf("GET after clear: %v", body)
	}
}

func TestMatrixSettingsRejectsBadInput(t *testing.T) {
	srv := makeTestServer(t)
	_, cookie, _ := loginCookie(t, srv.URL, "admin", "test123456")
	for name, payload := range map[string]string{
		"alias":     `{"server":"https://matrix.example.org","roomId":"#room:example.org","token":"syt_x","enabled":true}`,
		"no scheme": `{"server":"matrix.example.org","roomId":"!x","token":"syt_x","enabled":true}`,
		"no token":  `{"server":"https://matrix.example.org","roomId":"!x","enabled":true}`,
	} {
		res, _ := wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/matrix", cookie, payload)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, res.StatusCode)
		}
	}
}

func TestMatrixSettingsNeedAdmin(t *testing.T) {
	srv := makeTestServer(t)
	res, _ := wanSpeedRequest(t, "GET", srv.URL, "/api/settings/matrix", "", "")
	if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
		t.Fatalf("anonymous GET: %d", res.StatusCode)
	}
}

func TestIntegrationsMatrixToggleMirrorsEnabled(t *testing.T) {
	srv := makeTestServer(t)
	_, cookie, _ := loginCookie(t, srv.URL, "admin", "test123456")
	_, body := wanSpeedRequest(t, "GET", srv.URL, "/api/settings/integrations", cookie, "")
	if body["matrix"] != true {
		t.Fatalf("matrix must default on like the other channels: %v", body)
	}
	res, body := wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/integrations", cookie, `{"matrix":false}`)
	if res.StatusCode != http.StatusOK || body["matrix"] != false || body["ntfy"] != true {
		t.Fatalf("PUT matrix=false: %d %v", res.StatusCode, body)
	}
	var v string
	if err := srv.db.QueryRow("SELECT value FROM kv WHERE key = 'matrix.enabled'").Scan(&v); err != nil || v != "false" {
		t.Fatalf("matrix.enabled mirror = %q, %v", v, err)
	}
}
