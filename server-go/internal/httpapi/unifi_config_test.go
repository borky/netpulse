// unifi_config_test.go — the UniFi settings endpoint, whose one hard rule is
// that the controller password never comes back out.
package httpapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func unifiConfig(t *testing.T, url, cookie string) map[string]any {
	t.Helper()
	res := doReq(t, "GET", url+"/api/config/unifi", cookie, "")
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET config: %d", res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUniFiConfigCRUD(t *testing.T) {
	srv := makeTestServer(t)
	_, cookie, _ := loginCookie(t, srv.URL, "admin", "test123456")

	// Nothing configured yet.
	if got := unifiConfig(t, srv.URL, cookie); got["enabled"] != false || got["passwordSet"] != false {
		t.Fatalf("empty config: %+v", got)
	}

	// Save one.
	res := doReq(t, "PUT", srv.URL+"/api/config/unifi", cookie,
		`{"url":"https://192.0.2.10:8443/","username":"viewer","password":"s3cret","site":"default","insecure":true}`)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PUT: %d %s", res.StatusCode, body)
	}
	// The response is the sanitised view, and the password is not in it.
	if strings.Contains(string(body), "s3cret") {
		t.Fatalf("the password came back: %s", body)
	}

	got := unifiConfig(t, srv.URL, cookie)
	if got["url"] != "https://192.0.2.10:8443" { // trailing slash trimmed
		t.Fatalf("url: %+v", got["url"])
	}
	if got["username"] != "viewer" || got["site"] != "default" || got["insecure"] != true {
		t.Fatalf("config: %+v", got)
	}
	if got["passwordSet"] != true || got["enabled"] != true {
		t.Fatalf("password state: %+v", got)
	}

	// Editing without resending the password keeps it.
	res = doReq(t, "PUT", srv.URL+"/api/config/unifi", cookie,
		`{"url":"https://192.0.2.11:8443","username":"viewer","site":"home"}`)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("PUT edit: %d", res.StatusCode)
	}
	got = unifiConfig(t, srv.URL, cookie)
	if got["url"] != "https://192.0.2.11:8443" || got["site"] != "home" {
		t.Fatalf("edited: %+v", got)
	}
	if got["passwordSet"] != true || got["enabled"] != true {
		t.Fatalf("the stored password should have survived: %+v", got)
	}

	// Delete forgets everything.
	res = doReq(t, "DELETE", srv.URL+"/api/config/unifi", cookie, "")
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE: %d", res.StatusCode)
	}
	if got := unifiConfig(t, srv.URL, cookie); got["enabled"] != false || got["url"] != "" {
		t.Fatalf("after delete: %+v", got)
	}
}

func TestUniFiConfigValidation(t *testing.T) {
	srv := makeTestServer(t)
	_, cookie, _ := loginCookie(t, srv.URL, "admin", "test123456")

	for _, tc := range []struct{ name, body string }{
		{"no url", `{"username":"u","password":"p"}`},
		{"url without scheme", `{"url":"192.0.2.10:8443","username":"u","password":"p"}`},
		{"no username", `{"url":"https://192.0.2.10","password":"p"}`},
		{"first save without password", `{"url":"https://192.0.2.10","username":"u"}`},
	} {
		res := doReq(t, "PUT", srv.URL+"/api/config/unifi", cookie, tc.body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", tc.name, res.StatusCode)
		}
	}
}

func TestUniFiConfigNeedsAdmin(t *testing.T) {
	srv := makeTestServer(t)
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		res := doReq(t, m, srv.URL+"/api/config/unifi", "", `{"url":"https://x","username":"u","password":"p"}`)
		res.Body.Close()
		if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent {
			t.Errorf("%s without a session returned %d", m, res.StatusCode)
		}
	}
}

// The test endpoint reports a failure as a result, not as an HTTP error: the
// form needs to show what the controller said.
func TestUniFiTestReportsUnreachable(t *testing.T) {
	srv := makeTestServer(t)
	_, cookie, _ := loginCookie(t, srv.URL, "admin", "test123456")

	res := doReq(t, "POST", srv.URL+"/api/config/unifi/test", cookie,
		`{"url":"http://127.0.0.1:1","username":"u","password":"p"}`)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("test: %d", res.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != false || out["error"] == "" {
		t.Fatalf("unreachable controller: %+v", out)
	}
}
