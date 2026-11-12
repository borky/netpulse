package httpapi_test

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

const dummyBackupPass = "dummy backup passphrase"

func TestBackupPassphraseSettingsAndDownload(t *testing.T) {
	srv := makeTestServer(t)
	_, cookie, _ := loginCookie(t, srv.URL, "admin", "test123456")

	if res, _ := wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/backup", cookie, `{"passphrase":"short"}`); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("short passphrase: %d", res.StatusCode)
	}
	res, body := wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/backup", cookie, `{"passphrase":"`+dummyBackupPass+`"}`)
	if res.StatusCode != http.StatusOK || body["encrypted"] != true {
		t.Fatalf("set: %d %v", res.StatusCode, body)
	}
	for k, v := range body {
		if s, ok := v.(string); ok && strings.Contains(s, dummyBackupPass) {
			t.Fatalf("the answer echoes the passphrase in %q", k)
		}
	}
	var stored string
	_ = srv.db.QueryRow("SELECT value FROM kv WHERE key = 'backup.passphrase'").Scan(&stored)
	if stored == "" || strings.Contains(stored, dummyBackupPass) {
		t.Fatalf("passphrase stored in the clear: %q", stored)
	}

	// The download is the encrypted archive.
	req, _ := http.NewRequest("GET", srv.URL+"/api/backup/download", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: cookie})
	dl, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(dl.Body)
	dl.Body.Close()
	if dl.StatusCode != http.StatusOK || dl.Header.Get("X-Netpulse-Backup-Contains-Credentials") != "encrypted" {
		t.Fatalf("download: %d %q", dl.StatusCode, dl.Header.Get("X-Netpulse-Backup-Contains-Credentials"))
	}
	if !strings.Contains(dl.Header.Get("Content-Disposition"), ".tar.gz.enc") || !bytes.HasPrefix(raw, []byte("Salted__")) {
		t.Fatalf("download is not an encrypted archive: %q", dl.Header.Get("Content-Disposition"))
	}

	if res, body := wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/backup", cookie, `{"passphrase":""}`); res.StatusCode != http.StatusOK || body["encrypted"] != false {
		t.Fatalf("clear: %d %v", res.StatusCode, body)
	}
}
