package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Deleting a router takes the NetGrip executor token stored under its id,
// so a router later re-added under the same id does not inherit it.
func TestDeletingARouterDropsItsExecutorToken(t *testing.T) {
	s := panelTestServer(t)
	if _, err := s.db.Exec("INSERT INTO routers (id, name, host, type, is_gateway, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		"gw", "router-a", "192.0.2.1", "openwrt", 1, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO kv (key, value) VALUES (?, ?)",
		"netgrip.executor_token.gw", "exec-token-for-test"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/config/routers/gw", nil)
	req.SetPathValue("id", "gw")
	rec := httptest.NewRecorder()
	s.handleDeleteConfigRouter(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d", rec.Code)
	}
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM kv WHERE key = ?", "netgrip.executor_token.gw").Scan(&n); err != nil || n != 0 {
		t.Fatalf("executor token still stored after the delete (count %d, err %v)", n, err)
	}
}
