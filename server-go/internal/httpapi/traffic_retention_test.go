package httpapi_test

import (
	"net/http"
	"testing"
)

func TestTrafficBucketRetentionSetting(t *testing.T) {
	srv := makeTestServer(t)
	_, cookie, _ := loginCookie(t, srv.URL, "admin", "test123456")
	_, body := wanSpeedRequest(t, "GET", srv.URL, "/api/settings/thresholds", cookie, "")
	if body["trafficBucketDays"] != float64(90) {
		t.Fatalf("default = %v, want 90", body["trafficBucketDays"])
	}
	res, body := wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/thresholds", cookie, `{"trafficBucketDays":180}`)
	if res.StatusCode != http.StatusOK || body["trafficBucketDays"] != float64(180) {
		t.Fatalf("PUT 180: %d %v", res.StatusCode, body)
	}
	for _, bad := range []string{`{"trafficBucketDays":6}`, `{"trafficBucketDays":366}`} {
		if res, _ := wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/thresholds", cookie, bad); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, res.StatusCode)
		}
	}
	// Setting another value leaves it alone.
	_, body = wanSpeedRequest(t, "PUT", srv.URL, "/api/settings/thresholds", cookie, `{"alertRetentionDays":30}`)
	if body["trafficBucketDays"] != float64(180) {
		t.Fatalf("after another PUT = %v, want 180", body["trafficBucketDays"])
	}
}
