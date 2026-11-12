package portseries

import (
	"testing"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/retention"
)

// The 5m purge follows the retention set in kv, and keeps the 90-day
// default without one.
func TestPurge5mFollowsTheConfiguredRetention(t *testing.T) {
	s := openTestDB(t)
	insert := func(age time.Duration) {
		t.Helper()
		bucketMs := (time.Now().Add(-age).UnixMilli() / int64(BucketMS)) * int64(BucketMS)
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO port_series_5m
			(router_id, port_id, bucket_ts, n, rx_bytes, tx_bytes,
			 rx_errors, tx_errors, rx_frames, tx_frames,
			 rx_bps_min, rx_bps_max, rx_bps_avg,
			 tx_bps_min, tx_bps_max, tx_bps_avg, speed_mbps)
			VALUES (?, ?, ?, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1000)`,
			"rt-test", "lan1", bucketMs); err != nil {
			t.Fatal(err)
		}
	}
	day := 24 * time.Hour
	insert(60 * day)
	insert(10 * day)

	// No kv table at all: the default (90 days) keeps both.
	if n, err := s.Purge5m(); err != nil || n != 0 {
		t.Fatalf("default retention purged %d (err %v), want 0", n, err)
	}

	if _, err := s.db.Exec(`CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO kv (key, value) VALUES (?, '40')`, retention.KeyTrafficBucketDays); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Purge5m(); err != nil || n != 1 {
		t.Fatalf("40-day retention purged %d (err %v), want 1", n, err)
	}
}
