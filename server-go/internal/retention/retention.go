// Package retention holds the configurable retention of the 5-minute
// traffic buckets (per-client bandwidth and per-port series).
//
// #1862 cut it from a year to a fixed 90 days to keep the database inside a
// small container disk. A server with room to spare can keep more, one with
// less can keep fewer: the value lives in kv and both purges read it on
// every pass, so a change applies without a restart.
package retention

import (
	"database/sql"
	"strconv"
	"time"
)

const (
	// KeyTrafficBucketDays is the kv key holding the retention in days.
	KeyTrafficBucketDays = "history.traffic_5m_days"
	// DefaultTrafficBucketDays is #1862's value, used when nothing is set.
	DefaultTrafficBucketDays = 90
	// MinTrafficBucketDays and MaxTrafficBucketDays bound the setting. The
	// nightly job rebuilds the daily totals of the last 35 days from the 5m
	// buckets (Rollup5mToDaily, INSERT OR REPLACE): with fewer days kept, a
	// day partly purged would be rebuilt short and its total lost for good.
	// A year is what #1862 found too much for its disk.
	MinTrafficBucketDays = 36
	MaxTrafficBucketDays = 365
)

// ValidTrafficBucketDays reports whether d is an accepted setting.
func ValidTrafficBucketDays(d int) bool {
	return d >= MinTrafficBucketDays && d <= MaxTrafficBucketDays
}

// TrafficBucketDays reads the setting; a missing, unreadable or out-of-range
// value gives the default.
func TrafficBucketDays(db *sql.DB) int {
	if db == nil {
		return DefaultTrafficBucketDays
	}
	var v string
	if err := db.QueryRow("SELECT value FROM kv WHERE key = ?", KeyTrafficBucketDays).Scan(&v); err != nil {
		return DefaultTrafficBucketDays
	}
	d, err := strconv.Atoi(v)
	if err != nil || !ValidTrafficBucketDays(d) {
		return DefaultTrafficBucketDays
	}
	return d
}

// TrafficBucket returns the setting as a duration.
func TrafficBucket(db *sql.DB) time.Duration {
	return time.Duration(TrafficBucketDays(db)) * 24 * time.Hour
}
