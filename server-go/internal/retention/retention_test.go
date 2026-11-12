package retention

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestTrafficBucketDays(t *testing.T) {
	if got := TrafficBucketDays(nil); got != DefaultTrafficBucketDays {
		t.Fatalf("nil db = %d", got)
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	set := func(v string) {
		if _, err := db.Exec(`INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, KeyTrafficBucketDays, v); err != nil {
			t.Fatal(err)
		}
	}
	for v, want := range map[string]int{
		"180": 180, "7": 7, "365": 365,
		"6": DefaultTrafficBucketDays, "366": DefaultTrafficBucketDays, "x": DefaultTrafficBucketDays,
	} {
		set(v)
		if got := TrafficBucketDays(db); got != want {
			t.Errorf("stored %q: got %d, want %d", v, got, want)
		}
	}
}
