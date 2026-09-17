// store.go — where the controller's connection settings live.
//
// One controller per server, unlike Proxmox's instance list: a UniFi site is
// already the unit that owns a whole fleet, and nobody has asked for two.
// Kept in kv under a single key, with the password stored server-side only.
package unifi

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

const kvConfig = "unifi_config"

// LoadConfig reads the stored controller settings. A missing or corrupt
// value reads as "not configured" rather than an error: the integration is
// optional and must never take the poller down with it.
func LoadConfig(db *sql.DB) Config {
	if db == nil {
		return Config{}
	}
	var raw string
	if err := db.QueryRow("SELECT value FROM kv WHERE key = ?", kvConfig).Scan(&raw); err != nil {
		return Config{}
	}
	if strings.TrimSpace(raw) == "" {
		return Config{}
	}
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		log.Printf("[unifi] stored config is unreadable, ignoring it: %v", err)
		return Config{}
	}
	return cfg
}

// SaveConfig persists the settings. An empty Password keeps the stored one,
// so the UI can save a form it never received the password in.
func SaveConfig(db *sql.DB, cfg Config) error {
	if db == nil {
		return fmt.Errorf("unifi: no database")
	}
	cfg.URL = strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.Site = strings.TrimSpace(cfg.Site)
	if cfg.Password == "" {
		cfg.Password = LoadConfig(db).Password
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		kvConfig, string(raw))
	return err
}

// ClearConfig forgets the controller, password included.
func ClearConfig(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("unifi: no database")
	}
	_, err := db.Exec("DELETE FROM kv WHERE key = ?", kvConfig)
	return err
}
