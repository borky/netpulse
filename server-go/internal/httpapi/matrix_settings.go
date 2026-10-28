// matrix_settings.go - settings of the Matrix channel: GET (never the
// token), PUT (blank field = keep the stored one; checked against the
// homeserver before it is saved) and a real test send.
package httpapi

import (
	"net/http"

	"github.com/gnacho/netpulse/server-go/internal/auth"
	"github.com/gnacho/netpulse/server-go/internal/matrix"
)

type matrixConfigResponse struct {
	Server     string `json:"server"`
	RoomID     string `json:"roomId"`
	TokenSet   bool   `json:"tokenSet"`
	Enabled    bool   `json:"enabled"`
	UrgentOnly bool   `json:"urgentOnly"`
	// Unreadable: credentials are stored but this server's key does not
	// open them; the admin has to enter them again.
	Unreadable bool `json:"unreadable"`
	// SecretsUnavailable: the key file itself cannot be opened, so nothing
	// can be saved until it is fixed (see the journal at startup).
	SecretsUnavailable bool `json:"secretsUnavailable"`
}

func (s *server) registerMatrixRoutes(mux *http.ServeMux) {
	adapter := &dbKVAdapter{db: s.db.DB}

	mux.Handle("GET /api/settings/matrix", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := matrix.LoadConfig(adapter, s.secrets)
		writeJSON(w, http.StatusOK, matrixConfigResponse{
			Server:     cfg.Server,
			RoomID:     cfg.RoomID,
			TokenSet:   cfg.Token != "",
			Enabled:    cfg.Enabled,
			UrgentOnly: cfg.UrgentOnly,
			Unreadable: cfg.Unreadable && s.secrets != nil,
			// The key file is a server-side problem; re-entering the
			// credentials cannot fix it.
			SecretsUnavailable: s.secrets == nil,
		})
	})))

	mux.Handle("PUT /api/settings/matrix", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Server  string `json:"server"`
			RoomID  string `json:"roomId"`
			Token   string `json:"token"`
			Enabled bool   `json:"enabled"`
			// UrgentOnly: nil = leave as is.
			UrgentOnly *bool `json:"urgentOnly"`
			// Clear: disable the channel and wipe its credentials.
			Clear bool `json:"clear"`
		}
		if st := readJSONBody(w, r, &body); st != 0 {
			writeBodyError(w, st, "invalid_body", "")
			return
		}
		if s.secrets == nil {
			writeError(w, http.StatusServiceUnavailable, "secrets_unavailable", "secret storage is not available on this server")
			return
		}
		cfg := matrix.LoadConfig(adapter, s.secrets)
		if body.Clear {
			cfg = matrix.Config{UrgentOnly: true}
			if err := matrix.SaveConfig(adapter, s.secrets, cfg); err != nil {
				writeError(w, http.StatusInternalServerError, "kv_error")
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		storedServer := cfg.Server
		if body.Server != "" {
			cfg.Server = body.Server
		}
		if body.RoomID != "" {
			cfg.RoomID = body.RoomID
		}
		if body.Token != "" {
			cfg.Token = body.Token
		}
		cfg.Enabled = body.Enabled
		if body.UrgentOnly != nil {
			cfg.UrgentOnly = *body.UrgentOnly
		}
		cfg, err := matrix.Normalize(cfg)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_input", err.Error())
			return
		}
		if !cfg.Configured() {
			writeError(w, http.StatusBadRequest, "invalid_input", "homeserver URL, room id and access token are required")
			return
		}
		// The stored token only ever goes to the homeserver it was entered
		// for: pointing the channel elsewhere needs the token typed again,
		// or a PUT with just a new URL would hand it to that server during
		// validation.
		if storedServer != "" && cfg.Server != storedServer && body.Token == "" {
			writeError(w, http.StatusBadRequest, "token_required", "enter the access token again to change the homeserver")
			return
		}
		userID, err := matrix.Validate(cfg)
		if err != nil {
			writeError(w, http.StatusBadRequest, "validation_failed", err.Error())
			return
		}
		if err := matrix.SaveConfig(adapter, s.secrets, cfg); err != nil {
			writeError(w, http.StatusInternalServerError, "kv_error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "userId": userID})
	})))

	mux.Handle("POST /api/settings/matrix/test", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := matrix.SendTest(adapter, s.secrets); err != nil {
			writeError(w, http.StatusBadRequest, "matrix_test_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})))
}
