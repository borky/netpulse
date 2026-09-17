// unifi_config.go — GET/PUT/DELETE /api/config/unifi (admin).
//
// Same contract as the Proxmox settings: the credential never comes back
// out. The UI learns only whether one is stored (passwordSet) and can save
// the form without resending it, so editing the URL does not require typing
// the password again.
package httpapi

import (
	"net/http"
	"strings"

	"github.com/gnacho/netpulse/server-go/internal/unifi"
)

// GET /api/config/unifi — sanitised view of the stored controller.
func (s *server) handleGetUniFiConfig(w http.ResponseWriter, r *http.Request) {
	cfg := unifi.LoadConfig(s.db.DB)
	writeJSON(w, http.StatusOK, map[string]any{
		"url":         cfg.URL,
		"username":    cfg.Username,
		"site":        cfg.SiteOrDefault(),
		"insecure":    cfg.Insecure,
		"passwordSet": cfg.Password != "",
		"enabled":     cfg.Enabled(),
	})
}

type unifiInput struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	// Password empty on an edit = keep the stored one.
	Password string `json:"password"`
	Site     string `json:"site"`
	// Insecure is a pointer so "absent" differs from "false": a partial save
	// must not silently turn certificate checking back on.
	Insecure *bool `json:"insecure"`
}

// PUT /api/config/unifi — save the controller. Validates what it can before
// storing: a URL that is not a URL, or a username with no password and none
// stored, would only fail later inside the poller where nobody is watching.
func (s *server) handlePutUniFiConfig(w http.ResponseWriter, r *http.Request) {
	var in unifiInput
	if st := readJSONBody(w, r, &in); st != 0 {
		writeBodyError(w, st, "invalid_json", "")
		return
	}
	url := strings.TrimRight(strings.TrimSpace(in.URL), "/")
	if url == "" {
		writeError(w, http.StatusBadRequest, "invalid_input", "url es obligatoria")
		return
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		writeError(w, http.StatusBadRequest, "invalid_input", "url debe empezar por http:// o https://")
		return
	}
	if strings.TrimSpace(in.Username) == "" {
		writeError(w, http.StatusBadRequest, "invalid_input", "username es obligatorio")
		return
	}
	stored := unifi.LoadConfig(s.db.DB)
	if in.Password == "" && stored.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid_input", "password es obligatoria la primera vez")
		return
	}
	cfg := unifi.Config{
		URL:      url,
		Username: in.Username,
		Password: in.Password, // empty keeps the stored one (SaveConfig)
		Site:     in.Site,
		Insecure: stored.Insecure,
	}
	if in.Insecure != nil {
		cfg.Insecure = *in.Insecure
	}
	if err := unifi.SaveConfig(s.db.DB, cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	s.handleGetUniFiConfig(w, r)
}

// DELETE /api/config/unifi — forget the controller, password included.
func (s *server) handleDeleteUniFiConfig(w http.ResponseWriter, r *http.Request) {
	if err := unifi.ClearConfig(s.db.DB); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/config/unifi/test — try the stored (or submitted) credentials
// against the controller and report what came back. The UI needs an answer
// while the user is still looking at the form: a wrong password that only
// shows up as an empty topology an hour later is the worst outcome.
func (s *server) handleTestUniFiConfig(w http.ResponseWriter, r *http.Request) {
	var in unifiInput
	// A body is optional: with none, the stored config is tested.
	_ = readJSONBody(w, r, &in)
	cfg := unifi.LoadConfig(s.db.DB)
	if strings.TrimSpace(in.URL) != "" {
		cfg.URL = strings.TrimRight(strings.TrimSpace(in.URL), "/")
	}
	if strings.TrimSpace(in.Username) != "" {
		cfg.Username = strings.TrimSpace(in.Username)
	}
	if in.Password != "" {
		cfg.Password = in.Password
	}
	if strings.TrimSpace(in.Site) != "" {
		cfg.Site = strings.TrimSpace(in.Site)
	}
	// Without this the test would verify the certificate of a controller the
	// saved config is explicitly allowed to skip, and fail where the poller
	// will succeed.
	if in.Insecure != nil {
		cfg.Insecure = *in.Insecure
	}
	if !cfg.Enabled() {
		writeError(w, http.StatusBadRequest, "invalid_input", "falta url, username o password")
		return
	}
	devices, clients, err := unifi.NewClient(cfg).Inventory(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	switches, aps := 0, 0
	for _, d := range devices {
		switch d.Kind {
		case "switch":
			switches++
		case "ap":
			aps++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "switches": switches, "aps": aps, "clients": len(clients),
	})
}
