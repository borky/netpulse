package httpapi

// FORK: GET /api/quarantine — the device quarantine the routers' panels
// (NetGrip) report, for the device list to show. Which devices are trusted
// is what someone copying a MAC address wants, so it is served only over
// HTTPS: over plain HTTP the answer says so and lists nothing. Kept out of
// /api/devices and the overview snapshots, which are also served in clear.

import (
	"net/http"

	"github.com/gnacho/netpulse/server-go/internal/auth"
	"github.com/gnacho/netpulse/server-go/internal/quarantinestate"
)

func (s *server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	if !auth.IsSecureRequest(r) {
		writeJSON(w, http.StatusOK, map[string]any{"secure": false, "devices": []quarantinestate.Entry{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"secure": true, "devices": quarantinestate.Default.Snapshot()})
}
