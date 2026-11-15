package probe

// QuarantineRadiusInfo lets the monitoring server answer RADIUS MAC
// authentication requests while the router's panel cannot (a restart or an
// update): the access points list the server as their second RADIUS
// server. It carries the shared secret, so the agent sends it only to a
// server reached over HTTPS with a pinned key, and the server keeps it in
// memory, apart from the rest of the push.
type QuarantineRadiusInfo struct {
	// Secret is the RADIUS shared secret the access points use.
	Secret string `json:"secret"`
	// Enforce false: the quarantine is off; every device is accepted.
	Enforce bool `json:"enforce"`
	// Approved are the MACs (lowercase, colon-separated) let in.
	Approved []string `json:"approved"`
	// PauseUntil (unix seconds) and PauseKind ("learn" or "off"): while a
	// pause runs, every device is accepted (only the panel itself records
	// and approves).
	PauseUntil int64  `json:"pauseUntil,omitempty"`
	PauseKind  string `json:"pauseKind,omitempty"`
	// Disabled: the panel's RADIUS layer was turned off; the server drops
	// what it holds for this router (no secret is sent with it).
	Disabled bool `json:"disabled,omitempty"`
}
