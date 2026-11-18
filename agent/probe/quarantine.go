package probe

// QuarantineInfo is the device quarantine as the router's panel (NetGrip)
// keeps it, for the monitoring server to show next to each device. Which
// devices are trusted is what someone copying a MAC address would want to
// know, so, like QuarantineRadiusInfo, it travels only to a server reached
// over HTTPS with a pinned key.
type QuarantineInfo struct {
	// Enabled false: the quarantine is off; Devices is empty and the
	// server forgets what it showed for this router.
	Enabled bool `json:"enabled"`
	// Devices: every approved or waiting device, and those reported as a
	// possible copied MAC.
	Devices []QuarantineDevice `json:"devices,omitempty"`
	// PauseUntil (unix seconds) and PauseKind ("learn" or "off"): a pause
	// is running. "off": nothing is enforced, so a waiting device is not
	// restricted; "learn": new devices are approved as they join.
	PauseUntil int64  `json:"pauseUntil,omitempty"`
	PauseKind  string `json:"pauseKind,omitempty"`
}

// QuarantineDevice is one device's quarantine state.
type QuarantineDevice struct {
	// MAC: lowercase, colon-separated.
	MAC string `json:"mac"`
	// State: "approved" or "waiting" (not approved: it gets at most the
	// internet).
	State string `json:"state"`
	// Report: "notice" or "alert" while the copied-MAC detection reports
	// this device and nobody has dealt with it yet ("alert" too once it
	// was moved back to quarantine automatically); "" otherwise.
	Report string `json:"report,omitempty"`
}

// QuarantineStation is what the server's UniFi controller says about one
// device the router listed in its QuarantineInfo: how it is connected right
// now. The copied-MAC detection compares it with what it saw before.
type QuarantineStation struct {
	// MAC: lowercase, colon-separated.
	MAC string `json:"mac"`
	// Wired: on a switch port, not on Wi-Fi.
	Wired bool `json:"wired"`
	// The rest is Wi-Fi only (empty or zero when the controller does not
	// say). APModel: the access point's model; Band: "2g", "5g" or "6g";
	// Proto: the Wi-Fi standard in use ("n", "ac", "ax", "be"); NSS: spatial
	// streams; MLO: a Wi-Fi 7 multi-link connection.
	APModel string `json:"apModel,omitempty"`
	Band    string `json:"band,omitempty"`
	Proto   string `json:"proto,omitempty"`
	NSS     int    `json:"nss,omitempty"`
	MLO     bool   `json:"mlo,omitempty"`
}

// IngestReply is the server's answer to a push. Stations is set only when
// the push carried a QuarantineInfo over pinned HTTPS and the server reads
// a UniFi controller; nil means "nothing to say", not "no stations".
type IngestReply struct {
	Stations []QuarantineStation `json:"stations,omitempty"`
	// Names: the names the server knows for devices, by lowercase MAC,
	// only real ones (none inferred from a fingerprint, none that is just
	// an address). Display only: an embedder shows one where it has no
	// name of its own.
	Names map[string]string `json:"names,omitempty"`
}
