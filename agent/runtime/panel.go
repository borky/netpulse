package runtime

// FORK: this file exists only in the fork, next to runtime.go rather than
// inside it, so the lines the fork adds to upstream's push paths stay at one
// call per path.

import "github.com/gnacho/netpulse/agent/probe"

// withPanel fills in where and how the embedder's own panel answers: its port,
// and, when it serves HTTPS, the key of the certificate it is serving.
//
// Upstream's withMeta fills Kind and MQTT; this sits beside it rather than
// inside it, so a later upstream edit to withMeta cannot conflict with fork
// code.
func withPanel(payload *probe.Payload, opts Options) {
	payload.PanelPort = opts.PanelPort
	if !opts.PanelTLS {
		return
	}
	payload.PanelTLS = true
	if opts.PanelSPKI != nil {
		payload.PanelSPKI = opts.PanelSPKI()
	}
}
