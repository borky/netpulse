package adapters

import (
	"context"
	"strings"
	"unicode"
)

// deviceNamesMax bounds the names listed; deviceNameMaxLen each one.
const (
	deviceNamesMax   = 16384 // fleet-wide; each reply carries one router's
	deviceNameMaxLen = 63
)

// DeviceNames lists the names this server knows for devices, by lowercase
// MAC (a device's linked MACs included), for a router panel to show where
// it has no name of its own. Only real names: none made up from a DHCP
// fingerprint (NameInferred), none that is just the address.
func (l *Live) DeviceNames() map[string]string {
	if l == nil {
		return nil
	}
	return deviceNamesOf(l.GetDevices(context.Background()))
}

func deviceNamesOf(devices []Device) map[string]string {
	out := map[string]string{}
	for _, d := range devices {
		// No control characters: a display name, and the reply's size is
		// counted without JSON escapes.
		name := strings.TrimSpace(strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, d.Name))
		if name == "" || d.NameInferred || isMACLike(name) || strings.EqualFold(name, d.MAC) {
			continue
		}
		// A display name, bounded: the reply must stay well under what an
		// agent reads (1 MiB), whatever a device calls itself.
		if r := []rune(name); len(r) > deviceNameMaxLen {
			name = strings.TrimSpace(string(r[:deviceNameMaxLen]))
		}
		for _, mac := range append([]string{d.MAC}, d.AliasMacs...) {
			if len(out) >= deviceNamesMax {
				return out
			}
			mac = strings.ToLower(strings.TrimSpace(mac))
			if isMACLike(mac) {
				out[strings.ReplaceAll(mac, "-", ":")] = name
			}
		}
	}
	return out
}
