package adapters

import (
	"context"
	"strings"
)

// deviceNamesMax bounds what one reply carries.
const deviceNamesMax = 4096

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
		name := strings.TrimSpace(d.Name)
		if name == "" || d.NameInferred || isMACLike(name) || strings.EqualFold(name, d.MAC) {
			continue
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
