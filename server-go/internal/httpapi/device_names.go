package httpapi

import (
	"sync"
	"time"
)

// Device names for a router panel (the push reply's "names"): what this
// server calls each device, which the panel shows only where it has no name
// of its own. Building the device list is the server's heaviest read, so it
// is done at most once a minute, whatever the number of routers pushing.

const deviceNamesTTL = time.Minute

var (
	deviceNamesMu  sync.Mutex
	deviceNamesAt  time.Time
	deviceNamesMap map[string]string
)

func (s *server) deviceNamesForReply() map[string]string {
	src, ok := s.adapter.(interface{ DeviceNames() map[string]string })
	if !ok {
		return nil
	}
	deviceNamesMu.Lock()
	defer deviceNamesMu.Unlock()
	if deviceNamesMap == nil || time.Since(deviceNamesAt) > deviceNamesTTL {
		deviceNamesMap, deviceNamesAt = src.DeviceNames(), time.Now()
	}
	if len(deviceNamesMap) == 0 {
		return nil
	}
	return deviceNamesMap
}
