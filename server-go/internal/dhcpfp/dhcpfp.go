// Package dhcpfp recognises an operating system from the DHCP parameter
// request list (option 55) its client sends.
//
// Every DHCP client asks the server for a fixed set of options, and each
// operating system's client asks for its own: the list is a fingerprint of
// the OS, not of the device, and it is sent on every lease, by clients that
// send no hostname and by clients behind a private (randomised) MAC, which
// is exactly when nothing else says what a device is.
//
// The table is deliberately short. It holds the lists of the operating
// systems that account for nearly every phone and computer on a home
// network, as the public fingerprint databases (Fingerbank and its kin)
// record them, and nothing that could be several things at once. An unknown list is reported as unknown: the
// caller keeps whatever it had, and the device stays "unknown" rather than
// becoming something it is not. The device types are the server's own
// classification keys (adapters.ValidDeviceTypes).
package dhcpfp

import "strings"

// Match is what a parameter request list says about the client.
type Match struct {
	// OS is a short label for the UI, such as "iOS" or "Windows".
	OS string
	// Manufacturer is the hardware maker when the OS implies it (Apple),
	// filled in when the MAC's OUI gives nothing (a private MAC). Empty for
	// an OS that runs on anyone's hardware.
	Manufacturer string
	// Type is the server's device type: "movil", "ordenador", ...
	Type string
}

// Apple's client sends the same list on every platform, with a small set of
// options that mark the platform: 95 (LDAP) only on macOS, and 108 (IPv6-only
// preferred, iOS 17 / macOS 14) and 162 (encrypted DNS, iOS 18 / macOS 15)
// added by newer releases. The lists below are the combinations seen from
// real devices; an iPhone and an iPad are not told apart, both are iOS.
var exact = map[string]Match{
	// iOS / iPadOS
	"1,121,3,6,15,119,252":             {OS: "iOS", Manufacturer: "Apple", Type: "movil"}, // up to iOS 13
	"1,121,3,6,15,114,119,252":         {OS: "iOS", Manufacturer: "Apple", Type: "movil"},
	"1,121,3,6,15,108,114,119,252":     {OS: "iOS", Manufacturer: "Apple", Type: "movil"},
	"1,121,3,6,15,108,114,119,162,252": {OS: "iOS", Manufacturer: "Apple", Type: "movil"},
	// macOS
	"1,121,3,6,15,119,95,252,44,46":             {OS: "macOS", Manufacturer: "Apple", Type: "ordenador"}, // up to macOS 11
	"1,121,3,6,15,114,119,95,252,44,46":         {OS: "macOS", Manufacturer: "Apple", Type: "ordenador"},
	"1,121,3,6,15,108,114,119,95,252,44,46":     {OS: "macOS", Manufacturer: "Apple", Type: "ordenador"},
	"1,121,3,6,15,108,114,119,162,95,252,44,46": {OS: "macOS", Manufacturer: "Apple", Type: "ordenador"},
	// Windows 10 and 11 (the same list since Windows 10). No manufacturer:
	// Microsoft writes the OS, someone else built the machine.
	"1,3,6,15,31,33,43,44,46,47,119,121,249,252": {OS: "Windows", Type: "ordenador"},
}

// Android's client (the platform's own, since Android 9) asks for this list,
// with options appended by later releases: 114 (captive portal, Android 11)
// and 108 (IPv6-only preferred, Android 12). Matched as a prefix, so a
// further release that appends another option still matches; a list that
// starts differently is not Android. The hardware vendor is unknown: the OUI
// says it when the MAC is real, nothing does when it is private.
const androidPrefix = "1,3,6,15,26,28,51,58,59,43"

// Lookup recognises a parameter request list. ok is false for an unknown or
// empty list.
func Lookup(paramReqList string) (m Match, ok bool) {
	list := strings.ReplaceAll(strings.TrimSpace(paramReqList), " ", "")
	if list == "" {
		return Match{}, false
	}
	if m, ok := exact[list]; ok {
		return m, true
	}
	if list == androidPrefix || strings.HasPrefix(list, androidPrefix+",") {
		return Match{OS: "Android", Type: "movil"}, true
	}
	return Match{}, false
}
