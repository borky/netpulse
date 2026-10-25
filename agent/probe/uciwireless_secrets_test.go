package probe

// FORK: no secret leaves the router in the wireless dump, whatever the option
// is called, and everything the 802.11r parser reads still does.

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestUciWirelessFilterDropsEverySecretOption(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	secret := []string{
		`wireless.ap1.key='s-key'`,
		`wireless.ap1.key1='s-wep1'`,
		`wireless.ap1.key4='s-wep4'`,
		`wireless.ap1.sae_key='s-sae'`,
		`wireless.ap1.sae_password='s-saepw'`,
		`wireless.ap1.wpa_psk='s-wpa'`,
		`wireless.ap1.password='s-pw'`,
		`wireless.ap1.auth_secret='s-auth'`,
		`wireless.ap1.acct_secret='s-acct'`,
		`wireless.ap1.dae_secret='s-dae'`,
		`wireless.ap1.radius_secret='s-radius'`,
		`wireless.ap1.priv_key_pwd='s-privpwd'`,
		`wireless.ap1.r0kh='02:00:00:00:00:01,nas1,s-r0kh'`,
		`wireless.ap1.r1kh='02:00:00:00:00:01,02:00:00:00:00:01,s-r1kh'`,
		`wireless.ap1.wps_pin='s-wps'`,
		`wireless.ap1.mesh_psk='s-mesh'`,
		`wireless.ap1.eap_password='s-eap'`,
		`wireless.ap1.priv_key2_pwd='s-priv2'`,
		`wireless.ap1.password2='s-pw2'`,
	}
	kept := []string{
		`wireless.ap1=wifi-iface`,
		`wireless.ap1.device='radio0'`,
		`wireless.ap1.network='lan'`,
		`wireless.ap1.ssid='example-secret-net'`,
		`wireless.ap1.encryption='sae-mixed'`,
		`wireless.ap1.disabled='0'`,
		`wireless.ap1.ieee80211r='1'`,
		`wireless.ap1.mobility_domain='4f57'`,
		`wireless.ap1.nasid='nas1'`,
		`wireless.ap1.ft_psk_generate_local='1'`,
		`wireless.ap1.ifname='wlan0'`,
		`wireless.ap1.macaddr='02:00:00:00:00:02'`,
		`wireless.ap1.ft_over_ds='0'`,
		`wireless.ap1.pmk_r1_push='1'`,
		`wireless.ap1.ieee80211k='1'`,
		`wireless.ap1.ieee80211v='1'`,
		`wireless.ap1.ieee80211w='1'`,
		`wireless.ap1.bss_transition='1'`,
		`wireless.ap1.wpa_psk_file='/etc/hostapd.wpa_psk'`,
		`wireless.radio0=wifi-device`,
		`wireless.radio0.channel='36'`,
		`wireless.radio0.band='5g'`,
		// A value or a section name that looks like a secret option.
		`wireless.ap2.ssid='a.psk=b'`,
		`wireless.guest_psk=wifi-iface`,
		`wireless.guest_psk.ssid='example-guest'`,
	}
	cmd := exec.Command("/bin/sh", "-c", uciWirelessSecretsFilter)
	cmd.Stdin = strings.NewReader(strings.Join(append(append([]string{}, secret...), kept...), "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	got := string(out)
	if strings.Contains(got, "s-") {
		t.Fatalf("a secret went through the filter:\n%s", got)
	}
	for _, k := range kept {
		if !strings.Contains(got, k) {
			t.Fatalf("the filter dropped %q, which is not a secret:\n%s", k, got)
		}
	}
}
