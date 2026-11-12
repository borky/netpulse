package httpapi_test

import (
	"os/exec"
	"strings"
	"testing"
)

// #1737: en un router sin curl (BusyBox pelado) el one-liner moría con
// "curl: not found" antes de llegar al instalador. Tiene que haber rama wget.
func TestInstallLineHasAWgetBranch(t *testing.T) {
	ts := makeURLTestServer(t, nil)
	_, _, line := createAgentToken(t, ts, "rt1")

	if !strings.Contains(line, "if command -v curl") {
		t.Fatalf("install line does not check for curl:\n%s", line)
	}
	if !strings.Contains(line, "wget -q -O /tmp/netpulse-install-agent.sh") {
		t.Fatalf("install line does not fall back to wget:\n%s", line)
	}
	// La descarga sigue siendo a fichero y el script solo se ejecuta si el
	// descargador terminó bien (#1577).
	if !strings.Contains(line, "fi && sh /tmp/netpulse-install-agent.sh") {
		t.Fatalf("install line does not gate the run on the download:\n%s", line)
	}
}

// With HTTPS and a private CA the wget branch verifies against that root
// and never retries unverified (FORK): the downloaded script runs as root
// and is what applies the pin, so an unverified one could skip it.
func TestInstallLineWgetBranchKeepsTheRootWhenPossible(t *testing.T) {
	ts, mgr := makeHTTPSTestServer(t)
	enableHTTPS(t, mgr)
	_, _, line := createAgentToken(t, ts, "rt2")

	for _, want := range []string{
		`wget -q --ca-certificate="$NPCA" -O /tmp/netpulse-install-agent.sh`,
		"this wget cannot verify the server certificate",
		"--server-fp=" + mgr.Fingerprint(),
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("install line lacks %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "--no-check-certificate") {
		t.Fatalf("install line downloads the installer unverified:\n%s", line)
	}
	if out, err := exec.Command("sh", "-n", "-c", line).CombinedOutput(); err != nil {
		t.Fatalf("install line is not valid sh: %v\n%s", err, out)
	}
}
