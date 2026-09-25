// script_test.go — contrato de reinstall.Script (#463/#457): instalación
// completa del agente (binario verificado, init self-heal, watchdog, cron).
package reinstall_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gnacho/netpulse/server-go/internal/reinstall"
)

func scriptForTest() string {
	return reinstall.Script(
		"test-router",
		strings.Repeat("a1", 32), // 64 hex como un token real
		"http://192.168.1.226:3000",
		map[string]string{
			"arm64":  "cafebabe",
			"arm":    "deadbeef",
			"amd64":  "abcd1234",
			"mipsle": "0123feed",
			"mips":   "4567beef",
		},
	)
}

func TestScriptConfig(t *testing.T) {
	s := scriptForTest()
	for _, want := range []string{
		`SERVER="http://192.168.1.226:3000"`,
		`SLUG="test-router"`,
		`NETPULSE_SERVER=$SERVER`,
		`NETPULSE_SLUG=$SLUG`,
		`NETPULSE_TOKEN=$TOKEN`,
		"chmod 600 \"$ENV_FILE\"",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script sin %q", want)
		}
	}
}

func TestScriptArchAndDigests(t *testing.T) {
	s := scriptForTest()
	for _, want := range []string{
		"aarch64|arm64)  GOARCH=arm64; SHA256=\"cafebabe\"",
		"armv7l|armv7|armhf|arm) GOARCH=arm; SHA256=\"deadbeef\"",
		"x86_64|amd64)   GOARCH=amd64; SHA256=\"abcd1234\"",
		`/api/agents/$SLUG/binary?arch=$GOARCH`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script sin %q", want)
		}
	}
	if strings.Contains(s, "arch=armv7\"") {
		t.Error("el script no debe pedir arch=armv7 (normalizeArch espera arm)")
	}
	// #488: uname -m "mips" no distingue endianness; el script lo detecta
	// con el byte EI_DATA del ELF y mapea a mipsle/mips con su digest.
	for _, want := range []string{
		`1) GOARCH=mipsle; SHA256="0123feed"`,
		`2) GOARCH=mips;  SHA256="4567beef"`,
		`head -c 6 /bin/sh | tail -c 1 | tr '\001\002' '12'`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script sin %q", want)
		}
	}
	if strings.Count(s, "mipsle") < 2 {
		t.Errorf("el self-heal del init también debe resolver mipsle (apariciones: %d)",
			strings.Count(s, "mipsle"))
	}
	if !strings.Contains(s, `GOT=$(sha256sum /tmp/netpulse-agent.new | awk '{print $1}')`) {
		t.Error("sin verificación sha256sum")
	}
	if !strings.Contains(s, "exit 21") {
		t.Error("sin código de salida 21 para sha256 mismatch")
	}
}

func TestScriptSelfHealInit(t *testing.T) {
	s := scriptForTest()
	for _, want := range []string{
		"selfheal_binary()",
		`url="${NETPULSE_SERVER%/}/api/agents/${NETPULSE_SLUG}/binary?arch=${ARCH}"`,
		"logger -t netpulse-agent \"self-heal: binario restaurado\"",
		"selfheal_binary || logger -t netpulse-agent \"self-heal: no se pudo restaurar el binario\"",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("init sin self-heal: falta %q", want)
		}
	}
	if strings.Count(s, "armv7l|armv7|armhf|arm") != 2 {
		t.Errorf("case de arch incompleto (apariciones: %d, esperadas 2)",
			strings.Count(s, "armv7l|armv7|armhf|arm"))
	}
}

func TestScriptWatchdogAndCron(t *testing.T) {
	s := scriptForTest()
	for _, want := range []string{
		"pidof netpulse-agent",
		`echo '*/2 * * * * /usr/sbin/netpulse-watchdog'`,
		"/etc/init.d/cron restart",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("watchdog/cron incompleto: falta %q", want)
		}
	}
	if strings.Contains(s, "pgrep -x") {
		t.Error("el watchdog no debe usar pgrep -x (bug BusyBox)")
	}
	if !strings.Contains(s, "grep -v netpulse-watchdog") {
		t.Error("el cron no es idempotente")
	}
}

func TestScriptFinishesWithStart(t *testing.T) {
	s := scriptForTest()
	if !strings.HasSuffix(strings.TrimSpace(s), "\"$INIT\" enable\n\"$INIT\" restart") {
		t.Error("el script debe terminar con enable + restart")
	}
}

func TestTokenPushScriptConfig(t *testing.T) {
	s := reinstall.TokenPushScript("test-router", strings.Repeat("c3", 32))
	for _, want := range []string{
		"/etc/netpulse-agent.env",
		"NETPULSE_TOKEN=" + strings.Repeat("c3", 32),
		"chmod 600 \"$ENV_FILE.tmp\"",
		"mv -f \"$ENV_FILE.tmp\" \"$ENV_FILE\"",
		"\"$INIT\" restart",
		"exit 30",
		"exit 31",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("TokenPushScript sin %q", want)
		}
	}
	// No debe descargar binario ni tocar init/watchdog/cron (rotate ligero).
	if strings.Contains(s, "/binary?arch=") {
		t.Error("TokenPushScript no debe descargar el binario")
	}
	for _, notWant := range []string{"watchdog", "crontab", "/etc/init.d/netpulse-agent >", "GOT=$(sha256sum"} {
		if strings.Contains(s, notWant) {
			t.Errorf("TokenPushScript no debe contener %q (rotate ligero)", notWant)
		}
	}
}

func TestScriptEmptyDigestSkipsVerify(t *testing.T) {
	s := reinstall.Script(
		"r", strings.Repeat("b2", 32), "http://s:3000",
		map[string]string{"arm64": "", "arm": "", "amd64": ""},
	)
	if !strings.Contains(s, `GOARCH=arm64; SHA256=""`) {
		t.Error("sin digest, SHA256 debe quedar vacío")
	}
	if !strings.Contains(s, `if [ -n "$SHA256" ]; then`) {
		t.Error("la verificación debe estar protegida contra digest vacío")
	}
}

// FORK: the rotation runs for real against a copy of an agent's env file.
// Only the token changes: the server's pin and every other setting stay, and
// an agent on HTTPS keeps starting after a rotation.
func TestTokenPushScriptKeepsTheRestOfTheEnv(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "netpulse-agent.env")
	before := "NETPULSE_SERVER=https://192.0.2.10:3443\n" +
		"NETPULSE_SLUG=test-router\n" +
		"NETPULSE_SERVER_FP=" + strings.Repeat("ab", 32) + "\n" +
		"NETPULSE_TOKEN=" + strings.Repeat("0f", 32) + "\n" +
		"NETPULSE_PAIRING_TOKEN=11111111-2222-4333-8444-555555555555\n" +
		"NETPULSE_INTERVAL=30\n"
	if err := os.WriteFile(env, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	s := reinstall.TokenPushScript("test-router", strings.Repeat("c3", 32))
	s = strings.ReplaceAll(s, "/etc/netpulse-agent.env", env)
	s = strings.ReplaceAll(s, "/etc/init.d/netpulse-agent", filepath.Join(dir, "no-init"))
	if out, err := exec.Command("sh", "-c", s).CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(env)
	if err != nil {
		t.Fatal(err)
	}
	want := "NETPULSE_SERVER=https://192.0.2.10:3443\n" +
		"NETPULSE_SLUG=test-router\n" +
		"NETPULSE_SERVER_FP=" + strings.Repeat("ab", 32) + "\n" +
		"NETPULSE_INTERVAL=30\n" +
		"NETPULSE_TOKEN=" + strings.Repeat("c3", 32) + "\n"
	if string(got) != want {
		t.Fatalf("env after rotation:\n%s\nwant:\n%s", got, want)
	}
	if st, _ := os.Stat(env); st.Mode().Perm() != 0o600 {
		t.Fatalf("env mode = %v, want 0600", st.Mode().Perm())
	}
}

// FORK: with a Trust the script moves the agent to the HTTPS address, writes
// the root to the router, verifies its downloads - including the self-heal's
// - against it, and pins the server. Without one nothing of that appears.
func TestScriptWithTrust(t *testing.T) {
	root := "-----BEGIN CERTIFICATE-----\nMIIBtestroot\n-----END CERTIFICATE-----\n"
	fp := strings.Repeat("ab", 32)
	s := reinstall.Script("test-router", strings.Repeat("a1", 32), "http://192.0.2.10:3000",
		map[string]string{}, reinstall.Trust{ServerURL: "https://192.0.2.10:3443", ServerFP: fp, CAPEM: []byte(root)})
	for _, want := range []string{
		`SERVER="https://192.0.2.10:3443"`,
		"cat > /etc/netpulse-ca.pem <<'CAEOF'\n" + strings.TrimSpace(root) + "\nCAEOF",
		`curl -fsSL $CURL_TLS`,
		`wget -q $WGET_TLS`,
		`echo "NETPULSE_SERVER_FP=` + fp + `" >> "$ENV_FILE"` + "\nchmod 600",
		`ctls="--cacert /etc/netpulse-ca.pem"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if out, err := exec.Command("sh", "-n", "-c", s).CombinedOutput(); err != nil {
		t.Fatalf("not valid sh: %v\n%s", err, out)
	}

	plain := reinstall.Script("test-router", strings.Repeat("a1", 32), "http://192.0.2.10:3000", map[string]string{})
	if !strings.Contains(plain, "rm -f /etc/netpulse-ca.pem") {
		t.Error("a script without a root leaves a stale one on the router")
	}
	if strings.Contains(s, "rm -f /etc/netpulse-ca.pem") {
		t.Error("a script with a root removes it")
	}
	for _, notWant := range []string{"CAEOF", "NETPULSE_SERVER_FP=", "https://"} {
		if strings.Contains(plain, notWant) {
			t.Errorf("a script without Trust contains %q", notWant)
		}
	}
	if out, err := exec.Command("sh", "-n", "-c", plain).CombinedOutput(); err != nil {
		t.Fatalf("not valid sh: %v\n%s", err, out)
	}
}
