package backupcrypt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

const testPass = "correct horse battery staple"

// fastKDF lowers the work factor for tests that only check the cipher.
func fastKDF(t *testing.T) {
	orig := iterations
	iterations = 1000
	t.Cleanup(func() { iterations = orig })
}

func encrypt(t *testing.T, plain []byte, pass string, chunk int) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewWriter(&out, pass)
	if err != nil {
		t.Fatal(err)
	}
	for len(plain) > 0 {
		n := min(chunk, len(plain))
		if _, err := w.Write(plain[:n]); err != nil {
			t.Fatal(err)
		}
		plain = plain[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func decrypt(t *testing.T, enc []byte, pass string) ([]byte, error) {
	t.Helper()
	r, err := NewReader(bytes.NewReader(enc), pass)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestRoundTripAcrossSizesAndWriteChunks(t *testing.T) {
	fastKDF(t)
	for _, size := range []int{0, 1, 15, 16, 17, 31, 32, 33, 100_000} {
		plain := make([]byte, size)
		_, _ = rand.Read(plain)
		for _, chunk := range []int{1, 7, 16, 4096} {
			enc := encrypt(t, plain, testPass, chunk)
			if bytes.Contains(enc, plain) && size > 16 {
				t.Fatalf("size %d: plaintext visible in the output", size)
			}
			got, err := decrypt(t, enc, testPass)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("size %d chunk %d: round trip failed (%v)", size, chunk, err)
			}
		}
	}
}

func TestWrongPassphraseIsRefused(t *testing.T) {
	fastKDF(t)
	enc := encrypt(t, bytes.Repeat([]byte("netpulse backup "), 1000), testPass, 4096)
	if _, err := decrypt(t, enc, "not the passphrase"); !errors.Is(err, ErrBadPassphrase) {
		// CBC without a tag cannot always tell; with this much data and a
		// random key the padding check fails all but 1 time in ~256.
		t.Fatalf("wrong passphrase: err = %v", err)
	}
	if _, err := decrypt(t, []byte("plain tar.gz bytes"), testPass); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("not an encrypted file: err = %v", err)
	}
	if _, err := decrypt(t, enc[:len(enc)-5], testPass); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("truncated file: err = %v", err)
	}
}

func TestEachEncryptionUsesAFreshSalt(t *testing.T) {
	fastKDF(t)
	a := encrypt(t, []byte("same"), testPass, 16)
	b := encrypt(t, []byte("same"), testPass, 16)
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions are identical: the salt is not random")
	}
}

func TestEmptyPassphraseIsRefused(t *testing.T) {
	if _, err := NewWriter(io.Discard, ""); err == nil {
		t.Fatal("an empty passphrase was accepted")
	}
}

// The point of the format: openssl opens what NetPulse writes, and NetPulse
// opens what openssl writes, with the command the UI shows.
func TestOpenSSLInterop(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	if iterations != Iterations {
		t.Fatal("the interop test must run with the real work factor")
	}
	dir := t.TempDir()
	plain := make([]byte, 70_001)
	_, _ = rand.Read(plain)
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte(testPass), 0o600); err != nil {
		t.Fatal(err)
	}
	args := func(dec bool, in, out string) []string {
		a := []string{"enc", "-aes-256-cbc", "-pbkdf2", "-md", "sha256", "-iter", strconv.Itoa(Iterations),
			"-pass", "file:" + passFile, "-in", in, "-out", out}
		if dec {
			a = append([]string{"enc", "-d"}, a[1:]...)
		}
		return a
	}

	encPath := filepath.Join(dir, "ours.enc")
	if err := os.WriteFile(encPath, encrypt(t, plain, testPass, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "ours.dec")
	if out, err := exec.Command("openssl", args(true, encPath, outPath)...).CombinedOutput(); err != nil {
		t.Fatalf("openssl could not decrypt our file: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(outPath); !bytes.Equal(got, plain) {
		t.Fatal("openssl decrypted our file to different bytes")
	}

	inPath := filepath.Join(dir, "plain")
	if err := os.WriteFile(inPath, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(dir, "theirs.enc")
	if out, err := exec.Command("openssl", args(false, inPath, theirs)...).CombinedOutput(); err != nil {
		t.Fatalf("openssl encrypt: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(theirs)
	if got, err := decrypt(t, b, testPass); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("we could not decrypt openssl's file: %v", err)
	}
}
