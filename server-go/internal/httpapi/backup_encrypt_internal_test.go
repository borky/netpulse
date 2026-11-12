package httpapi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gnacho/netpulse/server-go/internal/backupcrypt"
	"github.com/gnacho/netpulse/server-go/internal/kvseal"
)

const testBackupPass = "dummy backup passphrase"

// newSealedBackupServer is newBackupTestServer with the data directory's
// kvseal key, as main wires it.
func newSealedBackupServer(t *testing.T) (*server, string) {
	t.Helper()
	s, dataDir := newBackupTestServer(t)
	sealer, err := kvseal.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	s.secrets = sealer
	return s, dataDir
}

func setBackupPassphrase(t *testing.T, s *server, pass string) {
	t.Helper()
	sealed, err := s.secrets.Seal(kvBackupPassphrase, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO kv (key, value) VALUES (?, ?)", kvBackupPassphrase, sealed); err != nil {
		t.Fatal(err)
	}
}

// tarNames lists an archive's entries, from plain gzip bytes.
func tarNames(t *testing.T, gz io.Reader) []string {
	t.Helper()
	zr, err := gzip.NewReader(gz)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(zr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		names = append(names, strings.TrimSuffix(hdr.Name, "/"))
	}
}

func hasEntry(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// Without a passphrase the archive is plain, as upstream writes it, and now
// carries secrets.key: restored without it, kvseal values do not open.
func TestPlainBackupCarriesTheSealKey(t *testing.T) {
	s, _ := newSealedBackupServer(t)
	dst, err := s.runBackup()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dst, ".tar.gz") {
		t.Fatalf("plain backup named %s", dst)
	}
	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if names := tarNames(t, f); !hasEntry(names, kvseal.KeyFile) || !hasEntry(names, "netpulse.db") {
		t.Fatalf("archive entries %v lack %s or the database", names, kvseal.KeyFile)
	}
}

// With a passphrase the file is encrypted from its first byte, opens with
// the passphrase, and holds the same archive.
func TestEncryptedBackup(t *testing.T) {
	s, dataDir := newSealedBackupServer(t)
	setBackupPassphrase(t, s, testBackupPass)
	dst, err := s.runBackup()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dst, ".tar.gz"+backupcrypt.Ext) {
		t.Fatalf("encrypted backup named %s", dst)
	}
	if fi, _ := os.Stat(dst); fi.Mode().Perm() != backupFileMode {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("Salted__")) || bytes.Contains(raw, []byte("SQLite format 3")) {
		t.Fatal("the backup is not encrypted")
	}
	r, err := backupcrypt.NewReader(bytes.NewReader(raw), testBackupPass)
	if err != nil {
		t.Fatal(err)
	}
	names := tarNames(t, r)
	if !hasEntry(names, "netpulse.db") || !hasEntry(names, kvseal.KeyFile) {
		t.Fatalf("decrypted archive entries %v", names)
	}
	// The purge counts encrypted archives as backups.
	if !isBackupFile(filepath.Base(dst)) {
		t.Fatal("isBackupFile does not recognise an encrypted backup")
	}
	_ = dataDir
}

// A stored passphrase this server cannot open stops the backup; it never
// falls back to writing the archive unencrypted.
func TestUnreadablePassphraseFailsClosed(t *testing.T) {
	s, dataDir := newSealedBackupServer(t)
	setBackupPassphrase(t, s, testBackupPass)
	other, err := kvseal.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.secrets = other
	if _, err := s.runBackup(); !errors.Is(err, errBackupPassphraseUnreadable) {
		t.Fatalf("runBackup err = %v, want errBackupPassphraseUnreadable", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dataDir, "backups"))
	for _, e := range entries {
		if isBackupFile(e.Name()) {
			t.Fatalf("a backup was written anyway: %s", e.Name())
		}
	}
	if v := s.backupView(); v.Encrypted || !v.PassphraseUnreadable {
		t.Fatalf("view %+v", v)
	}
}

// Nothing but the archive stays in backups/: the plaintext snapshot and the
// half-written file are gone once a backup is written.
func TestEncryptedBackupLeavesNoPlaintext(t *testing.T) {
	s, dataDir := newSealedBackupServer(t)
	setBackupPassphrase(t, s, testBackupPass)
	dst, err := s.runBackup()
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dataDir, "backups"))
	for _, e := range entries {
		if e.Name() != filepath.Base(dst) {
			t.Fatalf("left behind in backups/: %s", e.Name())
		}
	}
}

func TestCleanBackupLeftovers(t *testing.T) {
	dir := t.TempDir()
	keep := []string{"netpulse-20260101-000000.tar.gz", "netpulse-20260101-000000.tar.gz.enc"}
	for _, n := range append([]string{"netpulse-x.tar.gz.tmp", "netpulse-x.tar.gz.tmp.db"}, keep...) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{snapshotDirPrefix + "1", exportDirPrefix + "2"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cleanBackupLeftovers(dir)
	entries, _ := os.ReadDir(dir)
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if len(left) != len(keep) || !hasEntry(left, keep[0]) || !hasEntry(left, keep[1]) {
		t.Fatalf("after cleanup: %v, want only %v", left, keep)
	}
}
