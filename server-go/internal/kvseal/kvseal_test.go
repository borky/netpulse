package kvseal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSealRoundTripAndNoPlaintextAtRest(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal("matrix.token", "syt_dummy_token")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, prefix) || strings.Contains(sealed, "syt_dummy_token") {
		t.Fatalf("sealed value leaks the plaintext or lacks the prefix: %q", sealed)
	}
	got, err := s.Unseal("matrix.token", sealed)
	if err != nil || got != "syt_dummy_token" {
		t.Fatalf("unseal = %q, %v", got, err)
	}
	again, _ := s.Seal("matrix.token", "syt_dummy_token")
	if again == sealed {
		t.Fatal("two seals of the same value are identical: the nonce is not fresh")
	}
}

func TestEmptyStaysEmpty(t *testing.T) {
	s, _ := Open(t.TempDir())
	if v, _ := s.Seal("k", ""); v != "" {
		t.Fatalf("seal(\"\") = %q", v)
	}
	if v, err := s.Unseal("k", ""); v != "" || err != nil {
		t.Fatalf("unseal(\"\") = %q, %v", v, err)
	}
}

func TestValueDoesNotOpenUnderAnotherName(t *testing.T) {
	s, _ := Open(t.TempDir())
	sealed, _ := s.Seal("matrix.room_id", "!dummy")
	if _, err := s.Unseal("matrix.token", sealed); err == nil {
		t.Fatal("a value sealed for one key opened under another")
	}
}

func TestPlaintextIsRefused(t *testing.T) {
	s, _ := Open(t.TempDir())
	if _, err := s.Unseal("k", "plain"); !errors.Is(err, ErrNotSealed) {
		t.Fatalf("err = %v, want ErrNotSealed", err)
	}
}

func TestKeyPersistsAndIsPrivate(t *testing.T) {
	dir := t.TempDir()
	s1, _ := Open(dir)
	sealed, _ := s1.Seal("k", "v")
	fi, err := os.Stat(filepath.Join(dir, KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, want 0600", fi.Mode().Perm())
	}
	s2, _ := Open(dir)
	if got, err := s2.Unseal("k", sealed); err != nil || got != "v" {
		t.Fatalf("a reopened key cannot read its own value: %q, %v", got, err)
	}
	other, _ := Open(t.TempDir())
	if _, err := other.Unseal("k", sealed); err == nil {
		t.Fatal("another data directory's key opened the value")
	}
}

func TestConcurrentFirstOpenAgreesOnOneKey(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	sealers := make([]*Sealer, 8)
	for i := range sealers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := Open(dir)
			if err != nil {
				t.Error(err)
				return
			}
			sealers[i] = s
		}(i)
	}
	wg.Wait()
	sealed, _ := sealers[0].Seal("k", "v")
	for i, s := range sealers {
		if s == nil {
			continue
		}
		if got, err := s.Unseal("k", sealed); err != nil || got != "v" {
			t.Fatalf("sealer %d holds a different key", i)
		}
	}
}

func TestShortKeyFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, KeyFile), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("a truncated key file was accepted")
	}
}

func TestDanglingSymlinkIsAnErrorNotALoop(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, KeyFile)); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("a dangling symlink was accepted as a key")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestNoDataDirIsAnError(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("an empty data directory was accepted")
	}
}
