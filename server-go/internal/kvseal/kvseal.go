// Package kvseal encrypts secrets before they are written to the kv table.
//
// The database is the file that gets copied around: backups, a support
// bundle, a disk image. A secret sealed here is useless without the key,
// which lives in its own 0600 file in the data directory, next to the TLS
// CA key and outside the database. Losing that file makes the sealed values
// unreadable: the channel then reports itself as not configured and the
// admin enters the credentials again.
//
// AES-256-GCM, a fresh random nonce per value, and the kv key name as
// associated data, so a sealed value copied into another key does not open.
package kvseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyFile is the key's file name inside the data directory.
const KeyFile = "secrets.key"

const (
	keyLen = 32
	prefix = "enc:v1:"
)

// ErrNotSealed is returned by Unseal for a value that was never sealed.
var ErrNotSealed = errors.New("kvseal: value is not sealed")

// Sealer seals and unseals values with the key of one data directory.
type Sealer struct {
	aead cipher.AEAD
}

// Open loads the key from dir, creating it on first use.
func Open(dir string) (*Sealer, error) {
	if dir == "" {
		return nil, errors.New("kvseal: no data directory")
	}
	key, err := loadOrCreateKey(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, err
	}
	return newSealer(key)
}

func newSealer(key []byte) (*Sealer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kvseal: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kvseal: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	key, err := readKey(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	created, err := createKey(path)
	if err == nil || !errors.Is(err, os.ErrExist) {
		return created, err
	}
	// Another process created the key between the read and the link: read
	// it once more. Still missing means something that is not a key sits at
	// the path (a dangling symlink reads as missing yet blocks the link).
	key, err = readKey(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("kvseal: %s exists but cannot be read as a key (dangling symlink?)", path)
	}
	return key, err
}

func readKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, fmt.Errorf("kvseal: read key: %w", err)
	}
	if len(key) != keyLen {
		return nil, fmt.Errorf("kvseal: %s holds %d bytes, want %d", path, len(key), keyLen)
	}
	return key, nil
}

// createKey writes a new key to path. It fails with an os.ErrExist error if
// something is already there.
func createKey(path string) ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("kvseal: generate key: %w", err)
	}
	// Write a temp file and hard-link it into place: the key appears whole
	// or not at all, and if another process created it first the link fails
	// and that key is the one read back.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+KeyFile+"-*")
	if err != nil {
		return nil, fmt.Errorf("kvseal: create key: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("kvseal: create key: %w", err)
	}
	if _, err := tmp.Write(key); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("kvseal: write key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, fmt.Errorf("kvseal: write key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("kvseal: write key: %w", err)
	}
	if err := os.Link(name, path); err != nil {
		return nil, fmt.Errorf("kvseal: install key: %w", err)
	}
	return key, nil
}

// Seal encrypts plaintext for the kv key name. An empty plaintext stays
// empty, so "not configured" needs no key to read.
func (s *Sealer) Seal(name, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("kvseal: nonce: %w", err)
	}
	out := s.aead.Seal(nonce, nonce, []byte(plaintext), []byte(name))
	return prefix + base64.RawStdEncoding.EncodeToString(out), nil
}

// Unseal decrypts a value Seal produced for the same kv key name.
func (s *Sealer) Unseal(name, stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, prefix) {
		return "", ErrNotSealed
	}
	raw, err := base64.RawStdEncoding.DecodeString(stored[len(prefix):])
	if err != nil {
		return "", fmt.Errorf("kvseal: decode: %w", err)
	}
	ns := s.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("kvseal: value too short")
	}
	pt, err := s.aead.Open(nil, raw[:ns], raw[ns:], []byte(name))
	if err != nil {
		return "", errors.New("kvseal: cannot decrypt (wrong key or tampered value)")
	}
	return string(pt), nil
}
