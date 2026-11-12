// Package backupcrypt encrypts NetPulse backup archives with a passphrase,
// the way pfSense and OPNsense encrypt their configuration backups.
//
// The format is OpenSSL's own `enc` file format, so a backup can be opened
// with nothing but openssl, without NetPulse:
//
//	openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 600000 \
//	    -in netpulse-<date>.tar.gz.enc -out netpulse-<date>.tar.gz
//
// Layout: "Salted__", an 8-byte random salt, then AES-256-CBC with PKCS#7
// padding. Key and IV come together from PBKDF2-HMAC-SHA256 over the
// passphrase and salt (48 bytes: 32 of key, 16 of IV), as `openssl enc
// -pbkdf2` derives them.
//
// Like the formats it follows, this is confidentiality, not authentication:
// CBC has no tag, so a modified file is not detected here. Inside, the
// gzip CRC catches corruption; it is not a defence against someone who
// rewrites the file on purpose. Keep backups where only you can write.
package backupcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const (
	// Iterations is the PBKDF2 work factor. 600000 is OWASP's figure for
	// PBKDF2-HMAC-SHA256; it must match the -iter given to openssl.
	Iterations = 600000
	// MinPassphraseLen is the shortest passphrase accepted.
	MinPassphraseLen = 12
	// Ext is appended to an encrypted archive's name.
	Ext = ".enc"
	// DecryptCommand shows how to open a file without NetPulse; %s is the
	// file name without Ext.
	DecryptCommand = "openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -iter 600000 -in %s.enc -out %s"

	magic   = "Salted__"
	saltLen = 8
	keyLen  = 32
)

// iterations is what derive uses: Iterations, lowered only by tests that do
// not check the on-disk format.
var iterations = Iterations

// ErrBadPassphrase is returned when a file does not decrypt: wrong
// passphrase, or not an encrypted backup.
var ErrBadPassphrase = errors.New("backupcrypt: wrong passphrase or not an encrypted backup")

func derive(pass string, salt []byte) (cipher.Block, []byte, error) {
	km, err := pbkdf2.Key(sha256.New, pass, salt, iterations, keyLen+aes.BlockSize)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(km[:keyLen])
	if err != nil {
		return nil, nil, err
	}
	return block, km[keyLen:], nil
}

// writer encrypts in whole blocks and pads the tail on Close.
type writer struct {
	w      io.Writer
	mode   cipher.BlockMode
	buf    []byte
	closed bool
}

// NewWriter returns a writer that encrypts everything written to it into w.
// Close must be called to write the final block; it does not close w.
func NewWriter(w io.Writer, pass string) (io.WriteCloser, error) {
	if pass == "" {
		return nil, errors.New("backupcrypt: empty passphrase")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("backupcrypt: salt: %w", err)
	}
	block, iv, err := derive(pass, salt)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(append([]byte(magic), salt...)); err != nil {
		return nil, err
	}
	return &writer{w: w, mode: cipher.NewCBCEncrypter(block, iv)}, nil
}

func (e *writer) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("backupcrypt: write after close")
	}
	e.buf = append(e.buf, p...)
	if full := len(e.buf) / aes.BlockSize * aes.BlockSize; full > 0 {
		out := make([]byte, full)
		e.mode.CryptBlocks(out, e.buf[:full])
		if _, err := e.w.Write(out); err != nil {
			return 0, err
		}
		e.buf = append(e.buf[:0], e.buf[full:]...)
	}
	return len(p), nil
}

func (e *writer) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	n := aes.BlockSize - len(e.buf)
	last := append(e.buf, bytes.Repeat([]byte{byte(n)}, n)...)
	e.mode.CryptBlocks(last, last)
	_, err := e.w.Write(last)
	return err
}

// reader decrypts, holding back the last block until it knows it is last,
// so the padding can be checked and removed.
type reader struct {
	r    io.Reader
	mode cipher.BlockMode
	held []byte // decrypted, not yet returned; its last block may be padding
	out  []byte // ready to return
	eof  bool
}

// NewReader returns a reader that decrypts r. A wrong passphrase usually
// shows as ErrBadPassphrase at the end of the stream, when the padding
// does not check out.
func NewReader(r io.Reader, pass string) (io.Reader, error) {
	hdr := make([]byte, len(magic)+saltLen)
	if _, err := io.ReadFull(r, hdr); err != nil || string(hdr[:len(magic)]) != magic {
		return nil, ErrBadPassphrase
	}
	block, iv, err := derive(pass, hdr[len(magic):])
	if err != nil {
		return nil, err
	}
	return &reader{r: r, mode: cipher.NewCBCDecrypter(block, iv)}, nil
}

func (d *reader) Read(p []byte) (int, error) {
	for len(d.out) == 0 {
		if d.eof {
			return 0, io.EOF
		}
		chunk := make([]byte, 32*1024)
		n, err := io.ReadFull(d.r, chunk)
		chunk = chunk[:n]
		if n%aes.BlockSize != 0 && (err == io.ErrUnexpectedEOF || err == io.EOF) {
			return 0, ErrBadPassphrase // truncated: not a whole number of blocks
		}
		if n > 0 {
			d.mode.CryptBlocks(chunk, chunk)
			d.held = append(d.held, chunk...)
		}
		switch {
		case err == io.EOF || err == io.ErrUnexpectedEOF:
			d.eof = true
			if len(d.held) == 0 {
				return 0, ErrBadPassphrase
			}
			pad := int(d.held[len(d.held)-1])
			if pad == 0 || pad > aes.BlockSize || pad > len(d.held) {
				return 0, ErrBadPassphrase
			}
			for _, b := range d.held[len(d.held)-pad:] {
				if int(b) != pad {
					return 0, ErrBadPassphrase
				}
			}
			d.out, d.held = d.held[:len(d.held)-pad], nil
		case err != nil:
			return 0, err
		default:
			// Keep the last block back: it may turn out to be the padding.
			keep := len(d.held) - aes.BlockSize
			d.out = append(d.out, d.held[:keep]...)
			d.held = append([]byte(nil), d.held[keep:]...)
		}
	}
	n := copy(p, d.out)
	d.out = d.out[n:]
	return n, nil
}
