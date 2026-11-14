package radiusbackup

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

const secret = "dummy-radius-secret"

func request(t *testing.T, id byte, mac, key string) []byte {
	t.Helper()
	body := append(append([]byte{attrCallingStation, byte(2 + len(mac))}, mac...), append([]byte{attrMessageAuth, 18}, make([]byte, 16)...)...)
	b := make([]byte, headerLen+len(body))
	b[0], b[1] = accessRequest, id
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	for i := 4; i < 20; i++ {
		b[i] = byte(i * 3)
	}
	copy(b[headerLen:], body)
	m := hmac.New(md5.New, []byte(key))
	m.Write(b)
	copy(b[len(b)-16:], m.Sum(nil))
	return b
}

func code(t *testing.T, resp, req []byte) byte {
	t.Helper()
	if resp == nil {
		return 0
	}
	check := append([]byte(nil), resp...)
	copy(check[4:20], req[4:20])
	sum := md5.Sum(append(append([]byte(nil), check...), secret...))
	if !bytes.Equal(sum[:], resp[4:20]) {
		t.Fatal("bad Response Authenticator")
	}
	if resp[20] != attrMessageAuth {
		t.Fatal("Message-Authenticator not first")
	}
	return resp[0]
}

func store(now time.Time) *Store {
	s := &Store{routers: map[string]*router{}, now: func() time.Time { return now }, started: true}
	return s
}

func TestBackupAnswersLikeThePanel(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := store(now)
	s.Update("gateway", &probe.QuarantineRadiusInfo{Secret: secret, Enforce: true, Approved: []string{"02:00:00:00:00:0A"}})
	req := request(t, 1, "02-00-00-00-00-0A", secret)
	if c := code(t, s.Handle(req), req); c != accessAccept {
		t.Fatalf("approved: %d", c)
	}
	req = request(t, 2, "02-00-00-00-00-0B", secret)
	if c := code(t, s.Handle(req), req); c != accessReject {
		t.Fatalf("unknown: %d", c)
	}
	// A pause accepts everyone; the quarantine off too.
	s.Update("gateway", &probe.QuarantineRadiusInfo{Secret: secret, Enforce: true, PauseUntil: now.Add(time.Minute).Unix(), PauseKind: "learn"})
	if c := code(t, s.Handle(req), req); c != accessAccept {
		t.Fatalf("during a pause: %d", c)
	}
	s.Update("gateway", &probe.QuarantineRadiusInfo{Secret: secret, Enforce: false})
	if c := code(t, s.Handle(req), req); c != accessAccept {
		t.Fatalf("quarantine off: %d", c)
	}
}

func TestBackupDropsUnsignedAndUnknownSecrets(t *testing.T) {
	s := store(time.Now())
	s.Update("gateway", &probe.QuarantineRadiusInfo{Secret: secret, Enforce: true})
	if s.Handle(request(t, 1, "02-00-00-00-00-0A", "another-secret")) != nil {
		t.Fatal("answered a request signed with another secret")
	}
	unsigned := request(t, 2, "02-00-00-00-00-0A", secret)
	unsigned[len(unsigned)-1] ^= 1
	if s.Handle(unsigned) != nil {
		t.Fatal("answered a request with a bad Message-Authenticator")
	}
	if s.Handle([]byte{1, 2, 3}) != nil {
		t.Fatal("answered garbage")
	}
}

func TestBackupIgnoresDataWithoutASecret(t *testing.T) {
	s := store(time.Now())
	s.Update("gateway", &probe.QuarantineRadiusInfo{Enforce: true})
	s.Update("gateway", nil)
	if len(s.routers) != 0 {
		t.Fatal("stored data without a secret")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{1, 1, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, err := parse(b); err == nil {
			_ = verify(p, []byte("x"))
		}
	})
}
