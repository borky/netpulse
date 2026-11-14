// Package radiusbackup answers RADIUS MAC authentication for routers whose
// panel (NetGrip) runs the device quarantine, while that panel cannot: the
// access points list this server as their second RADIUS server.
//
// Each router's agent sends, over HTTPS with a pinned key only, the shared
// secret, the approved MACs and whether the quarantine is enforcing. It is
// kept in memory, apart from the rest of the push, never written to the
// database or returned by the API. A request is answered by the router whose
// secret signs it (Message-Authenticator, RFC 3579, required); answers carry
// one first (BlastRADIUS). The backup never approves anything: during a
// pause it accepts every device, as the panel would, but records nothing.
//
// The listener starts with the first router's data (address from
// NETPULSE_RADIUS_ADDR, default ":1812"; "off" disables it), so a server
// whose routers do not use this never opens the port.
package radiusbackup

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

const (
	accessRequest = 1
	accessAccept  = 2
	accessReject  = 3

	attrUserName       = 1
	attrCallingStation = 31
	attrMessageAuth    = 80

	headerLen = 20
	maxLen    = 4096
)

type router struct {
	secret   []byte
	enforce  bool
	approved map[string]bool
	pauseTil time.Time
	at       time.Time
}

// Store holds each router's latest RADIUS data.
type Store struct {
	mu      sync.Mutex
	routers map[string]*router
	started bool
	addr    string
	now     func() time.Time
}

// Default is the server-wide store the push handler feeds.
var Default = &Store{routers: map[string]*router{}, addr: os.Getenv("NETPULSE_RADIUS_ADDR"), now: time.Now}

// Update records a router's data. It must be called only for a push that
// arrived over TLS (the caller checks); the listener starts on first use.
func (s *Store) Update(slug string, info *probe.QuarantineRadiusInfo) {
	if info == nil || info.Secret == "" {
		return
	}
	r := &router{secret: []byte(info.Secret), enforce: info.Enforce, approved: map[string]bool{}, at: s.now()}
	for _, m := range info.Approved {
		if mac := normMAC(m); mac != "" {
			r.approved[mac] = true
		}
	}
	if info.PauseUntil > 0 && (info.PauseKind == "learn" || info.PauseKind == "off") {
		r.pauseTil = time.Unix(info.PauseUntil, 0)
	}
	s.mu.Lock()
	s.routers[slug] = r
	start := !s.started
	s.started = true
	s.mu.Unlock()
	if start {
		go s.listen()
	}
}

// Has reports whether a router's data is held.
func (s *Store) Has(slug string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.routers[slug]
	return ok
}

func (s *Store) listen() {
	addr := s.addr
	if addr == "" {
		addr = ":1812"
	}
	if strings.EqualFold(addr, "off") {
		log.Printf("[netpulse] radius backup: disabled (NETPULSE_RADIUS_ADDR=off)")
		return
	}
	for {
		c, err := net.ListenPacket("udp", addr)
		if err != nil {
			log.Printf("[netpulse] radius backup: listen %s: %v (retrying in 30s)", addr, err)
			time.Sleep(30 * time.Second)
			continue
		}
		log.Printf("[netpulse] radius backup: answering on %s", addr)
		buf := make([]byte, maxLen)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				break
			}
			if resp := s.Handle(buf[:n]); resp != nil {
				_, _ = c.WriteTo(resp, from)
			}
		}
		_ = c.Close()
	}
}

// Handle answers one datagram, or returns nil to drop it.
func (s *Store) Handle(b []byte) []byte {
	p, err := parse(b)
	if err != nil || p.code != accessRequest {
		return nil
	}
	s.mu.Lock()
	var r *router
	for _, cand := range s.routers {
		if verify(p, cand.secret) {
			r = cand
			break
		}
	}
	now := s.now()
	s.mu.Unlock()
	if r == nil {
		return nil // no router's secret signs it
	}
	mac := ""
	if v := p.attr(attrCallingStation); v != nil {
		mac = normMAC(string(v))
	}
	if mac == "" {
		if v := p.attr(attrUserName); v != nil {
			mac = normMAC(string(v))
		}
	}
	code := byte(accessReject)
	if mac != "" && decide(r, mac, now) {
		code = accessAccept
	}
	return respond(code, p, r.secret)
}

// decide mirrors the panel: off accepts all, approved MACs and any device
// during a pause are accepted, the rest refused.
func decide(r *router, mac string, now time.Time) bool {
	return !r.enforce || r.approved[mac] || now.Before(r.pauseTil)
}

type packet struct {
	code, id byte
	auth     [16]byte
	attrs    [][2][]byte // {type}, value
	raw      []byte
}

func (p *packet) attr(t byte) []byte {
	for _, a := range p.attrs {
		if a[0][0] == t {
			return a[1]
		}
	}
	return nil
}

func parse(b []byte) (*packet, error) {
	if len(b) < headerLen || len(b) > maxLen {
		return nil, errors.New("bad size")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < headerLen || n > len(b) {
		return nil, errors.New("bad length")
	}
	b = b[:n]
	p := &packet{code: b[0], id: b[1], raw: append([]byte(nil), b...)}
	copy(p.auth[:], b[4:20])
	for i := headerLen; i < n; {
		if i+2 > n {
			return nil, errors.New("truncated attribute")
		}
		l := int(b[i+1])
		if l < 2 || i+l > n {
			return nil, errors.New("bad attribute")
		}
		p.attrs = append(p.attrs, [2][]byte{{b[i]}, append([]byte(nil), b[i+2:i+l]...)})
		i += l
	}
	return p, nil
}

// verify checks the request's single Message-Authenticator.
func verify(p *packet, secret []byte) bool {
	var got []byte
	count := 0
	for _, a := range p.attrs {
		if a[0][0] == attrMessageAuth {
			got = a[1]
			count++
		}
	}
	if count != 1 || len(got) != 16 {
		return false
	}
	buf := append([]byte(nil), p.raw...)
	for i := headerLen; i < len(buf); {
		l := int(buf[i+1])
		if buf[i] == attrMessageAuth {
			for j := i + 2; j < i+l; j++ {
				buf[j] = 0
			}
		}
		i += l
	}
	m := hmac.New(md5.New, secret)
	m.Write(buf)
	return hmac.Equal(m.Sum(nil), got)
}

// respond builds Accept/Reject: Message-Authenticator first, then the
// Response Authenticator.
func respond(code byte, req *packet, secret []byte) []byte {
	b := make([]byte, headerLen+18)
	b[0], b[1] = code, req.id
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[4:20], req.auth[:])
	b[20], b[21] = attrMessageAuth, 18
	m := hmac.New(md5.New, secret)
	m.Write(b)
	copy(b[22:38], m.Sum(nil))
	sum := md5.Sum(append(append([]byte(nil), b...), secret...))
	copy(b[4:20], sum[:])
	return b
}

func normMAC(v string) string {
	hexs := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + 'a' - 'A'
		}
		return -1
	}, v)
	if len(hexs) != 12 {
		return ""
	}
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = hexs[2*i : 2*i+2]
	}
	return strings.Join(parts, ":")
}
