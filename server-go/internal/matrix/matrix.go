// Package matrix is a notification channel that posts alerts to a Matrix
// room through the client-server API. It follows the contract of the other
// channels: the engine hands over every event that passes the feed config,
// the urgency and integration gates in main.go trim it, and a queue with
// retries keeps a slow or unreachable homeserver from ever blocking alerts.
//
// Sending is one call:
//
//	PUT {server}/_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}
//	Authorization: Bearer {token}
//
// The transaction id is fixed per alert and reused on every retry, so a
// retry of a send that did land is dropped by the homeserver as a duplicate.
//
// The homeserver URL, the room id and the access token are all sealed with
// kvseal before they reach the kv table.
package matrix

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/gnacho/netpulse/server-go/internal/alerts"
	"github.com/gnacho/netpulse/server-go/internal/kvseal"
)

const (
	kvKeyServer     = "matrix.server"
	kvKeyRoomID     = "matrix.room_id"
	kvKeyToken      = "matrix.token"
	kvKeyEnabled    = "matrix.enabled"
	kvKeyUrgentOnly = "matrix.urgent_only"

	queueCap      = 64
	maxRetries    = 3
	baseRetry     = 2 * time.Second
	maxRetryAfter = 60 * time.Second
	sendTimeout   = 10 * time.Second
	maxMsgLen     = 4096
)

type kvStore interface {
	Get(key string) (string, bool)
	Set(key, value string) error
}

// Config is the channel's settings, in the clear once loaded.
type Config struct {
	Server     string `json:"server"`
	RoomID     string `json:"roomId"`
	Token      string `json:"-"` // write-only: never goes back out through the API
	Enabled    bool   `json:"enabled"`
	UrgentOnly bool   `json:"urgentOnly"`
	// Unreadable: sealed values are stored but this server's key does not
	// open them (the key file was lost or replaced). The channel then acts
	// as unconfigured until the credentials are entered again.
	Unreadable bool `json:"unreadable"`
}

// Configured reports whether every field a send needs is present.
func (c Config) Configured() bool {
	return c.Server != "" && c.RoomID != "" && c.Token != ""
}

// LoadConfig reads and unseals the settings. A nil sealer, or a value it
// cannot open, leaves that field empty and marks the config Unreadable.
func LoadConfig(kv kvStore, s *kvseal.Sealer) Config {
	cfg := Config{UrgentOnly: true}
	for _, f := range []struct {
		key string
		dst *string
	}{
		{kvKeyServer, &cfg.Server},
		{kvKeyRoomID, &cfg.RoomID},
		{kvKeyToken, &cfg.Token},
	} {
		stored, ok := kv.Get(f.key)
		if !ok || stored == "" {
			continue
		}
		if s == nil {
			cfg.Unreadable = true
			continue
		}
		v, err := s.Unseal(f.key, stored)
		if err != nil {
			cfg.Unreadable = true
			continue
		}
		*f.dst = v
	}
	if cfg.Unreadable {
		cfg.Server, cfg.RoomID, cfg.Token = "", "", ""
	}
	if v, ok := kv.Get(kvKeyEnabled); ok {
		cfg.Enabled = v == "true"
	}
	if v, ok := kv.Get(kvKeyUrgentOnly); ok {
		cfg.UrgentOnly = v != "false"
	}
	return cfg
}

// Normalize trims the fields and checks their shape. All three empty means
// "clear the channel" and is valid.
func Normalize(cfg Config) (Config, error) {
	cfg.Server = strings.TrimRight(strings.TrimSpace(cfg.Server), "/")
	cfg.RoomID = strings.TrimSpace(cfg.RoomID)
	cfg.Token = strings.TrimSpace(cfg.Token)
	if cfg.Server == "" && cfg.RoomID == "" && cfg.Token == "" {
		return cfg, nil
	}
	if !cfg.Configured() {
		return cfg, errors.New("homeserver URL, room id and access token are all required")
	}
	u, err := url.Parse(cfg.Server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return cfg, errors.New("homeserver must be an http(s) URL, e.g. https://matrix.example.org")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return cfg, errors.New("homeserver URL must not carry credentials, a query or a fragment")
	}
	if u.Scheme == "http" && !plainHTTPAllowed(u.Hostname()) {
		return cfg, errors.New("use https: the access token would cross the network in the clear (plain http is accepted only for localhost or a private address)")
	}
	if !strings.HasPrefix(cfg.RoomID, "!") || strings.ContainsAny(cfg.RoomID, " \t\r\n/") {
		return cfg, errors.New("room id must start with ! (an alias such as #room:server is not a room id)")
	}
	if strings.ContainsAny(cfg.Token, " \t\r\n") {
		return cfg, errors.New("access token must not contain whitespace")
	}
	return cfg, nil
}

// plainHTTPAllowed: http is accepted only where the token never leaves the
// host or the local network.
func plainHTTPAllowed(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// SaveConfig normalizes, seals and stores the settings.
func SaveConfig(kv kvStore, s *kvseal.Sealer, cfg Config) error {
	cfg, err := Normalize(cfg)
	if err != nil {
		return err
	}
	if s == nil {
		return errors.New("secret storage is not available")
	}
	for _, f := range []struct{ key, val string }{
		{kvKeyServer, cfg.Server},
		{kvKeyRoomID, cfg.RoomID},
		{kvKeyToken, cfg.Token},
	} {
		sealed, err := s.Seal(f.key, f.val)
		if err != nil {
			return err
		}
		if err := kv.Set(f.key, sealed); err != nil {
			return fmt.Errorf("save %s: %w", f.key, err)
		}
	}
	if err := kv.Set(kvKeyEnabled, strconv.FormatBool(cfg.Enabled)); err != nil {
		return fmt.Errorf("save enabled: %w", err)
	}
	if err := kv.Set(kvKeyUrgentOnly, strconv.FormatBool(cfg.UrgentOnly)); err != nil {
		return fmt.Errorf("save urgent_only: %w", err)
	}
	return nil
}

// Notifier satisfies alerts.Notifier.
type Notifier struct {
	kv        kvStore
	sealer    *kvseal.Sealer
	queue     chan alerts.AlertEvent
	done      chan struct{}
	wg        sync.WaitGroup
	client    *http.Client
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	txnSeq    atomic.Uint64
}

// NewNotifier starts the queue worker. It runs whether or not the channel
// is configured: the worker reads the config per event, so the channel can
// be turned on from the UI without a restart.
func NewNotifier(kv kvStore, s *kvseal.Sealer) *Notifier {
	n := newNotifier(kv, s)
	n.wg.Add(1)
	go n.worker()
	return n
}

func newNotifier(kv kvStore, s *kvseal.Sealer) *Notifier {
	ctx, cancel := context.WithCancel(context.Background())
	return &Notifier{
		kv:     kv,
		sealer: s,
		queue:  make(chan alerts.AlertEvent, queueCap),
		done:   make(chan struct{}),
		client: &http.Client{Timeout: sendTimeout},
		ctx:    ctx,
		cancel: cancel,
	}
}

func (n *Notifier) Notify(ev alerts.AlertEvent) {
	select {
	case n.queue <- ev:
	default:
		slog.Warn("matrix: queue full, dropping alert", "title", ev.Title)
	}
}

// Close stops the worker and cancels a send in flight. Safe to call twice.
func (n *Notifier) Close() {
	n.closeOnce.Do(func() {
		n.cancel()
		close(n.done)
	})
	n.wg.Wait()
}

func (n *Notifier) worker() {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case ev := <-n.queue:
			cfg := LoadConfig(n.kv, n.sealer)
			if !cfg.Enabled || !cfg.Configured() {
				continue
			}
			if err := n.sendWithRetry(cfg, ev); err != nil {
				slog.Error("matrix: send failed after retries", "error", LogSafe(err), "title", ev.Title)
			}
		}
	}
}

// newTxnID is unique per message within this process and across restarts.
func (n *Notifier) newTxnID() string {
	return fmt.Sprintf("netpulse-%d-%d", time.Now().UnixNano(), n.txnSeq.Add(1))
}

func (n *Notifier) sendWithRetry(cfg Config, ev alerts.AlertEvent) error {
	msg := buildMessage(ev)
	txnID := n.newTxnID()
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := baseRetry * time.Duration(1<<(attempt-1))
			var ae *apiError
			if errors.As(lastErr, &ae) && ae.RetryAfter > 0 {
				backoff = min(ae.RetryAfter, maxRetryAfter)
			}
			select {
			case <-time.After(backoff):
			case <-n.done:
				return errors.New("shutdown during retry")
			}
		}
		if err := n.send(cfg, txnID, msg); err != nil {
			lastErr = err
			if !isRetryable(err) {
				return err
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("max retries: %w", lastErr)
}

// message is the m.room.message content: plain body plus an HTML rendering.
type message struct {
	MsgType       string `json:"msgtype"`
	Body          string `json:"body"`
	Format        string `json:"format,omitempty"`
	FormattedBody string `json:"formatted_body,omitempty"`
}

// buildMessage renders an alert. Urgent alerts are m.text; the rest are
// m.notice, which clients show without a notification sound by default -
// the Matrix counterpart of Telegram's silent messages.
func buildMessage(ev alerts.AlertEvent) message {
	severity := "⚠️"
	msgType := "m.notice"
	if ev.Urgent {
		severity = "🔴"
		msgType = "m.text"
	}
	if ev.Ts <= 0 {
		ev.Ts = time.Now().Unix()
	}
	ts := time.Unix(ev.Ts, 0).Format("15:04:05")
	desc := ev.Description
	if len(desc) > 500 {
		desc = truncateUTF8(desc, 500) + "..."
	}

	var plain, rich strings.Builder
	fmt.Fprintf(&plain, "%s %s\n", severity, ev.Title)
	fmt.Fprintf(&rich, "%s <b>%s</b>", severity, html.EscapeString(ev.Title))
	if desc != "" {
		plain.WriteString(desc + "\n")
		rich.WriteString("<br>" + html.EscapeString(desc))
	}
	if ev.RouterID != "" {
		fmt.Fprintf(&plain, "📡 %s\n", ev.RouterID)
		fmt.Fprintf(&rich, "<br>📡 %s", html.EscapeString(ev.RouterID))
	}
	if ev.Hint != "" {
		fmt.Fprintf(&plain, "💡 %s\n", ev.Hint)
		fmt.Fprintf(&rich, "<br>💡 <i>%s</i>", html.EscapeString(ev.Hint))
	}
	fmt.Fprintf(&plain, "🕐 %s", ts)
	fmt.Fprintf(&rich, "<br>🕐 %s", ts)

	m := message{MsgType: msgType, Body: plain.String()}
	if len(m.Body) > maxMsgLen {
		m.Body = truncateUTF8(m.Body, maxMsgLen-3) + "..."
	}
	// The HTML is dropped rather than cut when too long: a cut could leave
	// an open tag.
	if r := rich.String(); len(r) <= maxMsgLen {
		m.Format = "org.matrix.custom.html"
		m.FormattedBody = r
	}
	return m
}

// apiError is a non-2xx answer from the homeserver.
type apiError struct {
	Status     int
	ErrCode    string
	Message    string
	RetryAfter time.Duration
}

func (e *apiError) Error() string {
	if e.ErrCode != "" {
		return fmt.Sprintf("status %d: %s: %s", e.Status, e.ErrCode, e.Message)
	}
	return fmt.Sprintf("status %d: %s", e.Status, e.Message)
}

// transportError drops the request URL from a client error: it carries the
// room id, which is stored sealed and should not land in the journal.
type transportError struct{ err error }

func (e *transportError) Error() string {
	var ue *url.Error
	if errors.As(e.err, &ue) {
		return ue.Op + ": " + ue.Err.Error()
	}
	return e.err.Error()
}
func (e *transportError) Unwrap() error { return e.err }

// LogSafe renders err for the journal. The homeserver's own error text can
// name the room ("User ... not in room !id"), and DNS and TLS errors name the
// host, both of which are stored sealed: keep the status, the Matrix errcode
// and the kind of network failure only. The full text still goes back to the
// admin from Validate and SendTest.
func LogSafe(err error) string {
	if err == nil {
		return ""
	}
	var ae *apiError
	if errors.As(err, &ae) {
		if ae.ErrCode != "" {
			return fmt.Sprintf("status %d %s", ae.Status, ae.ErrCode)
		}
		return fmt.Sprintf("status %d", ae.Status)
	}
	var te *transportError
	if !errors.As(err, &te) {
		return err.Error() // our own messages carry no secrets
	}
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		return "transport: dns lookup failed"
	case errors.As(err, &certErr):
		return "transport: tls certificate rejected"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "transport: timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "transport: connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "transport: connection reset"
	default:
		return "transport: request failed"
	}
}

// roomPath escapes a room id for use as one path segment: ! becomes %21
// and the :server part, when the id has one, keeps its colon escaped too.
func roomPath(roomID string) string {
	return strings.ReplaceAll(url.PathEscape(roomID), ":", "%3A")
}

func (n *Notifier) send(cfg Config, txnID string, m message) error {
	body, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	u := cfg.Server + "/_matrix/client/v3/rooms/" + roomPath(cfg.RoomID) +
		"/send/m.room.message/" + url.PathEscape(txnID)
	_, err = n.do(http.MethodPut, u, cfg.Token, body)
	return err
}

// do runs one authenticated call and returns the body of a 2xx answer.
func (n *Notifier) do(method, u, token string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(n.ctx, sendTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, &transportError{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return nil, &transportError{err: err}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return respBody, nil
	}
	ae := &apiError{Status: resp.StatusCode}
	var mErr struct {
		ErrCode      string `json:"errcode"`
		Error        string `json:"error"`
		RetryAfterMs int64  `json:"retry_after_ms"`
	}
	if json.Unmarshal(respBody, &mErr) == nil && (mErr.ErrCode != "" || mErr.Error != "") {
		ae.ErrCode, ae.Message = mErr.ErrCode, mErr.Error
	} else {
		ae.Message = strings.TrimSpace(string(respBody))
		if len(ae.Message) > 200 {
			ae.Message = truncateUTF8(ae.Message, 200) + "..."
		}
	}
	if mErr.RetryAfterMs > 0 {
		ae.RetryAfter = time.Duration(mErr.RetryAfterMs) * time.Millisecond
	} else if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
		ae.RetryAfter = time.Duration(secs) * time.Second
	}
	return nil, ae
}

// isRetryable: 5xx, 429 and transient network errors. A 4xx (bad token,
// not in the room), a bad URL, DNS or TLS failure will not fix itself.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status >= 500 || ae.Status == http.StatusTooManyRequests
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	for _, target := range []error{
		syscall.ECONNREFUSED,
		syscall.ECONNRESET,
		syscall.ECONNABORTED,
		syscall.EPIPE,
		io.ErrUnexpectedEOF,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// Validate checks the token with whoami and that its user has joined the
// room, and returns the bot's user id.
func Validate(cfg Config) (string, error) {
	n := newNotifier(nil, nil)
	defer n.Close()
	return n.validate(cfg)
}

func (n *Notifier) validate(cfg Config) (string, error) {
	raw, err := n.do(http.MethodGet, cfg.Server+"/_matrix/client/v3/account/whoami", cfg.Token, nil)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
			return "", fmt.Errorf("the homeserver refused the access token (%s)", ae.ErrCode)
		}
		return "", fmt.Errorf("whoami: %w", err)
	}
	var who struct {
		UserID string `json:"user_id"`
	}
	if err := json.Unmarshal(raw, &who); err != nil || who.UserID == "" {
		return "", errors.New("whoami: the answer carries no user id - is this a Matrix homeserver?")
	}
	raw, err = n.do(http.MethodGet, cfg.Server+"/_matrix/client/v3/rooms/"+roomPath(cfg.RoomID)+"/joined_members", cfg.Token, nil)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && (ae.Status == http.StatusForbidden || ae.Status == http.StatusNotFound) {
			return who.UserID, fmt.Errorf("%s has not joined that room: invite it and accept the invite first", who.UserID)
		}
		return who.UserID, fmt.Errorf("joined_members: %w", err)
	}
	var members struct {
		Joined map[string]json.RawMessage `json:"joined"`
	}
	if err := json.Unmarshal(raw, &members); err == nil && members.Joined != nil {
		if _, ok := members.Joined[who.UserID]; !ok {
			return who.UserID, fmt.Errorf("%s has not joined that room: invite it and accept the invite first", who.UserID)
		}
	}
	return who.UserID, nil
}

// SendTest posts a test message with the stored config. Like the worker it
// requires the channel to be enabled.
func SendTest(kv kvStore, s *kvseal.Sealer) error {
	cfg := LoadConfig(kv, s)
	if cfg.Unreadable {
		return errors.New("the stored Matrix credentials cannot be decrypted: enter them again")
	}
	if !cfg.Enabled {
		return errors.New("the Matrix channel is disabled")
	}
	if !cfg.Configured() {
		return errors.New("homeserver URL, room id and access token are required")
	}
	n := newNotifier(kv, s)
	defer n.Close()
	return n.send(cfg, n.newTxnID(), message{
		MsgType: "m.text",
		Body:    "✅ NetPulse Matrix notifications configured successfully.",
	})
}

// truncateUTF8 cuts s to at most maxBytes without splitting a rune.
func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size > 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
