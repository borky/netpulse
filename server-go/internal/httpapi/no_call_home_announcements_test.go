package httpapi

// FORK: this file exists only in the fork. It is a new file rather than an
// edit to an upstream one so that it can never conflict with a sync.
//
// The announcements feed is the one request this server makes to the
// project's own host, and the only one cmd/netpulse/no_telemetry_test.go
// allows. That makes it the most likely place for a future call home to be
// added: a query parameter, a header, a version in the user agent. A source
// scan cannot see those - they are built in code, next to a URL that is
// allowed - so this test looks at the request itself.
//
// It drives the real start path, with the feed pointed at a local server
// through the override upstream already provides, and fails if the request
// carries anything beyond a plain GET of a static file. If upstream renames
// startAnnouncements or the override, this stops compiling: loud, and a
// one-line fix, which is the right way for a guard to fail.

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

// The only headers the fetch may send. Accept-Encoding is Go's own default.
var allowedAnnouncementHeaders = map[string]string{
	"User-Agent":      "netpulse-announcements",
	"Accept-Encoding": "gzip",
}

func TestTheAnnouncementsFetchCarriesNothingIdentifying(t *testing.T) {
	got := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Clone(r.Context()):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	t.Setenv("NETPULSE_ANNOUNCEMENTS_URL", srv.URL+"/announcements.json")
	(&server{}).startAnnouncements()

	var r *http.Request
	select {
	case r = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the announcements fetch never arrived; the start path or its override has changed")
	}

	var problems []string
	if r.Method != http.MethodGet {
		problems = append(problems, "method is "+r.Method+", want GET")
	}
	if r.URL.Path != "/announcements.json" {
		problems = append(problems, "path became "+r.URL.Path)
	}
	if r.URL.RawQuery != "" {
		problems = append(problems, "query string added: ?"+r.URL.RawQuery)
	}
	if r.ContentLength > 0 {
		problems = append(problems, "the request has a body")
	}
	var names []string
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		want, ok := allowedAnnouncementHeaders[name]
		if !ok {
			problems = append(problems, "extra header "+name+": "+r.Header.Get(name))
			continue
		}
		if v := r.Header.Get(name); v != want {
			problems = append(problems, name+" is "+v+", want "+want)
		}
	}
	if len(problems) > 0 {
		t.Fatalf("the announcements request now carries more than a plain fetch of a static file:\n  %s\n\n"+
			"This fork sends no identifying data anywhere. Read what upstream added before deciding. See FORK.md.",
			strings.Join(problems, "\n  "))
	}
}
