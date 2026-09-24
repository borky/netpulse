package main

// FORK: this file exists only in the fork. It is a new file rather than an
// edit to an upstream one so that it can never conflict with a sync.
//
// Upstream added an anonymous daily instance ping (#822): a GET carrying a
// persistent random instance id, the version and the OS, sent to the
// project's server and on by default. The owner of this fork does not send
// identifying data anywhere, and a persistent id is identifying: it ties one
// installation together across every ping for as long as it runs.
//
// The fork keeps upstream's telemetry package in the tree, untouched, and only
// removes the two lines in main.go that wire it in. Unreferenced, the package
// is not linked into the binary at all - there is no code to switch on - and
// because its source is left alone, upstream's future changes to it merge
// without conflicts.
//
// The risk in that arrangement is a sync that brings the ping back. This test
// reads the source rather than asking the toolchain what it would link: a
// dependency-graph check only sees the host platform with default build tags,
// so a file limited to arm64, or behind a build tag, could re-link the package
// into the real deploy build while the check passed. Reading every .go file,
// whatever its constraints, closes that. It fails on:
//
//   - any import of the telemetry package outside the package itself;
//   - its switch, NETPULSE_TELEMETRY, anywhere else - a reference to the
//     switch is a sign the thing it switches is back;
//   - any request to the project's own host other than the announcements
//     feed, which is a static file fetched with no parameters. That last rule
//     also catches the ping rebuilt without the package, and every new call
//     home, whatever it is called: each one needs a human to read what it
//     sends before it is allowed.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	telemetryPkg = "github.com/gnacho/netpulse/server-go/internal/telemetry"
	telemetryDir = "internal/telemetry"
	telemetryEnv = "NETPULSE_TELEMETRY"
	// The whole domain, not one host: a new subdomain, or the host name split
	// across two strings, would slip past a single-host match.
	projectDomain = "cloudless.club"
)

// allowedProjectURLs are the only requests to the project's domain this fork
// makes. Each was read and found to carry nothing that identifies the
// installation. Adding one here is a decision, not a fix for a failing test.
//
// They are matched as complete quoted literals, quotes included. Matching the
// bare URL let anything written after it through - "...announcements.json?id=x"
// passed, because the allowed part was removed before the search. What is
// built onto the URL in code is caught by the request itself instead: see
// internal/httpapi/no_call_home_announcements_test.go.
var allowedProjectURLs = []string{
	`"https://netpulse.cloudless.club/announcements.json"`, // static file, no parameters
}

func TestTheServerNeverCallsHome(t *testing.T) {
	// Absolute, because the relative form is "../..", whose own name starts
	// with a dot: an earlier version skipped it as a hidden directory, scanned
	// nothing, and passed every case it was meant to catch.
	root, err := filepath.Abs(filepath.Join("..", "..")) // server-go, from cmd/netpulse
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("cannot find the server-go module root from %s: %v", root, err)
	}

	var hits []string
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			// The package itself may mention everything; it is inert as long
			// as nothing else does.
			if rel == filepath.FromSlash(telemetryDir) || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		// Tests do not ship, and this file names every pattern it looks for.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		src := string(b)
		for _, allowed := range allowedProjectURLs {
			src = strings.ReplaceAll(src, allowed, "")
		}
		switch {
		case strings.Contains(src, telemetryPkg):
			hits = append(hits, rel+": imports the telemetry package")
		case strings.Contains(src, telemetryEnv):
			hits = append(hits, rel+": refers to "+telemetryEnv)
		case strings.Contains(src, projectDomain):
			hits = append(hits, rel+": refers to "+projectDomain+" other than the allowed feed")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	// A guard that reads nothing passes everything. The server has hundreds
	// of source files; far fewer means the walk went wrong, not that the
	// code is clean.
	if scanned < 100 {
		t.Fatalf("scanned only %d files under %s; the walk is broken, so this check proves nothing", scanned, root)
	}
	t.Logf("scanned %d source files", scanned)
	if len(hits) > 0 {
		t.Fatalf("this fork sends no identifying data anywhere, and a sync has brought a call home back:\n  %s\n\n"+
			"For the telemetry package, remove the wiring and leave the package untouched.\n"+
			"For a new request to %s, read what it sends before deciding. See FORK.md.",
			strings.Join(hits, "\n  "), projectDomain)
	}
}
