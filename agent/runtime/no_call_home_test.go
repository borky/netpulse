package runtime

// FORK: this file exists only in the fork. It is a new file rather than an
// edit to an upstream one so that it can never conflict with a sync.
//
// The agent runs on the router, embedded in the NetGrip panel, and talks only
// to the NetPulse server its owner configured. This fork sends no identifying
// data anywhere else, and upstream has added a call home to the server before
// (an anonymous instance ping with a persistent id, #822). This test fails if
// the agent ever gains one.
//
// It reads the source rather than asking the toolchain what would be linked,
// so a file limited to one architecture or hidden behind a build tag is read
// like any other. Unlike the server's version of this check there is no
// allowed list: the agent has no reason to contact the project at all.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var callHomeMarkers = []string{
	"cloudless.club",     // the project's own hosts
	"NETPULSE_TELEMETRY", // the switch for the server's instance ping
	"server-go/internal/telemetry",
}

func TestTheAgentNeverCallsHome(t *testing.T) {
	root, err := filepath.Abs("..") // the agent module, from runtime/
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("cannot find the agent module root from %s: %v", root, err)
	}

	var hits []string
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel != "." && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for _, m := range callHomeMarkers {
			if strings.Contains(string(b), m) {
				hits = append(hits, rel+": "+m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	// A guard that reads nothing passes everything.
	if scanned < 10 {
		t.Fatalf("scanned only %d files under %s; the walk is broken, so this check proves nothing", scanned, root)
	}
	t.Logf("scanned %d source files", scanned)
	if len(hits) > 0 {
		t.Fatalf("the agent runs on the router and must not call home, but a sync has added:\n  %s\n\n"+
			"Read what it sends before deciding anything. See FORK.md.", strings.Join(hits, "\n  "))
	}
}
