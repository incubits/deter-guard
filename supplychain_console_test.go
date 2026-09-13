package main

import (
	"os"
	"strings"
	"testing"
)

// The document in testdata/console-document.txt is not written by hand: it is the output of the
// console's own compiler (see testdata/generate.mts). That is the entire point of it.
//
// Every other fixture in this package is hand-written, and hand-written fixtures are what hid the
// bug this file exists to catch. The console moved the entry separator from `:` to `|` — it had to,
// because a Maven package name IS a `group:artifact` coordinate and a colon split it in half — and
// this parser kept reading `:`. Every pinned malware release and every CVE in the real document
// failed to parse. The typosquat tail has no separator, so it still parsed, the guard still reported
// a plausible entry count, and CI enforced typosquats and nothing else. The suite stayed green
// throughout, because the suite was written in the grammar the parser expected.
func consoleDoc(t *testing.T) *supplyChain {
	t.Helper()
	raw, err := os.ReadFile("testdata/console-document.txt")
	if err != nil {
		t.Fatalf("reading the console fixture: %v", err)
	}
	sc, err := parseSupplyChainDoc(string(raw), 9)
	if err != nil {
		t.Fatalf("the guard cannot parse a document the console actually produced: %v", err)
	}
	return sc
}

// The regression test proper. Under the `:` parser this document yielded one usable entry out of
// six enforceable ones; `dropped` is what makes that a failure rather than a quiet Tuesday.
func TestConsoleDocumentParsesWithNothingDropped(t *testing.T) {
	sc := consoleDoc(t)

	if sc.dropped != 0 {
		t.Errorf("dropped = %d, want 0 — the guard cannot read %d entries the console published",
			sc.dropped, sc.dropped)
	}
	// npm is what this guard can enforce (see enforceableEcosystems): the tail entry, the pinned
	// release, and three vulnerability rows.
	if len(sc.tail) != 1 || len(sc.pinned) != 1 || sc.vulnLines() != 3 {
		t.Errorf("tail=%d pinned=%d vulns=%d, want 1/1/3", len(sc.tail), len(sc.pinned), sc.vulnLines())
	}
	// PyPI ×2, NuGet ×1, Maven ×1 — held back deliberately, not misread.
	if sc.skipped != 4 {
		t.Errorf("skipped = %d, want 4 (the non-npm entries)", sc.skipped)
	}
	if got := len(sc.Posture.Registries); got != 13 {
		t.Errorf("registries = %d, want the 13 the console's header ships", got)
	}
}

// What the document is FOR. A parser that populates its maps and still refuses nothing would pass
// the test above and protect no one.
func TestConsoleDocumentActuallyRefuses(t *testing.T) {
	sc := consoleDoc(t)

	cases := []struct {
		name    string
		pkg     ParsedPackage
		hit     bool
		block   bool
		reason  string
		fixedIn string
	}{
		{"a typosquat, at any version", ParsedPackage{"npm", "evil-typosquat", "9.9.9"}, true, true, "malware_tail", ""},
		{"the compromised release", ParsedPackage{"npm", "@ctrl/tinycolor", "4.1.1"}, true, true, "malware", ""},
		{"a clean release of the same package", ParsedPackage{"npm", "@ctrl/tinycolor", "4.1.0"}, false, false, "", ""},
		{"an enumerated affected version", ParsedPackage{"npm", "lodash", "4.17.20"}, true, true, "severity", "4.17.21"},
		{"a fixed version of it", ParsedPackage{"npm", "lodash", "4.17.21"}, false, false, "", ""},
		// The KEV override is the reason a `high` threshold still stops a MODERATE advisory, and the
		// fix named must be this branch's (6.2.4), never the advisory's lowest across all majors.
		{"a known-exploited moderate", ParsedPackage{"npm", "vite", "6.2.1"}, true, true, "kev", "6.2.4"},
		{"the branch fix for it", ParsedPackage{"npm", "vite", "6.2.4"}, false, false, "", ""},
		// Reported, not blocked: blocking an advisory with no fix leaves a developer nowhere to go.
		{"an advisory with no fix", ParsedPackage{"npm", "abandoned-pkg", "1.4.0"}, true, false, "unfixed", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hit, ok := sc.decide(c.pkg)
			if ok != c.hit {
				t.Fatalf("flagged = %v, want %v (%s@%s)", ok, c.hit, c.pkg.Name, c.pkg.Version)
			}
			if !ok {
				return
			}
			if hit.Block != c.block {
				t.Errorf("block = %v, want %v", hit.Block, c.block)
			}
			if hit.Reason != c.reason {
				t.Errorf("reason = %q, want %q", hit.Reason, c.reason)
			}
			if c.fixedIn != "" && hit.FixedIn != c.fixedIn {
				t.Errorf("fixedIn = %q, want %q", hit.FixedIn, c.fixedIn)
			}
		})
	}
}

// The colon separator was abandoned for a reason that is visible in this one line: `group:artifact`.
// Splitting it on `:` truncates the package to `org.apache.logging.log4j` and moves the range bounds
// one field left, so the entry both fails to match log4j-core and silently means something else.
func TestMavenCoordinateSurvivesTheSeparator(t *testing.T) {
	raw, err := os.ReadFile("testdata/console-document.txt")
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "~Maven/") {
			line = l
		}
	}
	if line == "" {
		t.Skip("the fixture carries no Maven entry")
	}
	if !strings.Contains(line, "org.apache.logging.log4j:log4j-core|") {
		t.Fatalf("the fixture's Maven entry is not the shape this test guards: %q", line)
	}
	name, _, _ := strings.Cut(line[1:], "|")
	if name != "Maven/org.apache.logging.log4j:log4j-core" {
		t.Errorf("splitting on `|` gave %q — the coordinate must survive whole", name)
	}
}

// The old grammar must now be unreadable, and LOUDLY so. If a future change made colon-separated
// lines parse again by accident, the two formats would both half-work and the next drift would be
// invisible for exactly the same reason this one was.
func TestTheOldColonGrammarIsRejectedAndCounted(t *testing.T) {
	old := "# deter-supply-chain v1\n" +
		"# malware=enforce tail=enforce cve=high action=enforce\n" +
		"=npm/pkg@1.0.0:MAL-1\n" +
		"~npm/vite:6.2.0:6.2.3::M:GHSA-X:kev\n" +
		"+npm/lodash@4.17.20:H:GHSA-Y:fix=4.17.21\n"
	sc, err := parseSupplyChainDoc(old, 1)
	if err != nil {
		t.Fatalf("a document with a readable header must still parse: %v", err)
	}
	if sc.dropped != 3 {
		t.Errorf("dropped = %d, want 3 — the old grammar must be counted as unreadable, not absorbed",
			sc.dropped)
	}
	if len(sc.pinned) != 0 || sc.vulnLines() != 0 {
		t.Errorf("colon-separated entries were absorbed: pinned=%d vulns=%d", len(sc.pinned), sc.vulnLines())
	}
}

// Opt-in, against a REAL document saved from the console — the same seam the Rust broker pins with
// DETER_TEST_SC_BUNDLE. The committed fixture is nine entries chosen to cover the grammar; this is
// the quarter of a million the fleet actually pulls, and only it can show that the shapes appear in
// the proportions the parser expects.
//
//	DETER_TEST_SC_DOC=/path/to/document.txt go test -run RealConsoleDocument -v
func TestRealConsoleDocument(t *testing.T) {
	path := os.Getenv("DETER_TEST_SC_DOC")
	if path == "" {
		t.Skip("set DETER_TEST_SC_DOC to a document saved from the console")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := parseSupplyChainDoc(string(raw), 1)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	readable := len(sc.tail) + len(sc.pinned) + sc.vulnLines()
	t.Logf("readable=%d dropped=%d skipped=%d (header says entries=%d)",
		readable, sc.dropped, sc.skipped, sc.Posture.Entries)
	if sc.dropped > 0 {
		t.Errorf("%d entries in a real console document are unreadable by this build", sc.dropped)
	}
	if readable == 0 {
		t.Error("a real console document yielded no enforceable entries at all")
	}
}
