package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- the document ------------------------------------------------------------------------------

func TestADocumentThisBuildCannotReadIsRefusedWholesale(t *testing.T) {
	// Enforcing the lines of a v2 document that happen to still parse would be enforcing an unknown
	// fraction of an organization's posture while reporting it as the whole thing. Refuse it, fail
	// open, and say so — see parseSupplyChainDoc.
	for _, doc := range []string{
		"# deter-supply-chain v2\n!npm/evil\n",
		"!npm/evil\n",
		"",
	} {
		if _, err := parseSupplyChainDoc(doc, 1); err == nil {
			t.Errorf("%q parsed as a v1 document", doc)
		}
	}
}

func TestOneUnreadableLineDoesNotCostTheOtherTwoHundredThousand(t *testing.T) {
	doc := "# deter-supply-chain v1\n" +
		"# registries=registry.npmjs.org\n" +
		"!npm/good-catch\n" +
		"~npm/truncated:1.0.0\n" + // too few fields
		"=npm/no-advisory\n" + // no `:` at all
		"?npm/unknown-shape\n" + // a marker this build does not know
		"=npm/pinned@1.0.0:MAL-1\n"
	sc, err := parseSupplyChainDoc(doc, 7)
	if err != nil {
		t.Fatalf("a document with junk lines must still parse: %v", err)
	}
	if _, ok := sc.decide(ParsedPackage{"npm", "good-catch", "1.0.0"}); !ok {
		t.Error("the line before the junk was lost")
	}
	if _, ok := sc.decide(ParsedPackage{"npm", "pinned", "1.0.0"}); !ok {
		t.Error("the line after the junk was lost")
	}
	if _, ok := sc.decide(ParsedPackage{"npm", "truncated", "1.0.0"}); ok {
		t.Error("a truncated range line was enforced anyway")
	}
}

func TestAnAbsentHeaderMeansEnforcing(t *testing.T) {
	// The console's rule, and it has to hold here too: a row that was never configured is the
	// enforcing default, not an unconfigured one. The window you would spend monitoring malware is
	// exactly the window a live campaign is running.
	sc, err := parseSupplyChainDoc("# deter-supply-chain v1\n!npm/evil\n", 1)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Posture.Malware != scEnforce || sc.Posture.Tail != scEnforce {
		t.Error("malware defaults must be enforce")
	}
	if !sc.Posture.KEV {
		t.Error("the KEV override defaults on")
	}
	if sc.Posture.BlockUnfixed {
		t.Error("blocking unfixed advisories must stay opt-in")
	}
	hit, ok := sc.decide(ParsedPackage{"npm", "evil", "1.0.0"})
	if !ok || !hit.Block {
		t.Errorf("an absent posture must still block malware: %+v", hit)
	}
}

func TestAHeaderFieldThisBuildDoesNotKnowIsIgnored(t *testing.T) {
	// The console will grow fields before every guard in the field is replaced. An unknown one must
	// not cost the fields this build does understand.
	doc := "# deter-supply-chain v1\n# malware=monitor quarantine=aggressive\n!npm/evil\n"
	sc, err := parseSupplyChainDoc(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Posture.Malware != scMonitor {
		t.Errorf("malware=%s, want monitor", sc.Posture.Malware)
	}
}

func TestModesDecideWhatAMatchDoes(t *testing.T) {
	base := "# deter-supply-chain v1\n# %s\n=npm/pkg@1.0.0:MAL-9\n"
	cases := []struct {
		header      string
		hit, blocks bool
	}{
		{"malware=enforce", true, true},
		{"malware=monitor", true, false},
		{"malware=off", false, false},
	}
	for _, c := range cases {
		sc, err := parseSupplyChainDoc(strings.Replace(base, "%s", c.header, 1), 1)
		if err != nil {
			t.Fatal(err)
		}
		hit, ok := sc.decide(ParsedPackage{"npm", "pkg", "1.0.0"})
		if ok != c.hit || (ok && hit.Block != c.blocks) {
			t.Errorf("%s: matched=%v block=%v, want %v/%v", c.header, ok, hit.Block, c.hit, c.blocks)
		}
	}
}

func TestTheTailAndThePinnedPairsSwitchSeparately(t *testing.T) {
	// ~208k typosquat entries are the only place a false positive could plausibly live, so an
	// organization measuring them must still be able to block the ~25k compromised releases, which
	// are the dangerous half.
	doc := "# deter-supply-chain v1\n# malware=enforce tail=off\n!npm/typo\n=npm/real@1.0.0:MAL-1\n"
	sc, err := parseSupplyChainDoc(doc, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sc.decide(ParsedPackage{"npm", "typo", "1.0.0"}); ok {
		t.Error("tail=off must not block the tail")
	}
	if hit, ok := sc.decide(ParsedPackage{"npm", "real", "1.0.0"}); !ok || !hit.Block {
		t.Error("the pinned half must still enforce")
	}
}

func TestBlockUnfixedIsOptIn(t *testing.T) {
	line := "~npm/abandoned:1.0.0:::C:GHSA-X:nofix\n"
	off, _ := parseSupplyChainDoc("# deter-supply-chain v1\n# unfixed=report\n"+line, 1)
	on, _ := parseSupplyChainDoc("# deter-supply-chain v1\n# unfixed=block\n"+line, 1)

	hit, ok := off.decide(ParsedPackage{"npm", "abandoned", "1.2.0"})
	if !ok || hit.Block || hit.Reason != "unfixed" {
		t.Errorf("by default an unfixed advisory is reported, not blocked: %+v", hit)
	}
	hit, ok = on.decide(ParsedPackage{"npm", "abandoned", "1.2.0"})
	if !ok || !hit.Block {
		t.Errorf("a regulated organization can opt in: %+v", hit)
	}
}

func TestABlockingHitBeatsAnUnfixedNote(t *testing.T) {
	// Two advisories on one package, one of them unfixed. The developer must be told the most
	// alarming TRUE thing, not whichever line the compiler happened to sort first.
	doc := "# deter-supply-chain v1\n" +
		"~npm/pkg:1.0.0:::C:GHSA-NOFIX:nofix\n" +
		"~npm/pkg:1.0.0:1.5.0::H:GHSA-REAL:fix=1.5.0\n"
	sc, _ := parseSupplyChainDoc(doc, 1)
	hit, ok := sc.decide(ParsedPackage{"npm", "pkg", "1.2.0"})
	if !ok || !hit.Block || hit.Advisory != "GHSA-REAL" {
		t.Errorf("got %+v, want the blocking advisory", hit)
	}
}

func TestKevIsReportedAsKevNotAsAThresholdHit(t *testing.T) {
	// "Blocked because it is being exploited right now" and "blocked because your organization set a
	// number" are different sentences, and the first is the one that gets a developer to act.
	doc := "# deter-supply-chain v1\n# cve=low\n~npm/pkg:1.0.0:2.0.0::L:GHSA-K:kev,fix=2.0.0\n"
	sc, _ := parseSupplyChainDoc(doc, 1)
	hit, _ := sc.decide(ParsedPackage{"npm", "pkg", "1.1.0"})
	if hit.Reason != "kev" {
		t.Errorf("reason=%q, want kev even though the band alone would have matched", hit.Reason)
	}
}

func TestKevOverrideCanBeTurnedOff(t *testing.T) {
	doc := "# deter-supply-chain v1\n# cve=critical kev=off\n~npm/pkg:1.0.0:2.0.0::M:GHSA-K:kev,fix=2.0.0\n"
	sc, _ := parseSupplyChainDoc(doc, 1)
	if hit, ok := sc.decide(ParsedPackage{"npm", "pkg", "1.1.0"}); ok {
		t.Errorf("a moderate under a critical threshold with kev=off must not match: %+v", hit)
	}
}

func TestEpssOverride(t *testing.T) {
	line := "~npm/pkg:1.0.0:2.0.0::L:GHSA-E:fix=2.0.0,epss=0.900\n"
	on, _ := parseSupplyChainDoc("# deter-supply-chain v1\n# cve=critical epss=0.5\n"+line, 1)
	off, _ := parseSupplyChainDoc("# deter-supply-chain v1\n# cve=critical\n"+line, 1)
	if hit, ok := on.decide(ParsedPackage{"npm", "pkg", "1.1.0"}); !ok || hit.Reason != "epss" {
		t.Errorf("got %+v, want an epss hit", hit)
	}
	if _, ok := off.decide(ParsedPackage{"npm", "pkg", "1.1.0"}); ok {
		t.Error("without the override a low advisory under a critical threshold must pass")
	}
}

// --- semver ------------------------------------------------------------------------------------

func TestSemverOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1", "1.0.0", 0}, // OSV writes bare majors, and `0` is the commonest lower bound
		{"1.2", "1.2.0", 0},
		{"v1.2.3", "1.2.3", 0}, // a leading v is noise, not a different version
		{"1.2.3", "1.10.0", -1},
		{"1.2.3", "1.2.10", -1},
		{"1.0.0-rc1", "1.0.0", -1}, // a prerelease ranks below its release
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-1", "1.0.0-alpha", -1}, // numeric identifiers rank below alphanumeric
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.2.3+build", "1.2.3", 0}, // build metadata is not part of precedence
	}
	for _, c := range cases {
		a, okA := parseSemver(c.a)
		b, okB := parseSemver(c.b)
		if !okA || !okB {
			t.Fatalf("%q/%q did not parse", c.a, c.b)
		}
		if got := compareSemver(a, b); got != c.want {
			t.Errorf("compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAVersionNobodyCanReadIsLetThrough(t *testing.T) {
	// The deliberate direction to fail. A false block on a package the organization actually depends
	// on is the failure that gets the whole feature switched off, so an unreadable version is not
	// blocked on a guess. Malware matching is exact-string and unaffected.
	doc := "# deter-supply-chain v1\n~npm/pkg:0:::H:GHSA-X:fix=9\n!npm/evil\n"
	sc, _ := parseSupplyChainDoc(doc, 1)
	if _, ok := sc.decide(ParsedPackage{"npm", "pkg", "not-a-version"}); ok {
		t.Error("an unparseable version matched a range")
	}
	if _, ok := sc.decide(ParsedPackage{"npm", "evil", "not-a-version"}); !ok {
		t.Error("malware is exact-string and must still match")
	}
}

func TestSpanBounds(t *testing.T) {
	cases := []struct {
		name    string
		v       scVuln
		version string
		want    bool
	}{
		{"fixed is exclusive", scVuln{Introduced: "1.0.0", Fixed: "2.0.0"}, "2.0.0", false},
		{"just below fixed", scVuln{Introduced: "1.0.0", Fixed: "2.0.0"}, "1.9.9", true},
		{"below introduced", scVuln{Introduced: "1.0.0", Fixed: "2.0.0"}, "0.9.0", false},
		{"last_affected is inclusive", scVuln{Introduced: "0", LastAffect: "2.0.0"}, "2.0.0", true},
		{"past last_affected", scVuln{Introduced: "0", LastAffect: "2.0.0"}, "2.0.1", false},
		{"introduced, never fixed", scVuln{Introduced: "1.0.0"}, "99.0.0", true},
		{"an empty lower bound means zero", scVuln{}, "0.0.1", true},
	}
	for _, c := range cases {
		v, _ := parseSemver(c.version)
		if got := c.v.inSpan(v); got != c.want {
			t.Errorf("%s: inSpan(%s) = %v, want %v", c.name, c.version, got, c.want)
		}
	}
}

// --- registry paths ----------------------------------------------------------------------------

func TestRegistryTarballPaths(t *testing.T) {
	cases := []struct {
		path, name, version string
		ok                  bool
	}{
		{"/express/-/express-4.22.2.tgz", "express", "4.22.2", true},
		{"/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz", "@ctrl/tinycolor", "4.1.1", true},
		// A hyphenated name and a prerelease version are the two cases a "split on the last dash"
		// shortcut gets wrong, in opposite directions.
		{"/left-pad/-/left-pad-1.3.0.tgz", "left-pad", "1.3.0", true},
		{"/vite/-/vite-6.2.3-beta.1.tgz", "vite", "6.2.3-beta.1", true},
		{"/express/-/express-4.22.2.tgz?foo=1", "express", "4.22.2", true},

		// METADATA must stay unparsed, and therefore allowed: dependency resolution breaks long
		// before it ever reaches a blocked version, and a blocklist that also broke `npm view` is
		// one an organization switches off.
		{"/express", "", "", false},
		{"/@ctrl/tinycolor", "", "", false},
		{"/-/v1/search?text=express", "", "", false},

		// Not a tarball, or not a package path.
		{"/express/-/express-4.22.2.tar.gz", "", "", false},
		{"/express/-/lodash-4.22.2.tgz", "", "", false}, // the file must belong to the name
		{"/a/b/c/-/c-1.0.0.tgz", "", "", false},
		{"/express/-/sub/express-1.0.0.tgz", "", "", false},
		{"/express/-/express-.tgz", "", "", false},
	}
	for _, c := range cases {
		got, ok := parseRegistryPath(c.path, nil)
		if ok != c.ok {
			t.Errorf("%s: parsed=%v, want %v", c.path, ok, c.ok)
			continue
		}
		if ok && (got.Name != c.name || got.Version != c.version) {
			t.Errorf("%s: got %s@%s, want %s@%s", c.path, got.Name, got.Version, c.name, c.version)
		}
	}
}

func TestAMirrorPrefixIsStrippedBeforeParsing(t *testing.T) {
	// Artifactory and Nexus put the registry under a path prefix. It travels in the document header
	// so an organization behind one does not need a new guard binary.
	got, ok := parseRegistryPath("/artifactory/api/npm/npm-remote/express/-/express-4.22.2.tgz",
		[]string{"/artifactory/api/npm/npm-remote"})
	if !ok || got.Name != "express" || got.Version != "4.22.2" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
}

func TestOnlyTheNamedRegistriesAreParsed(t *testing.T) {
	sc, _ := parseSupplyChainDoc("# deter-supply-chain v1\n# registries=registry.npmjs.org\n", 1)
	if !sc.covers("registry.npmjs.org") {
		t.Error("the named registry must be covered")
	}
	if sc.covers("example.com") {
		t.Error("npm's tarball grammar must not be applied to an arbitrary host")
	}
}

// --- staleness ---------------------------------------------------------------------------------

func TestStaleness(t *testing.T) {
	doc := "# deter-supply-chain v1\n# generated=2026-09-10T00:00:00Z stale=%s:24h\n"
	warn, _ := parseSupplyChainDoc(strings.Replace(doc, "%s", "warn", 1), 1)
	block, _ := parseSupplyChainDoc(strings.Replace(doc, "%s", "block_registry", 1), 1)

	fresh := time.Date(2026, 9, 10, 6, 0, 0, 0, time.UTC)
	old := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	if warn.stale(fresh) {
		t.Error("six hours old is not stale against a 24 h threshold")
	}
	if !warn.stale(old) {
		t.Error("three days old is stale")
	}
	if block.Posture.OnStale != scStaleBlock {
		t.Errorf("on_stale=%q", block.Posture.OnStale)
	}
	// A document with no timestamp is never called stale — that is a missing field, not evidence of
	// age, and inventing staleness from it would refuse registries for no reason.
	none, _ := parseSupplyChainDoc("# deter-supply-chain v1\n", 1)
	if none.stale(old) {
		t.Error("an undated document must not be treated as stale")
	}
}

// --- through the proxy ---------------------------------------------------------------------------

// startSupplyProxy runs a proxy with both artifacts, against a test origin standing in for a
// registry, and returns a client that goes through it.
func startSupplyProxy(t *testing.T, doc string, mode Mode) (*http.Client, *proxy, string, func()) {
	t.Helper()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tarball:" + r.URL.Path))
	}))
	originRoot := x509.NewCertPool()
	originRoot.AddCert(origin.Certificate())
	host := mustHost(t, strings.TrimPrefix(origin.URL, "https://"))

	sc, err := parseSupplyChainDoc(doc, 812)
	if err != nil {
		t.Fatal(err)
	}
	// The header names the real registries; the test origin is on 127.0.0.1.
	sc.Posture.Registries = []string{host}

	ca, err := newCertAuthority()
	if err != nil {
		t.Fatal(err)
	}
	px := newProxy(&Policy{Version: 5, Rules: []Rule{{Host: host}}}, sc, ca, nil, mode, false)
	px.upstream.TLSClientConfig = &tls.Config{RootCAs: originRoot}
	srv := httptest.NewServer(px)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.caPEM()) {
		t.Fatal("the guard CA did not parse as PEM")
	}
	u, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
	return client, px, origin.URL, func() { srv.Close(); origin.Close() }
}

const proxyTestDoc = "# deter-supply-chain v1\n" +
	"# generated=2126-01-01T00:00:00Z malware=enforce tail=enforce cve=high action=enforce kev=on\n" +
	"=npm/left-pad@1.3.0:MAL-2025-1\n" +
	"~npm/vite:6.2.0:6.2.4::M:GHSA-4r4m-qw57-chr8:kev,fix=6.2.4\n"

func TestABlockedPackageNeverReachesTheRegistry(t *testing.T) {
	client, _, origin, stop := startSupplyProxy(t, proxyTestDoc, ModeEnforce)
	defer stop()

	code, body := get(t, client, origin+"/vite/-/vite-6.2.1.tgz")
	if code != http.StatusForbidden {
		t.Fatalf("got %d %q, want 403", code, body)
	}
	if strings.Contains(body, "tarball:") {
		t.Fatal("the origin was reached anyway — the fetch was not stopped")
	}
	// The body IS the feature: it is what a developer reads in `npm install` output, and it has to
	// answer what, why, on whose authority, and what to do next.
	for _, want := range []string{
		"vite", "6.2.1", "GHSA-4r4m-qw57-chr8", "moderate", "6.2.4", "kev", "deny_supply_chain",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal must name %q:\n%s", want, body)
		}
	}
}

func TestASiblingVersionStillInstalls(t *testing.T) {
	// The entire point of deciding on the path rather than the host: the registry stays reachable
	// while one compromised release does not.
	client, _, origin, stop := startSupplyProxy(t, proxyTestDoc, ModeEnforce)
	defer stop()

	if code, body := get(t, client, origin+"/vite/-/vite-6.2.4.tgz"); code != 200 ||
		!strings.Contains(body, "tarball:") {
		t.Errorf("the fixed version must be fetched: %d %q", code, body)
	}
	if code, _ := get(t, client, origin+"/express/-/express-4.22.2.tgz"); code != 200 {
		t.Errorf("an unlisted package must be fetched: %d", code)
	}
}

func TestMetadataStaysAllowedForABlockedPackage(t *testing.T) {
	// If resolution cannot read the registry's metadata it fails before it ever reaches the version
	// that would be refused, and the developer sees a broken registry rather than a policy.
	client, _, origin, stop := startSupplyProxy(t, proxyTestDoc, ModeEnforce)
	defer stop()

	if code, body := get(t, client, origin+"/vite"); code != 200 {
		t.Errorf("metadata for a package with a blocked version must resolve: %d %q", code, body)
	}
}

func TestAMonitoredClassInstallsAndIsStillRecorded(t *testing.T) {
	// An enforcing RUN, with the organization measuring one class before committing to it. The
	// package installs; the finding is still counted, or the measurement was for nothing.
	doc := strings.Replace(proxyTestDoc, "action=enforce", "action=monitor", 1)
	client, px, origin, stop := startSupplyProxy(t, doc, ModeEnforce)
	defer stop()

	code, body := get(t, client, origin+"/vite/-/vite-6.2.1.tgz")
	if code != 200 || !strings.Contains(body, "tarball:") {
		t.Fatalf("a monitored finding must not block: %d %q", code, body)
	}
	list, _, observed, _ := px.summary()
	if len(list) != 1 || observed != 1 {
		t.Fatalf("the finding was not recorded: %d target(s), observed=%d", len(list), observed)
	}
	if !strings.Contains(list[0].reason, "GHSA-4r4m-qw57-chr8") {
		t.Errorf("the record must name the advisory, got %q", list[0].reason)
	}
	// Malware is still on enforce in the same document — the two classes are independent switches.
	if code, _ := get(t, client, origin+"/left-pad/-/left-pad-1.3.0.tgz"); code != http.StatusForbidden {
		t.Errorf("malware=enforce must still block while cve=monitor: %d", code)
	}
}

func TestGuardMonitorModeBlocksNothingAtAll(t *testing.T) {
	// --mode monitor is a property of the RUN, and it outranks an enforcing document: the whole
	// point is a first outing that cannot break the build it is measuring.
	client, px, origin, stop := startSupplyProxy(t, proxyTestDoc, ModeMonitor)
	defer stop()

	if code, body := get(t, client, origin+"/left-pad/-/left-pad-1.3.0.tgz"); code != 200 ||
		!strings.Contains(body, "tarball:") {
		t.Fatalf("monitor mode must not block: %d %q", code, body)
	}
	if list, _, _, _ := px.summary(); len(list) != 1 {
		t.Fatalf("it must still be recorded: %d", len(list))
	}
}

func TestAStaleBlocklistCanCloseTheRegistry(t *testing.T) {
	// The opt-in strict reading, for an organization whose compliance posture cannot accept
	// installing against a blocklist nobody could refresh.
	doc := "# deter-supply-chain v1\n# generated=2020-01-01T00:00:00Z stale=block_registry:24h\n"
	client, _, origin, stop := startSupplyProxy(t, doc, ModeEnforce)
	defer stop()

	code, body := get(t, client, origin+"/express/-/express-4.22.2.tgz")
	if code != http.StatusForbidden || !strings.Contains(body, "stale") {
		t.Fatalf("a stale blocklist under block_registry must refuse: %d %q", code, body)
	}
}

func TestNoDocumentMeansTheEgressPolicyIsUnaffected(t *testing.T) {
	// The failure direction that makes this artifact different from the egress policy: a console
	// outage degrades package blocking and nothing else. Every install in the fleet must not stop.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tarball:" + r.URL.Path))
	}))
	defer origin.Close()
	originRoot := x509.NewCertPool()
	originRoot.AddCert(origin.Certificate())
	host := mustHost(t, strings.TrimPrefix(origin.URL, "https://"))

	client, stop := startProxy(t, &Policy{Rules: []Rule{{Host: host}}}, originRoot)
	defer stop()
	if code, _ := get(t, client, origin.URL+"/left-pad/-/left-pad-1.3.0.tgz"); code != 200 {
		t.Errorf("with no blocklist the build must still run: %d", code)
	}
}
