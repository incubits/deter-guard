package main

// The supply-chain blocklist: refusing a package this organization will not install.
//
// This is the SECOND signed artifact the guard pulls, and it is deliberately not part of the egress
// policy. The two are kept apart because everything about them differs:
//
//	egress policy      a human edits a rule. Tens of entries. Fails CLOSED — no policy means no
//	                   egress, because that is what an egress policy is for.
//	supply chain       a feed moves, every fifteen minutes. A quarter of a million entries. Fails
//	                   OPEN — a console outage must not break every `npm ci` in the fleet.
//
// They share the fleet signing key and the signed-pull distribution, and nothing else.
//
// Two matchers, because the corpus has two shapes and conflating them costs 34x:
//
//	malware        set membership. Either every version of a package is malicious (a typosquat —
//	               ~208k of those) or one exact release of a real package is (~25k). No version
//	               arithmetic is involved in either.
//	vulnerability  RANGES. An advisory says `>=1.2.0 <1.4.7`, and expanding that to concrete
//	               versions was measured at ~341,000 pairs against ~9,900 range lines. Expansion is
//	               also stale the moment it ships, because a version published INTO an unfixed range
//	               is affected as soon as it exists. So ranges travel here and are evaluated here.
//
// The reference implementation is the console's `supplychain/match.ts`, and the Rust broker carries
// the third port of it. Three implementations of one wire format is the seam most likely to break
// silently — a mismatch means the fleet quietly enforces nothing — so the layout is pinned by a
// cross-language vector in supplychain_vector_test.go rather than trusted to read alike.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// scFormat is the only document version this build understands. A document announcing anything else
// is refused wholesale rather than parsed for the lines that happen to still make sense: half of a
// blocklist is not a blocklist, and a guard that enforced half of one would report itself as
// protecting a build it was not.
const scFormat = "deter-supply-chain v1"

// --- severity bands ----------------------------------------------------------------------------

// scBand is GitHub's severity band, which is what the threshold compares — not the CVSS score.
//
// The console's reasoning, kept here so the two agree: the band is present on 7,052 of 7,054 npm
// advisories where a parseable CVSS vector is not, and it is the word a security team already uses.
type scBand int

const (
	bandNone scBand = iota // "do not block on severity at all" — the KEV override can still fire
	bandLow
	bandModerate
	bandHigh
	bandCritical
	// bandUnknown ranks BELOW low, so an unrecognised severity never satisfies a threshold on its
	// own. It is a distinct value rather than `bandNone` so that a severity we could not read is
	// reported as `unknown` instead of silently printed as "none".
	bandUnknown scBand = -1
)

func (b scBand) String() string {
	switch b {
	case bandCritical:
		return "critical"
	case bandHigh:
		return "high"
	case bandModerate:
		return "moderate"
	case bandLow:
		return "low"
	case bandNone:
		return "none"
	}
	return "unknown"
}

// rank orders bands for the threshold comparison. `none` is not a severity, so it has no rank, and
// neither does an unreadable one.
func (b scBand) rank() int {
	if b <= bandNone {
		return 0
	}
	return int(b)
}

// meets reports whether a severity satisfies a threshold. A threshold of `none` never matches on
// severity alone — that is the whole point of it being a separate switch from the KEV override.
func (b scBand) meets(threshold scBand) bool {
	if threshold <= bandNone {
		return false
	}
	return b.rank() >= threshold.rank()
}

// parseBandWord reads a band from the header (`cve=high`).
func parseBandWord(s string) scBand {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return bandCritical
	case "high":
		return bandHigh
	case "moderate", "medium":
		return bandModerate
	case "low":
		return bandLow
	case "none", "off":
		return bandNone
	}
	return bandUnknown
}

// parseBandChar reads a band from an entry line, where it is one letter to keep 250k lines small.
func parseBandChar(s string) scBand {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "C":
		return bandCritical
	case "H":
		return bandHigh
	case "M":
		return bandModerate
	case "L":
		return bandLow
	}
	return bandUnknown
}

// --- the posture -------------------------------------------------------------------------------

// scMode is what a match DOES. Same three values as the guard's own --mode, and the same reasoning:
// `monitor` is never a default, because a control that defaults to not controlling is a control
// nobody turns on.
type scMode string

const (
	scEnforce scMode = "enforce" // refuse the fetch
	scMonitor scMode = "monitor" // allow it, report it — for measuring blast radius first
	scOff     scMode = "off"     // do not evaluate this class at all
)

func parseSCMode(s string, fallback scMode) scMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "enforce", "block":
		return scEnforce
	case "monitor", "report", "audit":
		return scMonitor
	case "off", "none", "disabled":
		return scOff
	}
	return fallback
}

// scPosture is the organization's settings, as they arrive in the document header.
//
// The posture travels WITH the data it decides on, which is what makes moving an organization from
// `high` to `critical` — or excusing one pipeline — a new document rather than a new guard release.
type scPosture struct {
	// Pinned malicious `name@version` pairs: a real package at a compromised release.
	Malware scMode
	// The long tail where EVERY version of a package is malicious — typosquats, throwaway malware.
	// ~208k entries, and the only place a false positive could plausibly live, so it is a separate
	// switch even though both default to enforce.
	Tail scMode
	// What a vulnerability match does, and the band at which one counts.
	CVEAction scMode
	Threshold scBand
	// Block anything in CISA's Known Exploited Vulnerabilities catalog regardless of the threshold.
	// Of the 13 npm CVEs in KEV, three are rated only MODERATE — jquery, vite and puppeteer — so an
	// organization on `high` installs all three without this.
	KEV bool
	// Block advisories with no fixed version. Default off: ~22% of advisories have no fix, and
	// blocking those leaves a developer with nowhere to go, which is how a control gets switched
	// off wholesale rather than tuned.
	BlockUnfixed bool
	// Also block at or above this EPSS probability (0–1). Negative means off.
	EPSS float64
	// What to do once the document is older than StaleHours. The egress policy fails closed; this
	// cannot, so the strict reading is opt-in.
	OnStale    string // "warn" (default) or "block_registry"
	StaleHours float64

	// Descriptive, from the header — not decisions, but the guard prints them so an operator can see
	// which document a build actually ran under.
	Scope      string
	Project    string
	Generated  time.Time
	Corpus     string
	Sources    []string
	Registries []string
	// Mirror path prefixes stripped before a tarball path is parsed (Artifactory, Nexus). They ride
	// in the header so a mirror does not need a new guard binary.
	Prefixes []string
	Entries  int
}

const (
	scStaleWarn  = "warn"
	scStaleBlock = "block_registry"
)

// defaultPosture is what an absent header field means.
//
// Enforcing, on every class that has no false-positive story. An absent setting is the enforcing
// default rather than an unconfigured one — the same rule the console applies to an organization
// that has never opened the page — because the window you would spend monitoring malware is exactly
// the window a live campaign is running.
func defaultPosture() scPosture {
	return scPosture{
		Malware:      scEnforce,
		Tail:         scEnforce,
		CVEAction:    scEnforce,
		Threshold:    bandHigh,
		KEV:          true,
		BlockUnfixed: false,
		EPSS:         -1,
		OnStale:      scStaleWarn,
		StaleHours:   24,
	}
}

// --- the compiled document ---------------------------------------------------------------------

// scVuln is one vulnerable range (or one enumerated affected version) for one package.
//
// One line of the document is one of these. The console groups spans per advisory; here each line
// stands alone, which is both simpler and more correct for the message: the fix reported must be the
// fix for the BRANCH that caught this version, and a line's own upper bound is exactly that.
type scVuln struct {
	Advisory string
	Severity scBand
	// Exactly one shape: an enumerated version, or a span. Empty Version means this is a span.
	Version                       string
	Introduced, Fixed, LastAffect string
	KEV                           bool
	// NoFix is the `nofix` flag: the advisory names no fixed version anywhere.
	NoFix bool
	// FixedIn is what a developer is told to move to. For a span this is that span's upper bound.
	FixedIn string
	EPSS    float64
}

// supplyChain is a parsed, verified document, ready to decide requests against.
//
// Package names are stored as 64-bit hashes rather than strings, mirroring the broker: ~232k entries
// cost a few megabytes instead of 15–25, and a process sitting in the middle of a build's TLS never
// holds the organization's dependency list in memory. The cost is a theoretical false block on a
// hash collision — around one in four hundred million at this corpus size, against a certain 20 MB.
type supplyChain struct {
	Version int64
	Posture scPosture

	tail   map[uint64]struct{} // hash("npm/name")          — every version malicious
	pinned map[uint64]string   // hash("npm/name@version")  → advisory id
	vulns  map[uint64][]scVuln // hash("npm/name")          → the ranges for it

	// dropped is entry lines for an ecosystem this guard DOES enforce that it could not read, and
	// skipped is lines for an ecosystem it does not. The difference is the whole point of counting
	// them: `skipped` is a stated limit, `dropped` is this parser disagreeing with the console about
	// the format, which is the failure that hides. See warnIfUnreadable.
	dropped int
	skipped int

	// Verified reports whether the signature was checked against a key the guard PINNED, rather
	// than one the same response handed it. Only one of those is a security claim.
	Verified bool
	// Source says where this came from, for the one line the guard logs about it.
	Source string
}

// covers reports whether this host is one of the package registries the document names.
//
// The list travels in the header rather than being compiled in, which is what lets an organization
// behind Artifactory or Nexus point the guard at its own mirror without waiting for a release. A
// host that is not a registry is not parsed at all: the tarball path grammar is npm's, and applying
// it to an arbitrary host would be guessing.
func (sc *supplyChain) covers(host string) bool {
	for _, r := range sc.Posture.Registries {
		if hostMatches(r, host) {
			return true
		}
	}
	return false
}

// scHash is FNV-1a/64 over the key. Internal only — it never goes on the wire, so the three
// implementations of this format are free to hash differently.
func scHash(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}

// parseSupplyChainDoc reads the compiled document.
//
// Line-oriented and sorted, which is what lets a quarter of a million entries parse in one pass, diff
// trivially for the console's delta endpoint, and gzip to 1.5 MB. A JSON array of the same data is
// neither small nor streamable.
//
//	# deter-supply-chain v1
//	# generated=2026-09-12T16:34:00Z scope=ci
//	# malware=enforce tail=enforce cve=high action=enforce kev=on unfixed=report stale=warn:24h
//	# registries=registry.npmjs.org,registry.yarnpkg.com
//	# corpus=2026-09-12T16:00:00Z sources=osv,cisa-kev entries=254014
//
//	!npm/@evil/pkg                                    every version malicious
//	=npm/@ctrl/tinycolor@4.1.1|MAL-2025-47141         one compromised release
//	~npm/vite|6.2.0|6.2.3||M|GHSA-4r4m-qw57-chr8|kev  a vulnerable RANGE
//	+npm/lodash@4.17.20|H|GHSA-35jh-r3h4-6jhm|fix=4.17.21   an enumerated affected version
//
// An unreadable ENTRY is skipped, because one malformed line out of 250k must not cost the other
// 249,999. An unreadable HEADER is fatal: the header is the posture, and enforcing a quarter of a
// million entries under a posture nobody could read is worse than enforcing none of them.
//
// Skipping is counted, though, and that is not bookkeeping. This parser read `:` where the console
// had moved to `|`, so every pinned release and every CVE in the document failed to parse and was
// dropped one line at a time, in silence; the typosquat tail carries no separator, so it still
// parsed, the guard still logged a healthy-looking entry count, and CI enforced a fraction of the
// posture it reported. A control that fails this way is worse than one that is off, because nobody
// goes looking. warnIfUnreadable is what makes that noisy now.
func parseSupplyChainDoc(doc string, version int64) (*supplyChain, error) {
	sc := &supplyChain{
		Version: version,
		Posture: defaultPosture(),
		tail:    map[uint64]struct{}{},
		pinned:  map[uint64]string{},
		vulns:   map[uint64][]scVuln{},
	}

	lines := strings.Split(doc, "\n")
	if len(lines) == 0 || strings.TrimSpace(strings.TrimPrefix(lines[0], "#")) != scFormat {
		first := ""
		if len(lines) > 0 {
			first = strings.TrimSpace(lines[0])
		}
		return nil, fmt.Errorf("not a %q document (first line was %q) — this guard cannot enforce it", scFormat, first)
	}

	fields := map[string]string{}
	for _, raw := range lines[1:] {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			continue
		}
		if line[0] == '#' {
			// Every header line is whitespace-separated `key=value`, so one collector handles all of
			// them and an unknown key is ignored rather than fatal. A document that grows a field
			// this build has not heard of must still enforce the fields it has.
			for _, tok := range strings.Fields(strings.TrimPrefix(line, "#")) {
				if k, v, ok := strings.Cut(tok, "="); ok {
					fields[strings.ToLower(k)] = v
				}
			}
			continue
		}
		sc.addEntry(line)
	}
	sc.Posture = postureFromHeader(fields)
	return sc, nil
}

// postureFromHeader turns the collected header fields into the settings the matcher reads.
func postureFromHeader(f map[string]string) scPosture {
	p := defaultPosture()
	p.Malware = parseSCMode(f["malware"], p.Malware)
	p.Tail = parseSCMode(f["tail"], p.Tail)
	p.CVEAction = parseSCMode(f["action"], p.CVEAction)
	if b := parseBandWord(f["cve"]); b != bandUnknown {
		p.Threshold = b
	}
	if v, ok := f["kev"]; ok {
		p.KEV = v == "on" || v == "true" || v == "1"
	}
	if v, ok := f["unfixed"]; ok {
		// `block` is the only value that blocks. The console has spelled the other side both
		// `report` and `allow`; either means the same thing, and so does anything unrecognised —
		// the safe direction for THIS field is the permissive one, because blocking an advisory
		// with no fix leaves a developer with nowhere to go.
		p.BlockUnfixed = v == "block"
	}
	if v, ok := f["epss"]; ok {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			p.EPSS = n
		}
	}
	if v, ok := f["stale"]; ok {
		// `stale=warn:24h`, or just `stale=warn`.
		action, hours, _ := strings.Cut(v, ":")
		if action == scStaleBlock {
			p.OnStale = scStaleBlock
		} else {
			p.OnStale = scStaleWarn
		}
		if n, err := strconv.ParseFloat(strings.TrimSuffix(hours, "h"), 64); err == nil && n > 0 {
			p.StaleHours = n
		}
	}
	p.Scope = f["scope"]
	p.Project = f["project"]
	p.Corpus = f["corpus"]
	if v := f["generated"]; v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			p.Generated = t
		}
	}
	p.Registries = splitList(f["registries"])
	p.Prefixes = splitList(f["prefixes"])
	p.Sources = splitList(f["sources"])
	if n, err := strconv.Atoi(f["entries"]); err == nil {
		p.Entries = n
	}
	return p
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// enforceableEcosystems are the ecosystems this guard can identify from a request URL, and so the
// only ones whose entries are worth keeping.
//
// The console compiles EIGHT ecosystems into one document. This guard reads npm tarball paths and
// nothing else (see parseRegistryPath), and the lookup key is `<ecosystem>/<name>` — so a PyPI or
// Maven entry is one nothing here can ever ask for. Holding them would cost a CI container hundreds
// of megabytes to answer a question it cannot pose. The Rust broker drops unknown ecosystems for the
// same reason, and for the same reason keeps its own entry count honest about what is enforceable.
//
// This set and parseRegistryPath are ONE decision written in two places: widen either without the
// other and the guard stores entries nothing looks up, or looks up entries that were never stored.
var enforceableEcosystems = map[string]bool{"npm": true}

// entryEcosystem reads the `<ecosystem>/` prefix every entry line opens with.
//
// Cut at the FIRST `/`: an npm scope (`npm/@ctrl/tinycolor`) and a Go module path
// (`Go/github.com/foo/bar`) both carry more, and only the first segment is the ecosystem.
func entryEcosystem(body string) (string, bool) {
	eco, _, ok := strings.Cut(body, "/")
	if !ok || eco == "" {
		return "", false
	}
	return eco, true
}

// addEntry parses one entry line into the index.
//
// Fields are `|`-separated, NOT `:`. Maven package names ARE `group:artifact` coordinates, so a
// colon separator splits the name in half and no Maven advisory can ever match; `|` is not valid in
// a package name in any ecosystem the console ships. This is the same grammar the Rust broker reads
// (broker/src/supply_chain.rs) and the one the console writes (supplychain/compile.ts).
//
// A line it cannot read is dropped and COUNTED — silently dropping them is what let this parser
// spend a release reading `:` while the console wrote `|`, enforcing typosquats and nothing else.
// See parseSupplyChainDoc.
func (sc *supplyChain) addEntry(line string) {
	switch line[0] {
	case '!', '=', '~', '+':
	default:
		// An entry shape this build does not know. Counted as unreadable rather than ignored: if the
		// console grows a kind of entry that carries real blocks, silence is the wrong answer — that
		// is the whole lesson of the separator change.
		sc.dropped++
		return
	}

	body := line[1:]
	eco, ok := entryEcosystem(body)
	if !ok {
		sc.dropped++
		return
	}
	if !enforceableEcosystems[eco] {
		// Not drift — a deliberate, stated limit. Counted separately so the two can never be
		// confused for one another in the one line an operator reads.
		sc.skipped++
		return
	}

	switch line[0] {
	case '!':
		// !npm/@evil/pkg — every version malicious. No advisory id, and that is measured rather than
		// missing: attaching one to ~208k high-entropy lines costs 0.56 MB gzipped and buys nothing
		// a developer can act on, because a tail hit means the whole package is malware.
		if key := strings.TrimSpace(body); key != "" {
			sc.tail[scHash(key)] = struct{}{}
			return
		}
	case '=':
		// =npm/@ctrl/tinycolor@4.1.1|MAL-2025-47141 — one compromised release of a real package.
		// The id stays here because this is the case a developer looks up, and the id is what makes
		// the message credible.
		key, advisory, ok := strings.Cut(body, "|")
		if ok && strings.TrimSpace(key) != "" {
			sc.pinned[scHash(strings.TrimSpace(key))] = strings.TrimSpace(advisory)
			return
		}
	case '~':
		// ~npm/vite|6.2.0|6.2.3||M|GHSA-4r4m-qw57-chr8|kev,fix=6.2.4
		parts := strings.SplitN(body, "|", 7)
		if len(parts) < 6 {
			break
		}
		v := scVuln{
			Introduced: parts[1],
			Fixed:      parts[2],
			LastAffect: parts[3],
			Severity:   parseBandChar(parts[4]),
			Advisory:   parts[5],
			EPSS:       -1,
		}
		// The span's own upper bound IS the fix for the branch this range covers. An advisory that
		// spans majors carries a fix per branch — vite's GHSA-4r4m-qw57-chr8 is fixed in 4.5.11 AND
		// 6.2.4 — so reporting the advisory's lowest tells someone on 6.2.1 to "upgrade" two majors
		// backwards. The flags below may override it only when this range has no upper bound.
		v.FixedIn = parts[2]
		if len(parts) == 7 {
			applyFlags(&v, parts[6])
		}
		if pkg := strings.TrimSpace(parts[0]); pkg != "" {
			sc.vulns[scHash(pkg)] = append(sc.vulns[scHash(pkg)], v)
			return
		}
	case '+':
		// +npm/lodash@4.17.20|H|GHSA-35jh-r3h4-6jhm|fix=4.17.21 — OSV enumerated the version instead
		// of giving a range.
		parts := strings.SplitN(body, "|", 4)
		if len(parts) < 3 {
			break
		}
		pkg, ver, ok := cutLast(parts[0], "@")
		if !ok || pkg == "" || ver == "" {
			break
		}
		v := scVuln{Version: ver, Severity: parseBandChar(parts[1]), Advisory: parts[2], EPSS: -1}
		if len(parts) == 4 {
			applyFlags(&v, parts[3])
		}
		sc.vulns[scHash(pkg)] = append(sc.vulns[scHash(pkg)], v)
		return
	}
	sc.dropped++
}

// applyFlags reads the optional comma-separated tail of a vulnerability line.
func applyFlags(v *scVuln, flags string) {
	for _, f := range strings.Split(flags, ",") {
		switch k, val, _ := strings.Cut(f, "="); k {
		case "kev":
			v.KEV = true
		case "nofix":
			v.NoFix = true
		case "fix":
			// Only when the range itself named no upper bound — a `last_affected` row, or an
			// enumerated version. Otherwise the span's bound is the branch-correct answer and this
			// advisory-level value would undo it.
			if v.FixedIn == "" {
				v.FixedIn = val
			}
		case "epss":
			if n, err := strconv.ParseFloat(val, 64); err == nil {
				v.EPSS = n
			}
		}
	}
}

// cutLast splits on the LAST occurrence of sep. A scoped npm name starts with `@`, so finding the
// version separator from the left would cut `@ctrl/tinycolor@4.1.1` in the wrong place.
func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// --- semver ------------------------------------------------------------------------------------

// semver is a parsed version, comparable with compareSemver.
type semver struct {
	major, minor, patch int
	// Dot-separated prerelease identifiers, empty for a release.
	pre []string
}

// The console's regex, character for character. OSV bounds are plain versions, frequently written
// `0`, so missing minor/patch default to zero: treating `0` as unparseable would silently drop a
// range's lower bound and with it the entire range.
var semverRE = regexp.MustCompile(`^[v=\s]*(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\s*$`)

func parseSemver(v string) (semver, bool) {
	if v == "" {
		return semver{}, false
	}
	m := semverRE.FindStringSubmatch(v)
	if m == nil {
		return semver{}, false
	}
	n := func(s string) int {
		if s == "" {
			return 0
		}
		x, err := strconv.Atoi(s)
		if err != nil {
			return 0
		}
		return x
	}
	out := semver{major: n(m[1]), minor: n(m[2]), patch: n(m[3])}
	if m[4] != "" {
		out.pre = strings.Split(m[4], ".")
	}
	return out, true
}

// comparePre implements semver §11 for prerelease identifiers: numeric identifiers rank below
// alphanumeric ones, and when one list is a prefix of the other the longer wins.
func comparePre(a, b []string) int {
	// A release outranks any prerelease of the same core version — 1.0.0 > 1.0.0-rc1.
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	n := min(len(a), len(b))
	for i := range n {
		x, y := a[i], b[i]
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				return cmpInt(xn, yn)
			}
		case (xerr == nil) != (yerr == nil):
			if xerr == nil {
				return -1 // numeric identifiers always have lower precedence
			}
			return 1
		case x != y:
			if x < y {
				return -1
			}
			return 1
		}
	}
	return cmpInt(len(a), len(b))
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compareSemver is a total order over parsed versions, prerelease-aware.
func compareSemver(a, b semver) int {
	if c := cmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpInt(a.patch, b.patch); c != 0 {
		return c
	}
	return comparePre(a.pre, b.pre)
}

// inSpan reports whether version falls inside `[introduced, fixed)` or `[introduced, lastAffected]`.
//
// Both upper bounds empty means "introduced, never fixed" — everything at or above the lower bound.
// An UNPARSEABLE bound is ignored rather than treated as matching, which is the deliberate direction
// to fail: a version nobody can read is let through rather than blocked on a guess, because a false
// block on a package the organization actually depends on is the failure that gets the whole feature
// switched off. The malware matchers are exact-string and unaffected by any of this.
func (v scVuln) inSpan(version semver) bool {
	lo, ok := parseSemver(v.Introduced)
	if !ok {
		lo = semver{}
	}
	if compareSemver(version, lo) < 0 {
		return false
	}
	if v.Fixed != "" {
		if hi, ok := parseSemver(v.Fixed); ok && compareSemver(version, hi) >= 0 {
			return false
		}
	}
	if v.LastAffect != "" {
		if last, ok := parseSemver(v.LastAffect); ok && compareSemver(version, last) > 0 {
			return false
		}
	}
	return true
}

// --- the decision ------------------------------------------------------------------------------

// supplyHit is everything the refusal has to say. The 403 body is the entire UX of this feature — it
// is what a developer reads in `npm install` output — so it names the package, the version, the
// advisory, the severity, and where to go next.
type supplyHit struct {
	Package  string
	Version  string
	Advisory string
	Severity string
	FixedIn  string
	KEV      bool
	// Reason is the machine-readable why: malware, malware_tail, severity, kev, epss, unfixed, stale.
	Reason string
	// Detail is the same thing in a sentence, for the log line and the body.
	Detail string
	// BlocklistVersion is the document this came from, so a refusal can be traced back to exactly
	// what the console published rather than to "the blocklist, at some point".
	BlocklistVersion int64
	// Block distinguishes a refusal from an observation. An organization on `monitor`, or an
	// advisory with no fix, produces a hit that is reported and let through.
	Block bool
}

// message is the line a developer reads.
func (h supplyHit) message() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s@%s", h.Package, h.Version)
	if h.Block {
		b.WriteString(" is blocked")
	} else {
		b.WriteString(" is flagged")
	}
	if h.Advisory != "" {
		fmt.Fprintf(&b, " — %s", h.Advisory)
		if h.Severity != "" && h.Severity != "unknown" {
			fmt.Fprintf(&b, " (%s)", strings.ToUpper(h.Severity))
		}
	} else if h.Severity != "" && h.Severity != "unknown" {
		fmt.Fprintf(&b, " — %s", strings.ToUpper(h.Severity))
	}
	if h.Detail != "" {
		fmt.Fprintf(&b, ": %s", h.Detail)
	}
	if h.FixedIn != "" {
		fmt.Fprintf(&b, ". Fixed in %s", h.FixedIn)
	}
	return b.String()
}

// outcome maps a mode to what it does. `off` is not even evaluated.
func outcomeOf(m scMode) (block bool, evaluate bool) {
	switch m {
	case scEnforce:
		return true, true
	case scMonitor:
		return false, true
	}
	return false, false
}

// decide evaluates one package version against the posture.
//
// Order matters and is not arbitrary. Malware outranks vulnerabilities — it is categorically worse
// and has no false-positive story — and within vulnerabilities the KEV override is checked BEFORE
// the severity threshold, so a known-exploited moderate reports as `kev` rather than as a threshold
// hit. That distinction is the entire message a developer reads: "blocked because it is being
// exploited right now", not "blocked because your organization set a number".
func (sc *supplyChain) decide(pkg ParsedPackage) (supplyHit, bool) {
	key := pkg.Ecosystem + "/" + pkg.Name

	// Pinned before the tail. The console's reference walks one array in corpus order, which makes
	// the choice arbitrary when a package appears in both; taking the specific entry first is the
	// same decision with a better message, because a pinned entry carries an advisory id.
	if advisory, ok := sc.pinned[scHash(key+"@"+pkg.Version)]; ok {
		if block, eval := outcomeOf(sc.Posture.Malware); eval {
			return supplyHit{
				Package: pkg.Name, Version: pkg.Version, Advisory: advisory,
				Severity: bandCritical.String(), Reason: "malware", Block: block,
				Detail: "this exact version is a known-compromised release",
			}, true
		}
	}
	if _, ok := sc.tail[scHash(key)]; ok {
		if block, eval := outcomeOf(sc.Posture.Tail); eval {
			return supplyHit{
				Package: pkg.Name, Version: pkg.Version,
				Severity: bandCritical.String(), Reason: "malware_tail", Block: block,
				Detail: "every version of this package is flagged as malicious",
			}, true
		}
	}

	vulnBlock, eval := outcomeOf(sc.Posture.CVEAction)
	if !eval {
		return supplyHit{}, false
	}
	entries := sc.vulns[scHash(key)]
	if len(entries) == 0 {
		return supplyHit{}, false
	}
	version, ok := parseSemver(pkg.Version)
	if !ok {
		// Not semver-shaped, so no range can be evaluated against it. Let it through rather than
		// guess — see inSpan.
		return supplyHit{}, false
	}

	var best supplyHit
	var found bool
	for _, v := range entries {
		if v.Version != "" {
			if v.Version != pkg.Version {
				continue
			}
		} else if !v.inSpan(version) {
			continue
		}

		// An advisory with no fix is REPORTED, not blocked, unless the organization opted in.
		// Blocking it leaves the developer with nowhere to go, and that is how a control gets
		// disabled wholesale rather than tuned. The row still ships so the finding is not lost.
		if v.NoFix && !sc.Posture.BlockUnfixed {
			if !found {
				best = supplyHit{
					Package: pkg.Name, Version: pkg.Version, Advisory: v.Advisory,
					Severity: v.Severity.String(), KEV: v.KEV, Reason: "unfixed", Block: false,
					Detail: "no fixed version is available yet, so this is reported rather than blocked",
				}
				found = true
			}
			continue
		}

		hit := supplyHit{
			Package: pkg.Name, Version: pkg.Version, Advisory: v.Advisory,
			Severity: v.Severity.String(), FixedIn: v.FixedIn, KEV: v.KEV, Block: vulnBlock,
		}
		switch {
		case sc.Posture.KEV && v.KEV:
			hit.Reason = "kev"
			hit.Detail = "confirmed exploited in the wild (CISA KEV)"
		case v.Severity.meets(sc.Posture.Threshold):
			hit.Reason = "severity"
			hit.Detail = fmt.Sprintf("rated %s, at or above this organization's %s threshold",
				v.Severity, sc.Posture.Threshold)
		case sc.Posture.EPSS >= 0 && v.EPSS >= 0 && v.EPSS >= sc.Posture.EPSS:
			hit.Reason = "epss"
			hit.Detail = fmt.Sprintf("exploitation probability %.1f%%, at or above the configured threshold",
				v.EPSS*100)
		default:
			// The document is compiled per organization, so a row that none of these selects should
			// not be in it. Skipping rather than blocking keeps a stale or hand-edited document from
			// refusing something this posture never asked to refuse.
			continue
		}

		// A real block beats a monitor-only `unfixed` note, and KEV beats a plain threshold hit, so
		// the developer is told the most alarming TRUE thing rather than the first one found.
		if !found || !best.Block || (hit.Reason == "kev" && best.Reason != "kev") {
			best, found = hit, true
		}
	}
	return best, found
}

// --- registry URL parsing ------------------------------------------------------------------------

// ParsedPackage is a package identified from a registry URL.
type ParsedPackage struct {
	Ecosystem string
	Name      string
	Version   string
}

// parseRegistryPath turns a request path into `(name, version)` for an npm tarball fetch.
//
// Exact, not heuristic. npm tarball paths always contain the literal segment `/-/`:
//
//	/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz  →  @ctrl/tinycolor @ 4.1.1
//	/express/-/express-4.22.2.tgz           →  express @ 4.22.2
//
// The name is the left side; the file must be `{basename}-{version}.tgz`. Deriving the version by
// stripping that known prefix survives both hyphenated package names and prerelease versions
// (`1.2.3-beta.1`), which a "split on the last dash" shortcut gets wrong in both directions.
//
// Only TARBALL requests are parsed. Metadata requests must stay allowed or dependency resolution
// breaks long before it ever reaches a blocked version — a blocklist that also broke `npm view` is
// a blocklist an organization turns off.
func parseRegistryPath(path string, prefixes []string) (ParsedPackage, bool) {
	p, _, _ := strings.Cut(path, "?")
	for _, prefix := range prefixes {
		if prefix != "" && strings.HasPrefix(p, prefix) {
			p = strings.TrimPrefix(p, prefix)
			break
		}
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Index 0 is the registry's own `/-/v1/search`, not a package: there is no name to the left of
	// it. A bare `< 0` test would slice p[1:0] and take the proxy's connection down with it.
	marker := strings.Index(p, "/-/")
	if marker < 1 {
		return ParsedPackage{}, false
	}
	name := p[1:marker]
	file := p[marker+3:]
	if name == "" || !strings.HasSuffix(file, ".tgz") || strings.Contains(file, "/") {
		return ParsedPackage{}, false
	}
	// A scoped name has exactly one slash; anything more is not a package path.
	if strings.HasPrefix(name, "@") {
		if strings.Count(name, "/") != 1 {
			return ParsedPackage{}, false
		}
	} else if strings.Contains(name, "/") {
		return ParsedPackage{}, false
	}
	base := name[strings.LastIndex(name, "/")+1:]
	stem := strings.TrimSuffix(file, ".tgz")
	if !strings.HasPrefix(stem, base+"-") {
		return ParsedPackage{}, false
	}
	version := stem[len(base)+1:]
	if version == "" {
		return ParsedPackage{}, false
	}
	return ParsedPackage{Ecosystem: "npm", Name: name, Version: version}, true
}
