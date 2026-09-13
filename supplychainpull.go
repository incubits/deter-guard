package main

// Getting the signed supply-chain document to the proxy.
//
// Same shape as the egress policy's pull, and deliberately NOT the same failure direction.
//
// The egress policy fails CLOSED: no policy means no egress, because a guard that let everything
// through while reporting itself as guarding would be worse than no guard. This artifact is the
// opposite. It changes every fifteen minutes as feeds move, it is not the thing that decides whether
// a build may reach the internet at all, and a console outage must not break every `npm ci` in the
// fleet. So every failure here — unreachable, unpublished, unverifiable, unparseable — degrades
// package blocking and says so loudly, and none of them stops the build.
//
// That asymmetry is the single most important property of this file, and it is why the pull lives
// here rather than being folded into resolvePolicy's error handling, where "could not fetch" already
// means "refuse to run".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// supplyChainBundle is what /api/ci/supply-chain serves. No `pubkey` field, unlike the policy and
// rules responses — see resolveSupplyChain for which key this is verified against and why.
type supplyChainBundle struct {
	Version int64  `json:"version"`
	Scope   string `json:"scope"`
	Doc     string `json:"doc"`
	Sig     string `json:"sig"`
}

// The compiled document is ~7 MB of text for the default posture (1.5 MB on the wire, gzipped by the
// transport). The shared 8 MB response ceiling is meant for JSON API replies and this would sit right
// against it, so the pull gets its own headroom. Truncation here would mean no enforcement rather
// than partial enforcement — the signature would not verify — but "it worked until the corpus grew"
// is not a property worth shipping.
const supplyChainMaxBytes = 64 << 20

// fetchSupplyChain pulls this project's document. The console resolves the CI token to a project and
// serves that project's document when it has an exemption, so the guard asks for nothing special.
func fetchSupplyChain(ctx context.Context, consoleURL, token string, headers map[string]string) (supplyChainBundle, error) {
	var b supplyChainBundle
	err := callLimited(ctx, http.MethodGet, baseURL(consoleURL)+"/api/ci/supply-chain", token, nil,
		headers, &b, supplyChainMaxBytes)
	return b, err
}

// loadSupplyChainFile reads a document from disk: an air-gapped runner, or a test.
//
// Accepts either the raw document or the bundle JSON the console serves, because somebody debugging
// this will have saved whichever one they had. Unsigned by nature — the caller says so out loud.
func loadSupplyChainFile(path string) (*supplyChain, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	text := strings.TrimLeft(string(raw), " \t\r\n")
	version := int64(0)
	if strings.HasPrefix(text, "{") {
		var b supplyChainBundle
		if err := json.Unmarshal([]byte(text), &b); err != nil {
			return nil, fmt.Errorf("%s is not a supply-chain bundle: %w", path, err)
		}
		text, version = b.Doc, b.Version
	}
	sc, err := parseSupplyChainDoc(text, version)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	sc.Source = path
	return sc, nil
}

// resolveSupplyChain produces the blocklist the proxy will enforce, or nil.
//
// nil is an ordinary outcome, not an error: an organization that has published no document, a
// console that cannot be reached, a key the guard has no way to check a signature against. Every one
// of those means package blocking does not happen on this run, and every one of them is logged in
// terms an operator can act on — a silently disabled security control is worse than an absent one.
//
// `key` is the same key the egress policy was verified against, resolved by the caller in the same
// order: an explicitly PINNED key, then the key the OIDC session reported at exchange time, then the
// key the console served alongside the rules. `pinned` says which, because only the first is a
// security claim and the guard should not print a word suggesting otherwise.
func resolveSupplyChain(ctx context.Context, o opts, token, key string, pinned bool, headers map[string]string) *supplyChain {
	if o.noSupplyChain {
		return nil
	}
	if o.supplyFile != "" {
		sc, err := loadSupplyChainFile(o.supplyFile)
		if err != nil {
			errf("supply-chain blocklist NOT in force: %s", err)
			return nil
		}
		logf("supply-chain blocklist from %s (UNSIGNED — nothing verified), %s",
			o.supplyFile, sc.describe())
		sc.warnIfUnreadable()
		return sc
	}
	if o.consoleURL == "" || token == "" {
		return nil
	}

	b, err := fetchSupplyChain(ctx, o.consoleURL, token, headers)
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.Status == http.StatusNotImplemented) {
			// Nothing published for this organization yet. Not a fault, and not worth a warning that
			// reads like one — but it IS worth a line, because "why did my blocked package install?"
			// has to be answerable from the build log.
			logf("no supply-chain blocklist published for this organization — package blocking is not in force")
			return nil
		}
		errf("could not fetch the supply-chain blocklist (%s) — package blocking is NOT in force "+
			"for this build. The egress policy is unaffected.", err)
		return nil
	}
	if b.Doc == "" {
		logf("the supply-chain blocklist is empty — package blocking is not in force")
		return nil
	}

	if key == "" {
		// No key means no check is possible, and enforcing a quarter of a million entries nobody
		// authenticated is not a trade worth making: anything that can answer the console's address
		// could then fail this build at will. Fail open, and name the fix.
		errf("supply-chain blocklist NOT in force: no public key to verify it against. " +
			"Set DETER_POLICY_PUBKEY (or use OIDC, which reports the key at exchange time).")
		return nil
	}
	if err := verifySupplyChain(b.Version, b.Doc, b.Sig, key); err != nil {
		// A signature that does not verify is the one failure here that is NOT routine. It still
		// fails open — this artifact cannot stop a build — but it is reported as what it is.
		errf("SUPPLY-CHAIN BLOCKLIST DID NOT VERIFY: %s", err)
		errf("key %s · version %d · refusing to enforce it. Treat the distribution path as "+
			"compromised until proven otherwise.", keyFingerprint(key), b.Version)
		return nil
	}

	sc, err := parseSupplyChainDoc(b.Doc, b.Version)
	if err != nil {
		errf("supply-chain blocklist NOT in force: %s", err)
		return nil
	}
	sc.Verified = pinned
	sc.Source = "console"

	// The CI endpoint serves the `ci` posture. A `developer` document arriving here would mean a
	// build running under laptop settings — usually looser, since a false block on a laptop stops
	// someone working while a red build is fixed in minutes. Worth saying out loud rather than
	// quietly enforcing the wrong half of the organization's configuration.
	if sc.Posture.Scope != "" && sc.Posture.Scope != "ci" {
		errf("this is the %q supply-chain posture, not the CI one — enforcing it anyway, but the "+
			"console served an unexpected document", sc.Posture.Scope)
	}
	if pinned {
		logf("supply-chain blocklist version %d verified against pinned key %s · %s",
			b.Version, keyFingerprint(key), sc.describe())
	} else {
		logf("supply-chain blocklist version %d verified against the key the CONSOLE SERVED (%s) · "+
			"%s — pin --pubkey to make this a real check", b.Version, keyFingerprint(key), sc.describe())
	}
	sc.warnIfUnreadable()
	sc.warnIfStale(time.Now())
	return sc
}

// describe is the one line that tells an operator what this build is actually enforcing: the posture,
// not just the fact that a document arrived.
func (sc *supplyChain) describe() string {
	p := sc.Posture
	entries := fmt.Sprintf("%d entries", len(sc.tail)+len(sc.pinned)+sc.vulnLines())
	// The console compiles eight ecosystems into one document and this guard enforces npm. Saying
	// only what was KEPT would report a number far below the header's and invite exactly the wrong
	// conclusion — that most of the document failed to parse.
	if sc.skipped > 0 {
		entries += fmt.Sprintf(" (+%d for ecosystems this guard cannot match to a download URL)", sc.skipped)
	}
	parts := []string{
		entries,
		fmt.Sprintf("malware=%s tail=%s", p.Malware, p.Tail),
	}
	if p.CVEAction == scOff {
		parts = append(parts, "cve=off")
	} else {
		cve := fmt.Sprintf("cve=%s/%s", p.Threshold, p.CVEAction)
		if p.KEV {
			cve += "+kev"
		}
		parts = append(parts, cve)
	}
	if p.Project != "" {
		parts = append(parts, "project "+p.Project+" (exempted)")
	}
	return strings.Join(parts, " · ")
}

func (sc *supplyChain) vulnLines() int {
	n := 0
	for _, v := range sc.vulns {
		n += len(v)
	}
	return n
}

// warnIfUnreadable says so when entry lines did not parse.
//
// The failure this exists for: the console changed the document's field separator from `:` to `|`
// and this parser did not, so every pinned malware release and every CVE range was dropped as
// malformed while the typosquat tail — which has no separator — kept parsing. The guard logged an
// entry count that looked fine and enforced a sliver of the posture it had just reported.
//
// Dropping the odd malformed line out of 250k is ordinary and stays quiet. Dropping a PERCENT of
// them is not a bad line, it is a grammar this build cannot read, and it is reported as what it
// costs: the blocklist is still enforced, because the part that parsed is real protection, but an
// operator is told the rest of it is not in force.
func (sc *supplyChain) warnIfUnreadable() {
	if sc.dropped == 0 {
		return
	}
	readable := len(sc.tail) + len(sc.pinned) + sc.vulnLines()
	total := readable + sc.dropped
	// 1%. Below that it is bad lines in a feed; at or above it, the console and this guard disagree
	// about the format itself.
	if total > 0 && sc.dropped*100 >= total {
		errf("%d of %d supply-chain entries could not be parsed — this guard does not understand "+
			"the format the console published. Only the %d that parsed are in force; the rest are "+
			"NOT blocked in this build. Upgrade deter-guard.", sc.dropped, total, readable)
		return
	}
	logf("%d supply-chain entries were unreadable and are not in force (%d are)", sc.dropped, readable)
}

// age is how old the document's data is. Zero when the header carried no timestamp.
func (sc *supplyChain) age(now time.Time) time.Duration {
	if sc.Posture.Generated.IsZero() {
		return 0
	}
	return now.Sub(sc.Posture.Generated)
}

// stale reports whether the document is past the organization's threshold.
func (sc *supplyChain) stale(now time.Time) bool {
	if sc.Posture.Generated.IsZero() || sc.Posture.StaleHours <= 0 {
		return false
	}
	return sc.age(now) > time.Duration(sc.Posture.StaleHours*float64(time.Hour))
}

// warnIfStale says so, once, at startup.
//
// A guard runs for one build, so this is not a background condition it can watch — it is a fact
// about the document it just pulled, and the only chance to report it is now. A blocklist the
// console stopped updating three days ago is a silently degraded control, which is exactly the shape
// of failure this whole feature exists to prevent somewhere else.
func (sc *supplyChain) warnIfStale(now time.Time) {
	if !sc.stale(now) {
		return
	}
	hours := sc.age(now).Hours()
	if sc.Posture.OnStale == scStaleBlock {
		errf("the supply-chain blocklist is %.0f h old (threshold %.0f h) and this organization set "+
			"on_stale=block_registry — every package registry is refused until it refreshes",
			hours, sc.Posture.StaleHours)
		return
	}
	errf("the supply-chain blocklist is %.0f h old (threshold %.0f h) — it is still enforced, but a "+
		"package flagged since then will NOT be blocked. Check the console's feed sync.",
		hours, sc.Posture.StaleHours)
}
