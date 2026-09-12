package main

// A cross-implementation test vector for the supply-chain document.
//
// The bytes below were produced by the CONSOLE — `compile()` over a corpus, then
// `signDocument()` — not by this package and not by hand. That is the whole point: the console
// compiles and signs, this client parses and enforces, and the Rust broker does the same a third
// time. Three implementations of one wire format is the seam most likely to break silently, because
// a mismatch does not fail: it means every guard in the fleet quietly enforces nothing while still
// reporting itself as protecting the build.
//
// So the agreement is pinned here — the domain tag, the payload layout, the header grammar, the four
// entry shapes, and the decisions they produce. A change on either side fails in this test rather
// than in the field.
//
// The signing key is the RFC 8032 test key, the same one rules_vector_test.go uses.

import (
	"strings"
	"testing"
)

const (
	scVecVersion = int64(1789234440)
	scVecPub     = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	scVecSig     = "bdd82d9d18f4dd65415ac430c73c1d877e92f5cb024265a71124a7cd2c6705e2bd5a2e0e9e36576e8d9a40dc85f3a66179ccad3080e208e353bab3b3de02a902"
	scVecDoc     = `# deter-supply-chain v1
# generated=2026-09-12T16:34:00.000Z scope=ci
# malware=enforce tail=enforce cve=high action=enforce kev=on unfixed=report stale=warn:24h
# registries=registry.npmjs.org,registry.yarnpkg.com,npm.pkg.github.com
# corpus=2026-09-12T16:00:00.000Z sources=osv,cisa-kev entries=6
!npm/reqeusts
=npm/@ctrl/tinycolor@4.1.1:MAL-2025-47141
~npm/abandoned-pkg:1.0.0:::C:GHSA-0000-nofix-0000:nofix
~npm/lodash:0::4.17.20:H:GHSA-35jh-r3h4-6jhm:fix=4.17.21
~npm/vite:4.0.0:4.5.11::M:GHSA-4r4m-qw57-chr8:kev,fix=4.5.11,epss=0.412
~npm/vite:6.2.0:6.2.4::M:GHSA-4r4m-qw57-chr8:kev,fix=6.2.4,epss=0.412
`
)

func TestConsoleSignedSupplyChainVerifies(t *testing.T) {
	if err := verifySupplyChain(scVecVersion, scVecDoc, scVecSig, scVecPub); err != nil {
		t.Fatalf("a document signed by the console must verify here: %v", err)
	}
}

func TestTamperedSupplyChainIsRejected(t *testing.T) {
	// NARROWING the blocklist by one character must break the signature. That is the attack this
	// exists to stop: an attacker who can serve the document does not need to add anything, only to
	// quietly drop the package they are about to ship.
	tampered := strings.Replace(scVecDoc, "=npm/@ctrl/tinycolor@4.1.1", "=npm/@ctrl/tinycolor@9.9.9", 1)
	if tampered == scVecDoc {
		t.Fatal("the test did not actually tamper with anything")
	}
	if err := verifySupplyChain(scVecVersion, tampered, scVecSig, scVecPub); err == nil {
		t.Fatal("a tampered supply-chain document verified")
	}
}

func TestSupplyChainDocumentSignedForAnotherVersionIsRejected(t *testing.T) {
	// The version is inside the signed payload, so replaying yesterday's document under today's
	// version number does not work either.
	if err := verifySupplyChain(scVecVersion+1, scVecDoc, scVecSig, scVecPub); err == nil {
		t.Fatal("a document replayed under a different version verified")
	}
}

// mustVector parses the console's document, which every decision test below runs against.
func mustVector(t *testing.T) *supplyChain {
	t.Helper()
	sc, err := parseSupplyChainDoc(scVecDoc, scVecVersion)
	if err != nil {
		t.Fatalf("the console's own document did not parse: %v", err)
	}
	return sc
}

func TestConsoleHeaderIsReadTheSameWayItWasWritten(t *testing.T) {
	p := mustVector(t).Posture
	if p.Malware != scEnforce || p.Tail != scEnforce || p.CVEAction != scEnforce {
		t.Errorf("modes: got malware=%s tail=%s action=%s", p.Malware, p.Tail, p.CVEAction)
	}
	if p.Threshold != bandHigh {
		t.Errorf("threshold: got %s, want high", p.Threshold)
	}
	if !p.KEV {
		t.Error("the KEV override is on in the document and must be read as on — it is the only " +
			"reason the three known-exploited moderates get blocked at a high threshold")
	}
	if p.BlockUnfixed {
		t.Error("unfixed=report must not be read as blocking")
	}
	if p.OnStale != scStaleWarn || p.StaleHours != 24 {
		t.Errorf("stale: got %s/%v", p.OnStale, p.StaleHours)
	}
	if p.Scope != "ci" {
		t.Errorf("scope: got %q", p.Scope)
	}
	if len(p.Registries) != 3 || p.Registries[0] != "registry.npmjs.org" {
		t.Errorf("registries: got %v", p.Registries)
	}
}

// TestConsoleDocumentDecisions is the table that matters: one real document, every shape of entry in
// it, and the verdict each produces.
func TestConsoleDocumentDecisions(t *testing.T) {
	sc := mustVector(t)
	cases := []struct {
		name, pkg, version string
		block              bool
		hit                bool
		reason             string
		advisory           string
		fixedIn            string
	}{
		// A moderate that a `high` threshold would let straight through, blocked because CISA lists
		// it as exploited. This single row is the argument for the KEV override existing.
		{"kev beats the threshold", "vite", "6.2.1", true, true, "kev", "GHSA-4r4m-qw57-chr8", "6.2.4"},
		// The fix reported is the one for the BRANCH this version is on. The advisory is also fixed
		// in 4.5.11, and telling someone on 6.2.1 to go there is a downgrade across two majors —
		// the bug the console's own end-to-end run caught, asserted here so this port cannot repeat it.
		{"the older branch reports its own fix", "vite", "4.1.0", true, true, "kev", "GHSA-4r4m-qw57-chr8", "4.5.11"},
		{"the fixed version is not blocked", "vite", "6.2.4", false, false, "", "", ""},
		{"between the branches is not affected", "vite", "5.0.0", false, false, "", "", ""},

		// last_affected rather than fixed: inclusive upper bound.
		{"last_affected is inclusive", "lodash", "4.17.20", true, true, "severity", "GHSA-35jh-r3h4-6jhm", "4.17.21"},
		{"one past last_affected is clean", "lodash", "4.17.21", false, false, "", "", ""},

		// Malware: set membership, no version arithmetic.
		{"a pinned compromised release", "@ctrl/tinycolor", "4.1.1", true, true, "malware", "MAL-2025-47141", ""},
		{"its sibling version is fine", "@ctrl/tinycolor", "4.1.2", false, false, "", "", ""},
		{"the typosquat tail is every version", "reqeusts", "2.31.0", true, true, "malware_tail", "", ""},

		// No fix anywhere: reported, never blocked, because blocking leaves nowhere to go.
		{"an unfixed advisory is reported only", "abandoned-pkg", "1.5.0", false, true, "unfixed", "GHSA-0000-nofix-0000", ""},

		{"a package in no list at all", "express", "4.22.2", false, false, "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hit, ok := sc.decide(ParsedPackage{Ecosystem: "npm", Name: c.pkg, Version: c.version})
			if ok != c.hit {
				t.Fatalf("matched=%v, want %v (%+v)", ok, c.hit, hit)
			}
			if !ok {
				return
			}
			if hit.Block != c.block {
				t.Errorf("block=%v, want %v", hit.Block, c.block)
			}
			if hit.Reason != c.reason {
				t.Errorf("reason=%q, want %q", hit.Reason, c.reason)
			}
			if hit.Advisory != c.advisory {
				t.Errorf("advisory=%q, want %q", hit.Advisory, c.advisory)
			}
			if hit.FixedIn != c.fixedIn {
				t.Errorf("fixedIn=%q, want %q — wrong advice in a denial is worse than none",
					hit.FixedIn, c.fixedIn)
			}
		})
	}
}
