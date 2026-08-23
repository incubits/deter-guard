package main

// A cross-implementation test vector for the compiled rule set.
//
// The bytes and signature below were produced by the CONSOLE (`signWithDomain(RULES_DOMAIN,
// compiledPayload(...))`), not by this package. That is the whole point: the console signs and this
// client verifies, so the two must agree on the domain tag, the payload layout, and the canonical
// JSON encoding down to key order and whitespace.
//
// If a change on either side breaks that agreement, this test fails here rather than every CI job in
// the field silently refusing to start — or worse, accepting something unverified.

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	vecVersion = int64(42)
	vecSigned  = `{"blocked":[{"host":"registry.npmjs.org","path_globs":["*/left-pad-1.3.0.tgz"],"reason":"on the blocklist"}],"rules":[{"active":true,"group":null,"host":"registry.npmjs.org","methods":[],"path_prefixes":[]},{"active":true,"group":null,"host":"api.example.com","methods":["GET"],"path_prefixes":["/v1/"]}]}`
	vecSig     = "929c333e6db869efe82bf92af78c92901753c07ebce809eda8d99db65b868cdb48c77e23dcc2d1b2e8aace107bdcf0bd30ea464e09f15207e7af9129302bdb0e"
	vecPub     = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

func TestConsoleSignedRuleSetVerifies(t *testing.T) {
	if err := verifyRules(vecVersion, vecSigned, vecSig, vecPub); err != nil {
		t.Fatalf("a rule set signed by the console must verify here: %v", err)
	}
}

func TestTamperedRuleSetIsRejected(t *testing.T) {
	// Widening the policy by one character must break the signature — this is the attack the
	// signature exists to stop.
	tampered := strings.Replace(vecSigned, "api.example.com", "evil.example.com", 1)
	if tampered == vecSigned {
		t.Fatal("the test did not actually tamper with anything")
	}
	if err := verifyRules(vecVersion, tampered, vecSig, vecPub); err == nil {
		t.Fatal("a tampered rule set verified")
	}
}

func TestRuleSetVersionIsCoveredBySignature(t *testing.T) {
	// The version is inside the signed payload, so a replayed older bundle cannot be relabelled.
	if err := verifyRules(vecVersion+1, vecSigned, vecSig, vecPub); err == nil {
		t.Fatal("changing the version must invalidate the signature")
	}
}

func TestVectorParsesIntoTheEnforcedPolicy(t *testing.T) {
	// Verifying bytes is only useful if the bytes we verified are the ones we enforce.
	var inner struct {
		Rules   []Rule  `json:"rules"`
		Blocked []Block `json:"blocked"`
	}
	if err := json.Unmarshal([]byte(vecSigned), &inner); err != nil {
		t.Fatalf("the signed payload must be the policy we parse: %v", err)
	}
	p := &Policy{Version: vecVersion, Rules: inner.Rules, Blocked: inner.Blocked}

	if d := p.Check("registry.npmjs.org", "GET", "/left-pad/-/left-pad-1.2.0.tgz"); !d.Allow {
		t.Error("the registry should be reachable")
	}
	if d := p.Check("registry.npmjs.org", "GET", "/left-pad/-/left-pad-1.3.0.tgz"); d.Allow {
		t.Error("the blocklisted tarball should be refused")
	}
	// The console's method/path narrowing has to mean the same thing out here.
	if d := p.Check("api.example.com", "GET", "/v1/x"); !d.Allow {
		t.Error("GET /v1/ should be allowed")
	}
	if d := p.Check("api.example.com", "POST", "/v1/x"); d.Allow {
		t.Error("POST should be denied — the console narrowed this rule to GET")
	}
	if d := p.Check("api.example.com", "GET", "/other"); d.Allow {
		t.Error("a path outside /v1/ should be denied")
	}
}
