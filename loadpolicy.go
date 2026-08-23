package main

// Getting a compiled policy to the proxy.
//
// Two sources, and which one is used says something different about trust:
//
//   --policy <file>   a local file. Convenient for testing and for an air-gapped runner, but it is
//                     whatever is on disk: no signature, no provenance.
//   the console       fetched over an authenticated call and ed25519-verified against a pinned key.
//                     This is the one that means anything.
//
// The signature covers `version + "\n" + <canonical rules JSON>` under its own domain tag, so a
// rules bundle can never be replayed as a Cedar policy bundle and vice versa — the two have
// different meanings to different clients, and one signature that satisfied both would be a way to
// turn one into the other.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// rulesResponse is what the console serves for clients that do not evaluate Cedar.
type rulesResponse struct {
	Version int64   `json:"version"`
	Rules   []Rule  `json:"rules"`
	Blocked []Block `json:"blocked"`
	// Canonical JSON of {rules, blocked} exactly as signed. Sent verbatim so the client verifies the
	// bytes the console signed rather than a re-serialisation of them — re-encoding JSON and hoping
	// it matches is how signature checks quietly stop meaning anything.
	Signed string `json:"signed"`
	Sig    string `json:"sig"`
	Pubkey string `json:"pubkey"`
}

// loadPolicyFile reads a compiled policy from disk. Unsigned by nature — the caller decides whether
// that is acceptable and says so.
func loadPolicyFile(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("%s is not a valid policy: %w", path, err)
	}
	return &p, nil
}

// fetchRules pulls the compiled rule set and verifies it against `pinned` when one is given.
//
// Returns the policy, the key the server claimed, and whether the signature was actually checked
// against a pinned key. An unverified policy is still returned — a caller may legitimately run
// unpinned on a first outing — but it must be told, so it can say so out loud.
func fetchRules(ctx context.Context, consoleURL, token, pinned string, headers map[string]string) (*Policy, string, bool, error) {
	var r rulesResponse
	err := call(ctx, http.MethodGet, baseURL(consoleURL)+"/api/ci/rules", token, nil, headers, &r)
	if err != nil {
		return nil, "", false, err
	}
	if r.Signed == "" || r.Sig == "" {
		return nil, r.Pubkey, false, errors.New("the console returned an unsigned rule set")
	}

	key := pinned
	if key == "" {
		key = r.Pubkey
	}
	if err := verifyRules(r.Version, r.Signed, r.Sig, key); err != nil {
		return nil, r.Pubkey, false, err
	}

	// Trust the SIGNED bytes, not the convenience fields beside them. A server that sent one thing
	// to verify and another to enforce would otherwise get exactly what it wanted.
	var inner struct {
		Rules   []Rule  `json:"rules"`
		Blocked []Block `json:"blocked"`
	}
	if err := json.Unmarshal([]byte(r.Signed), &inner); err != nil {
		return nil, r.Pubkey, false, fmt.Errorf("the signed rule set is not valid JSON: %w", err)
	}
	p := &Policy{Version: r.Version, Rules: inner.Rules, Blocked: inner.Blocked}
	return p, r.Pubkey, pinned != "", nil
}
