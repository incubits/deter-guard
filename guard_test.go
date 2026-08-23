package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

func TestSignedPayloadIsTheContract(t *testing.T) {
	// If this ever changes on one side only, the guard silently rejects every real policy — or worse,
	// accepts a forged one. Pinned so a divergence is a failing test, not a production mystery.
	got := string(signedPayload(42, "permit(principal, action, resource);"))
	want := "42\npermit(principal, action, resource);"
	if got != want {
		t.Fatalf("signed payload = %q, want %q", got, want)
	}
}

func TestAcceptsConsoleSignature(t *testing.T) {
	// Vector produced by the console's TypeScript signer (@noble/curves) with a fixed 32-byte key
	// (all 0x42) — the same vector the broker's Rust verifier is pinned against. Three
	// implementations, one signature; ed25519 is deterministic, so they must agree byte for byte.
	const pub = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
	const policy = "permit(principal == Deter::\"sandbox\", action == Action::\"connect\", resource == Net::\"egress\") when { context.host == \"api.anthropic.com\" };\n"
	const sig = "a5679c310de8a984445c45c5d3fd9cdc9b85068d8eace3cf99e08dd695c69723cf4c0237d964f0e17d94c1d7104d06f3b15d425c70a20beed2b4ebcf95125c0c"

	if err := verifyBundle(SignedBundle{Version: 100, Policy: policy, Sig: sig}, pub); err != nil {
		t.Fatalf("a real console signature must verify, got: %v", err)
	}
}

func signFixture(t *testing.T, version int64, policy string) (SignedBundle, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, signedPayload(version, policy))
	return SignedBundle{Version: version, Policy: policy, Sig: hex.EncodeToString(sig)},
		hex.EncodeToString(pub)
}

func TestRejectsTampering(t *testing.T) {
	b, pub := signFixture(t, 7, `permit(principal, action, resource) when { context.host == "ok.com" };`)
	if err := verifyBundle(b, pub); err != nil {
		t.Fatalf("baseline should verify: %v", err)
	}

	// The version is INSIDE the signature, so a rollback changes the payload.
	rolled := b
	rolled.Version = 6
	if err := verifyBundle(rolled, pub); err == nil {
		t.Error("a rolled-back version must not verify")
	}

	// Widening the policy under the original signature must fail — this is the whole point.
	widened := b
	widened.Policy = strings.ReplaceAll(b.Policy, "ok.com", "evil.com")
	if err := verifyBundle(widened, pub); err == nil {
		t.Error("a widened policy must not verify")
	}

	// A different key doesn't verify.
	_, other := signFixture(t, 7, "x")
	if err := verifyBundle(b, other); err == nil {
		t.Error("a foreign key must not verify")
	}
}

func TestMalformedInputIsAnErrorNotAPanic(t *testing.T) {
	b, pub := signFixture(t, 1, "p")
	cases := []struct {
		name   string
		bundle SignedBundle
		key    string
	}{
		{"non-hex signature", SignedBundle{1, "p", "nothex"}, pub},
		{"short signature", SignedBundle{1, "p", "abcd"}, pub},
		{"short key", b, "abcd"},
		{"non-hex key", b, strings.Repeat("zz", 32)},
		{"no signature", SignedBundle{Version: 1, Policy: "p"}, pub},
		{"no policy", SignedBundle{Version: 1, Sig: b.Sig}, pub},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := verifyBundle(c.bundle, c.key); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestKeyFingerprintDoesNotLeakTheKey(t *testing.T) {
	key := strings.Repeat("a", 32) + strings.Repeat("b", 32)
	fp := keyFingerprint(key)
	if fp == key {
		t.Error("fingerprint must not be the whole key")
	}
	if len([]rune(fp)) > 20 {
		t.Errorf("fingerprint too long for a log line: %q", fp)
	}
	if keyFingerprint("short") != "short" {
		t.Error("a short value should pass through")
	}
}

// ---------------------------------------------------------------------------------------------
// Credential discovery
// ---------------------------------------------------------------------------------------------

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestExplicitTokenWins(t *testing.T) {
	// Any platform can opt in by setting this, which is what makes GitLab (and Buildkite, and
	// anything else) work without the guard knowing about them.
	got, err := getIDToken(context.Background(), defaultAudience,
		envFrom(map[string]string{"DETER_ID_TOKEN": "  tok  "}))
	if err != nil {
		t.Fatal(err)
	}
	if got.token != "tok" || got.source != srcExplicit {
		t.Fatalf("got %+v", got)
	}
}

func TestGitLabGetsTheExactSnippet(t *testing.T) {
	_, err := getIDToken(context.Background(), defaultAudience,
		envFrom(map[string]string{"GITLAB_CI": "true"}))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !isOidcError(err) {
		t.Fatalf("expected an oidcError, got %T", err)
	}
	// GitLab can't be auto-detected because the job must name the token, so the message has to
	// carry the YAML rather than describe it.
	for _, want := range []string{"id_tokens:", "DETER_ID_TOKEN", defaultAudience} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message should mention %q, got:\n%s", want, err)
		}
	}
}

func TestNoIdentityNamesEveryOption(t *testing.T) {
	_, err := getIDToken(context.Background(), defaultAudience, envFrom(nil))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"id-token: write", "DETER_ID_TOKEN", "DETER_CI_TOKEN"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message should mention %q, got:\n%s", want, err)
		}
	}
}

func TestLooksLikeCI(t *testing.T) {
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL"} {
		if !looksLikeCI(envFrom(map[string]string{k: "1"})) {
			t.Errorf("%s should be detected", k)
		}
	}
	if looksLikeCI(envFrom(nil)) {
		t.Error("an empty environment is not CI")
	}
}

// ---------------------------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------------------------

func TestBaseURLTrimsTrailingSlashes(t *testing.T) {
	// A pasted console URL with a trailing slash would otherwise produce `//api/ci/policy`, which
	// some proxies treat as a different path.
	for in, want := range map[string]string{
		"https://c.example.com/":   "https://c.example.com",
		"https://c.example.com///": "https://c.example.com",
		"  https://c.example.com ": "https://c.example.com",
		"https://c.example.com":    "https://c.example.com",
	} {
		if got := baseURL(in); got != want {
			t.Errorf("baseURL(%q) = %q, want %q", in, got, want)
		}
	}
}
