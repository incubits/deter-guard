package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
)

// SignedBundle is what the console serves: a policy, a monotonic version, and a signature over both.
type SignedBundle struct {
	Version int64  `json:"version"`
	Policy  string `json:"policy"`
	Sig     string `json:"sig"`
}

// signedPayload returns the exact bytes the signature covers.
//
// This is the contract with the console's signer and the broker's Rust verifier — three
// independent implementations of the same two lines. verify_test.go pins it against a vector
// produced by the console, so a divergence fails loudly here rather than silently accepting an
// unverified policy.
func signedPayload(version int64, policy string) []byte {
	return []byte(fmt.Sprintf("%d\n%s", version, policy))
}

// verifyBundle checks a bundle against a public key.
//
// Returns an error describing the failure rather than a bare bool: "did not verify" and "your key is
// the wrong length" call for different actions, and a pipeline operator reads this message.
func verifyBundle(b SignedBundle, pubkeyHex string) error {
	if b.Policy == "" {
		return fmt.Errorf("bundle has no policy")
	}
	if b.Sig == "" {
		return fmt.Errorf("bundle has no signature")
	}

	sig, err := hex.DecodeString(strings.TrimSpace(b.Sig))
	if err != nil {
		return fmt.Errorf("signature is not valid hex: %w", err)
	}
	pub, err := hex.DecodeString(strings.TrimSpace(pubkeyHex))
	if err != nil {
		return fmt.Errorf("public key is not valid hex: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}

	if !ed25519.Verify(ed25519.PublicKey(pub), signedPayload(b.Version, b.Policy), sig) {
		return fmt.Errorf("signature does not verify against this public key")
	}
	return nil
}

// keyFingerprint shortens a key for logs. Never print a whole key — it invites somebody to
// copy-paste the wrong one back into a pipeline.
func keyFingerprint(pubkeyHex string) string {
	k := strings.TrimSpace(pubkeyHex)
	if len(k) > 16 {
		return k[:8] + "…" + k[len(k)-8:]
	}
	return k
}

// rulesDomain tags signatures over a COMPILED RULE SET, keeping them distinct from the Cedar policy
// bundles `verifyBundle` handles.
//
// The two artifacts mean different things to different clients — Cedar text to the Rust broker, a
// flat rule set to this one. A single signature that satisfied both would be a way to present one as
// the other, so each gets its own domain and the payloads can never collide.
const rulesDomain = "deter-policy-rules-v1"

// verifyRules checks a compiled rule set's signature.
//
// `signed` is the canonical JSON exactly as the console emitted it — verified as bytes, never
// re-serialised. Re-encoding JSON and hoping the result matches is how a signature check quietly
// stops meaning anything.
func verifyRules(version int64, signed, sigHex, pubkeyHex string) error {
	if signed == "" {
		return fmt.Errorf("rule set has no signed payload")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		return fmt.Errorf("signature is not valid hex: %w", err)
	}
	pub, err := hex.DecodeString(strings.TrimSpace(pubkeyHex))
	if err != nil {
		return fmt.Errorf("public key is not valid hex: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	payload := []byte(fmt.Sprintf("%s\n%d\n%s", rulesDomain, version, signed))
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return fmt.Errorf("rule set signature does not verify against this public key")
	}
	return nil
}
