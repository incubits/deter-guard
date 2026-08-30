package main

// What the console learns from a rules pull.
//
// Pulling the compiled rule set is the console's evidence that a guard stood in front of a build —
// nothing else asks for this encoding. Monitor mode pulls it for the identical reason enforce mode
// does, because it makes the identical decision, so the pull on its own cannot tell the two apart
// and the console had been reading every one of them as enforcement. The mode on the query string
// is the whole of the difference. A test that only checked "fetchRules returns a policy" would pass
// just as happily against the build that let a monitoring repository be badged as protected.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rulesServer serves one signed rule set and records the query string it was asked with.
func rulesServer(t *testing.T, seen *string) (*httptest.Server, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const version = int64(4)
	signed := `{"rules":[{"host":"registry.npmjs.org"}],"blocked":[]}`
	sig := ed25519.Sign(priv, []byte(rulesDomain+"\n4\n"+signed))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rulesResponse{
			Version: version,
			Signed:  signed,
			Sig:     hex.EncodeToString(sig),
			Pubkey:  hex.EncodeToString(pub),
		})
	}))
	t.Cleanup(srv.Close)
	return srv, hex.EncodeToString(pub)
}

func TestRulesPullDeclaresItsMode(t *testing.T) {
	for _, tc := range []struct {
		mode Mode
		want string
	}{
		{ModeEnforce, "mode=enforce"},
		{ModeMonitor, "mode=monitor"},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			var seen string
			srv, pub := rulesServer(t, &seen)

			p, _, verified, err := fetchRules(context.Background(), srv.URL, "tok", pub, nil, tc.mode)
			if err != nil {
				t.Fatalf("fetchRules: %v", err)
			}
			// The pull must still work in the ordinary way — a mode parameter that arrived by
			// breaking verification would be a worse bug than the one it fixes.
			if !verified || len(p.Rules) != 1 {
				t.Fatalf("verified=%v rules=%d, want a verified single-rule policy", verified, len(p.Rules))
			}
			if seen != tc.want {
				t.Errorf("console saw query %q, want %q", seen, tc.want)
			}
		})
	}
}

// Enforce is stated, not implied by silence. The console reads an absent parameter as enforcing —
// which is right for guards built before monitor mode existed — so an enforcing guard that sent
// nothing would still be read correctly. It sends it anyway, because otherwise silence means both
// "I enforce" and "I am too old to say", and the case that matters is a monitoring guard in the
// second group.
func TestEnforceIsSentExplicitly(t *testing.T) {
	var seen string
	srv, pub := rulesServer(t, &seen)
	if _, _, _, err := fetchRules(context.Background(), srv.URL, "tok", pub, nil, ModeEnforce); err != nil {
		t.Fatalf("fetchRules: %v", err)
	}
	if seen == "" {
		t.Error("an enforcing pull sent no mode: the console cannot tell it from a guard too old to have one")
	}
}
