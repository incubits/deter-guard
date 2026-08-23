package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// apiError carries the console's own message and status. The message is written for a human staring
// at a red pipeline, and it distinguishes "over your plan" from "your credential is wrong", so it's
// passed through rather than replaced.
type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return e.Msg }

type ciSession struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"`
	Project   struct {
		Provider string `json:"provider"`
		Ref      string `json:"ref"`
		Path     string `json:"path"`
	} `json:"project"`
	// The console's signing key AS IT REPORTS IT. Only a security claim if independently pinned.
	Pubkey string `json:"pubkey"`
}

type whoAmI struct {
	OrganizationID string `json:"organization_id"`
	Provider       string `json:"provider"`
	ProjectRef     string `json:"project_ref"`
	ProjectPath    string `json:"project_path"`
	Attested       bool   `json:"attested"`
	RunRef         string `json:"run_ref"`
}

type policyResponse struct {
	Version int64  `json:"version"`
	Policy  string `json:"policy"`
	Sig     string `json:"sig"`
	Pubkey  string `json:"pubkey"`
}

func baseURL(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

// call performs one request and decodes into out. Headers are MERGED, not replaced — dropping the
// caller's x-deter-* headers silently un-attributes a run from its project.
func call(ctx context.Context, method, url, token string, body any, headers map[string]string, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", url, err)
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Meter   string `json:"meter"`
		}
		_ = json.Unmarshal(raw, &e)
		detail := e.Error
		if detail == "" {
			detail = e.Message
		}
		if detail == "" {
			detail = strings.TrimSpace(string(raw))
			if len(detail) > 300 {
				detail = detail[:300]
			}
		}
		if detail == "" {
			detail = res.Status
		}
		if e.Meter != "" {
			detail += " [meter: " + e.Meter + "]"
		}
		return &apiError{Status: res.StatusCode, Msg: detail}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// exchangeIDToken trades a platform-signed OIDC ID token for a short-lived CI session.
func exchangeIDToken(ctx context.Context, consoleURL, tok string) (ciSession, error) {
	var s ciSession
	err := call(ctx, http.MethodPost, baseURL(consoleURL)+"/api/ci/token", "",
		map[string]string{"id_token": tok}, nil, &s)
	return s, err
}

func fetchWhoAmI(ctx context.Context, consoleURL, token string, headers map[string]string) (whoAmI, error) {
	var w whoAmI
	err := call(ctx, http.MethodGet, baseURL(consoleURL)+"/api/ci/whoami", token, nil, headers, &w)
	return w, err
}

// fetchPolicy returns the bundle AND the key the server claims signed it, kept separate so the
// caller decides which to trust. Conflating them is how a "verified" badge ends up meaning nothing.
func fetchPolicy(ctx context.Context, consoleURL, token string, headers map[string]string) (SignedBundle, string, error) {
	var p policyResponse
	if err := call(ctx, http.MethodGet, baseURL(consoleURL)+"/api/ci/policy", token, nil, headers, &p); err != nil {
		return SignedBundle{}, "", err
	}
	return SignedBundle{Version: p.Version, Policy: p.Policy, Sig: p.Sig}, p.Pubkey, nil
}
