package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// oidcError means "no usable CI identity", as distinct from "the console rejected the one we had".
// The difference decides whether falling back to a long-lived token is honest or is hiding a
// misconfiguration, so it gets its own type.
type oidcError struct{ msg string }

func (e *oidcError) Error() string { return e.msg }

func isOidcError(err error) bool {
	var e *oidcError
	return errors.As(err, &e)
}

type tokenSource string

const (
	srcGitHub   tokenSource = "github"
	srcExplicit tokenSource = "explicit"
)

type idToken struct {
	token  string
	source tokenSource
}

// fromGitHub exchanges the runner's request token for an ID token.
//
// Requires `permissions: id-token: write`. Without it GitHub doesn't set these variables at all,
// which is the single most common setup mistake — hence saying so explicitly.
func fromGitHub(ctx context.Context, audience, reqURL, reqToken string) (string, error) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", &oidcError{fmt.Sprintf("ACTIONS_ID_TOKEN_REQUEST_URL is not a URL: %v", err)}
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+reqToken)
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("asking GitHub for an ID token: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", &oidcError{fmt.Sprintf(
			"GitHub refused to mint an ID token (HTTP %d). Check that the job has `permissions: id-token: write`.",
			res.StatusCode)}
	}
	var body struct{ Value string }
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil || body.Value == "" {
		return "", &oidcError{"GitHub returned no ID token value"}
	}
	return body.Value, nil
}

// getIDToken resolves an ID token from whichever runner we're on.
//
// DETER_ID_TOKEN comes first so it can override detection — that's the escape hatch for GitLab,
// which requires the job to DECLARE its id_tokens block and hand the value over by name, and for any
// platform not detected here.
func getIDToken(ctx context.Context, audience string, env func(string) string) (idToken, error) {
	if t := strings.TrimSpace(env("DETER_ID_TOKEN")); t != "" {
		return idToken{t, srcExplicit}, nil
	}

	reqURL, reqTok := env("ACTIONS_ID_TOKEN_REQUEST_URL"), env("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL != "" && reqTok != "" {
		t, err := fromGitHub(ctx, audience, reqURL, reqTok)
		if err != nil {
			return idToken{}, err
		}
		return idToken{t, srcGitHub}, nil
	}

	// GitLab exposes the token under whatever name the job declared, so it can't be discovered.
	// Give the exact snippet rather than a description of it.
	if env("GITLAB_CI") != "" {
		return idToken{}, &oidcError{fmt.Sprintf(
			"On GitLab, declare an ID token and pass it through as DETER_ID_TOKEN:\n"+
				"  id_tokens:\n"+
				"    DETER_ID_TOKEN: { aud: %q }", audience)}
	}

	return idToken{}, &oidcError{
		"No CI identity found. On GitHub Actions add `permissions: id-token: write`; " +
			"elsewhere set DETER_ID_TOKEN to an OIDC ID token, or DETER_CI_TOKEN to a long-lived " +
			"token from the console."}
}

// looksLikeCI is used only to tailor an error message — never to gate behaviour.
func looksLikeCI(env func(string) string) bool {
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL"} {
		if env(k) != "" {
			return true
		}
	}
	return false
}

// osEnv is the real environment; tests pass their own lookup instead.
func osEnv(k string) string { return os.Getenv(k) }

// httpTimeout bounds every call. A pipeline hanging on a network read is worse than one that fails.
const httpTimeout = 15 * time.Second
