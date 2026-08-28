package main

import "strings"

import "testing"

// A claim exists to establish who owns an organization. The only credential that can settle that is
// one the PLATFORM signed — a dtrc_ token is a string somebody pasted into a CI variable, so
// honouring it here would let anyone holding one claim an organization they do not own.
func TestClaimRefusesASelfReportedIdentity(t *testing.T) {
	out, code := claimReport(whoAmI{
		OrganizationID: "org_1",
		Provider:       "github",
		ProjectPath:    "incubits/deter-console",
		Attested:       false,
	}, "DETER_CI_TOKEN")

	if code != exitAuth {
		t.Fatalf("an unattested identity must not settle a claim: got exit %d, want %d", code, exitAuth)
	}
	// The failure has to name the fix, because the admin reading it is mid-wizard and the console
	// cannot tell them — it only ever sees a claim that stayed pending.
	if !strings.Contains(strings.Join(out, " "), "id-token: write") {
		t.Errorf("refusal should say how to get an attested token, got:\n%s", strings.Join(out, "\n"))
	}
}

func TestClaimAcceptsAnAttestedIdentityAndSaysWhichOrganization(t *testing.T) {
	out, code := claimReport(whoAmI{
		OrganizationID: "org_1",
		Provider:       "github",
		ProjectPath:    "incubits/deter-console",
		Attested:       true,
	}, "GitHub Actions OIDC")

	if code != exitOK {
		t.Fatalf("an attested identity must settle a claim: got exit %d", code)
	}
	joined := strings.Join(out, "\n")
	for _, want := range []string{"org_1", "incubits/deter-console", "github"} {
		if !strings.Contains(joined, want) {
			t.Errorf("claim output should name %q, got:\n%s", want, joined)
		}
	}
	// This workflow stays in the repository and runs on every push. Wording that only makes sense
	// the very first time turns into a lie on the second, so the success line must not claim the
	// claim just happened.
	if strings.Contains(strings.ToLower(joined), "claimed") {
		t.Errorf("success wording must read correctly on re-runs too, got:\n%s", joined)
	}
}

// Not every provider gives a path; falling back to the ref keeps the line informative instead of
// printing a blank where the project should be.
func TestClaimFallsBackToTheProjectRefWhenThereIsNoPath(t *testing.T) {
	out, _ := claimReport(whoAmI{
		OrganizationID: "org_1",
		Provider:       "gitlab",
		ProjectRef:     "4815162342",
		Attested:       true,
	}, "DETER_ID_TOKEN")

	if !strings.Contains(strings.Join(out, "\n"), "4815162342") {
		t.Errorf("expected the project ref as a fallback, got:\n%s", strings.Join(out, "\n"))
	}
}
