// Obtain the CI platform's OIDC ID token, so the guard needs no stored secret.
//
// Each platform hands it over differently, and the whole point is that an SRE shouldn't have to know
// which: the guard detects the runner it's on. What it must NEVER do is guess silently — if no
// platform is detected, say which environment variables were expected, because "auth failed" with no
// explanation is the worst possible error in a pipeline.

/** Where the token came from, for diagnostics. */
export type TokenSource = "github" | "gitlab" | "explicit";

export interface IdToken {
  token: string;
  source: TokenSource;
}

export class OidcError extends Error {}

const TIMEOUT_MS = 10_000;

/**
 * GitHub Actions: exchange the runner's request token for an ID token.
 *
 * Requires `permissions: id-token: write` in the workflow. Without it GitHub doesn't set these
 * variables at all, which is the single most common setup mistake — hence the explicit message.
 */
async function fromGitHub(audience: string, env: NodeJS.ProcessEnv): Promise<string> {
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL!;
  const runnerToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN!;
  const res = await fetch(`${url}&audience=${encodeURIComponent(audience)}`, {
    headers: { authorization: `bearer ${runnerToken}`, accept: "application/json" },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new OidcError(
      `GitHub refused to mint an ID token (HTTP ${res.status}). Check that the job has ` +
        "`permissions: id-token: write`.",
    );
  }
  const body = (await res.json()) as { value?: unknown };
  if (typeof body.value !== "string" || !body.value) {
    throw new OidcError("GitHub returned no ID token value");
  }
  return body.value;
}

/**
 * Resolve an ID token from whichever runner we're on.
 *
 * `explicit` (DETER_ID_TOKEN) comes first so it can override detection — that's the escape hatch for
 * GitLab, which requires the job to DECLARE its id_tokens block and hand the value over by name, and
 * for any platform we don't detect yet.
 */
export async function getIdToken(
  audience: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<IdToken> {
  const explicit = (env.DETER_ID_TOKEN ?? "").trim();
  if (explicit) return { token: explicit, source: "explicit" };

  if (env.ACTIONS_ID_TOKEN_REQUEST_URL && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) {
    return { token: await fromGitHub(audience, env), source: "github" };
  }

  // GitLab exposes the token under whatever name the job declared, so we can't discover it. Give the
  // exact snippet rather than a description of it.
  if (env.GITLAB_CI) {
    throw new OidcError(
      "On GitLab, declare an ID token and pass it through as DETER_ID_TOKEN:\n" +
        "  id_tokens:\n" +
        `    DETER_ID_TOKEN: { aud: "${audience}" }`,
    );
  }

  throw new OidcError(
    "No CI identity found. On GitHub Actions add `permissions: id-token: write`; " +
      "elsewhere set DETER_ID_TOKEN to an OIDC ID token, or DETER_CI_TOKEN to a long-lived token " +
      "from the console.",
  );
}

/** True when this looks like a CI runner at all — used only to tailor the error message. */
export function looksLikeCi(env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(env.CI || env.GITHUB_ACTIONS || env.GITLAB_CI || env.BUILDKITE || env.JENKINS_URL);
}
