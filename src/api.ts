// The console's CI API, as the guard sees it.
//
// Two ways in, and the guard prefers the first:
//   OIDC exchange  — POST /api/ci/token with a platform-signed ID token → a 10-minute credential.
//                    Nothing long-lived is stored in the pipeline.
//   CI token       — a `dtrc_` value in DETER_CI_TOKEN, for platforms that can't issue an ID token.

import type { SignedBundle } from "./verify.js";

const TIMEOUT_MS = 15_000;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

export interface CiSession {
  token: string;
  expiresIn: number;
  project: { provider: string; ref: string; path: string | null };
  /** The console's signing key, as IT reports it. Only trustworthy if independently pinned. */
  pubkey: string | null;
}

export interface WhoAmI {
  organization_id: string;
  provider: string;
  project_ref: string;
  project_path: string | null;
  attested: boolean;
  run_ref: string | null;
}

function base(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

async function request<T>(
  url: string,
  init: RequestInit & { token?: string },
): Promise<T> {
  // Pull the caller's headers OUT of the rest, then merge. Spreading `...rest` and a fresh `headers`
  // into the same object would let one replace the other wholesale — which silently dropped the
  // x-deter-project / x-deter-run headers, so a token's run never got attributed to its project.
  const { token, headers: extra, ...rest } = init;
  const headers: Record<string, string> = {
    ...(extra as Record<string, string> | undefined),
    accept: "application/json",
  };
  if (token) headers.authorization = `Bearer ${token}`;
  if (rest.body) headers["content-type"] = "application/json";

  let res: Response;
  try {
    res = await fetch(url, { ...rest, headers, signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (e) {
    throw new ApiError(`could not reach ${url}: ${(e as Error).message}`);
  }

  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* keep the raw text for the error below */
  }

  if (!res.ok) {
    const b = body as { error?: string; message?: string; meter?: string } | null;
    // Surface the console's own message: it's written for a human staring at a red pipeline, and it
    // distinguishes "you're over your plan" from "your credential is wrong".
    const detail = b?.error ?? b?.message ?? text.slice(0, 300) ?? "";
    const meter = b?.meter ? ` [meter: ${b.meter}]` : "";
    throw new ApiError(`${detail || res.statusText}${meter}`, res.status);
  }
  return body as T;
}

/** Exchange a platform OIDC ID token for a short-lived CI session. */
export async function exchangeIdToken(consoleUrl: string, idToken: string): Promise<CiSession> {
  const body = await request<{
    ok: boolean;
    token: string;
    expires_in: number;
    project: { provider: string; ref: string; path: string | null };
    pubkey: string | null;
  }>(`${base(consoleUrl)}/api/ci/token`, {
    method: "POST",
    body: JSON.stringify({ id_token: idToken }),
  });
  return {
    token: body.token,
    expiresIn: body.expires_in,
    project: body.project,
    pubkey: body.pubkey,
  };
}

export async function whoami(
  consoleUrl: string,
  token: string,
  headers?: Record<string, string>,
): Promise<WhoAmI> {
  return request<WhoAmI>(`${base(consoleUrl)}/api/ci/whoami`, {
    token,
    headers,
  } as RequestInit & { token: string });
}

/**
 * Fetch the organization's signed egress policy.
 *
 * Returns the bundle AND the key the server claims signed it — kept separate so the caller can
 * decide whether to trust that key or a pinned one. Conflating them is how a "verified" badge ends
 * up meaning nothing.
 */
export async function fetchPolicy(
  consoleUrl: string,
  token: string,
  headers?: Record<string, string>,
): Promise<{ bundle: SignedBundle; servedPubkey: string | null }> {
  const body = await request<{
    version: number;
    policy: string;
    sig: string;
    pubkey: string | null;
  }>(`${base(consoleUrl)}/api/ci/policy`, { token, headers } as RequestInit & { token: string });
  return {
    bundle: { version: body.version, policy: body.policy, sig: body.sig },
    servedPubkey: body.pubkey,
  };
}
