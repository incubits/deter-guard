// deter-guard — what a CI job runs to get this organization's signed egress policy.
//
// No shebang here: the build adds one to the bundle (`--banner:js`). Keeping it in both places puts
// a second `#!` on line 2 of the output, which is a syntax error.
//
//   deter-guard whoami            what this pipeline authenticates as
//   deter-guard policy            fetch + VERIFY the signed policy, write it to a file
//
// Designed to need nothing but a console URL. On GitHub Actions it mints its own OIDC token, so
// there is no secret in the pipeline to leak; elsewhere DETER_ID_TOKEN or DETER_CI_TOKEN covers it.
//
// Exit codes are distinct on purpose — a pipeline should be able to tell these apart without
// grepping stderr:
//   0  fine
//   1  usage or configuration problem
//   2  the policy did NOT verify        (treat as compromise until proven otherwise)
//   3  authentication or authorization failed (includes being over a plan limit)

import { writeFileSync } from "node:fs";
import { ApiError, exchangeIdToken, fetchPolicy, whoami } from "./api.js";
import { getIdToken, looksLikeCi, OidcError } from "./oidc.js";
import { keyFingerprint, verifyBundle } from "./verify.js";

const EXIT_OK = 0;
const EXIT_USAGE = 1;
const EXIT_UNVERIFIED = 2;
const EXIT_AUTH = 3;

const DEFAULT_AUDIENCE = "deter-console";

function out(msg: string): void {
  process.stdout.write(`${msg}\n`);
}
function err(msg: string): void {
  process.stderr.write(`deter-guard: ${msg}\n`);
}

interface Opts {
  consoleUrl: string;
  audience: string;
  pubkey: string | null;
  outFile: string | null;
  project: string | null;
  run: string | null;
  json: boolean;
}

function usage(): string {
  return `deter-guard — fetch this organization's signed egress policy in CI

Usage:
  deter-guard whoami [options]
  deter-guard policy [options]

Options:
  --console <url>    Console base URL            (env DETER_CONSOLE_URL)
  --pubkey <hex>     PIN the signing key         (env DETER_POLICY_PUBKEY)
  --out <path>       Write the policy here       (default: stdout)
  --audience <aud>   OIDC audience               (env DETER_CI_OIDC_AUDIENCE, default ${DEFAULT_AUDIENCE})
  --project <ref>    Project id for a dtrc_ token (env DETER_PROJECT)
  --run <ref>        Run id, deduplicates usage  (env DETER_RUN_ID)
  --json             Machine-readable output
  -h, --help         This

Credentials, in the order tried:
  1. DETER_ID_TOKEN         an OIDC ID token you pass in (GitLab and friends)
  2. GitHub Actions OIDC    automatic, needs \`permissions: id-token: write\`
  3. DETER_CI_TOKEN         a long-lived dtrc_ token from the console

Exit codes: 0 ok · 1 usage · 2 policy did NOT verify · 3 auth failed`;
}

function parse(argv: string[]): { cmd: string; opts: Opts } {
  const env = process.env;
  const opts: Opts = {
    consoleUrl: env.DETER_CONSOLE_URL ?? "",
    audience: env.DETER_CI_OIDC_AUDIENCE ?? DEFAULT_AUDIENCE,
    pubkey: env.DETER_POLICY_PUBKEY ?? null,
    outFile: null,
    project: env.DETER_PROJECT ?? null,
    run: env.DETER_RUN_ID ?? null,
    json: false,
  };
  let cmd = "";
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => argv[++i] ?? "";
    if (a === "-h" || a === "--help") return { cmd: "help", opts };
    else if (a === "--console") opts.consoleUrl = next();
    else if (a === "--pubkey") opts.pubkey = next();
    else if (a === "--out") opts.outFile = next();
    else if (a === "--audience") opts.audience = next();
    else if (a === "--project") opts.project = next();
    else if (a === "--run") opts.run = next();
    else if (a === "--json") opts.json = true;
    else if (a.startsWith("-")) throw new Error(`unknown option ${a}`);
    else if (!cmd) cmd = a;
    else throw new Error(`unexpected argument ${a}`);
  }
  return { cmd, opts };
}

/**
 * Resolve a bearer token for the CI API.
 *
 * Prefers the OIDC exchange, because it leaves nothing long-lived in the pipeline. A `dtrc_` token is
 * the fallback for platforms that can't issue an ID token.
 */
async function authenticate(opts: Opts): Promise<{ token: string; how: string; pubkey: string | null }> {
  const ciToken = (process.env.DETER_CI_TOKEN ?? "").trim();
  try {
    const id = await getIdToken(opts.audience);
    const session = await exchangeIdToken(opts.consoleUrl, id.token);
    return {
      token: session.token,
      how: `OIDC (${id.source}) → ${session.project.path ?? session.project.ref}`,
      pubkey: session.pubkey,
    };
  } catch (e) {
    // Only fall back to the long-lived token if there was no usable OIDC identity at all. If the
    // exchange itself was REJECTED, falling back would mask a real misconfiguration (wrong audience,
    // owner not claimed) behind a different credential.
    if (e instanceof OidcError && ciToken) {
      return { token: ciToken, how: "DETER_CI_TOKEN", pubkey: null };
    }
    throw e;
  }
}

async function main(): Promise<number> {
  let cmd: string;
  let opts: Opts;
  try {
    ({ cmd, opts } = parse(process.argv.slice(2)));
  } catch (e) {
    err((e as Error).message);
    out(usage());
    return EXIT_USAGE;
  }

  if (!cmd || cmd === "help") {
    out(usage());
    return cmd === "help" ? EXIT_OK : EXIT_USAGE;
  }
  if (cmd !== "whoami" && cmd !== "policy") {
    err(`unknown command "${cmd}"`);
    return EXIT_USAGE;
  }
  if (!opts.consoleUrl) {
    err("no console URL — pass --console or set DETER_CONSOLE_URL");
    return EXIT_USAGE;
  }

  let auth;
  try {
    auth = await authenticate(opts);
  } catch (e) {
    if (e instanceof OidcError) {
      err(e.message);
      if (!looksLikeCi()) err("(this doesn't look like a CI runner — is that intended?)");
      return EXIT_AUTH;
    }
    const status = e instanceof ApiError ? e.status : undefined;
    err(`authentication failed${status ? ` (HTTP ${status})` : ""}: ${(e as Error).message}`);
    return EXIT_AUTH;
  }

  // A dtrc_ token's project identity comes from a header, so both commands have to send it —
  // otherwise `whoami` reports the token's fallback identity and disagrees with what `policy`
  // attributes the run to.
  const ciHeaders: Record<string, string> = {};
  if (opts.project) ciHeaders["x-deter-project"] = opts.project;
  if (opts.run) ciHeaders["x-deter-run"] = opts.run;

  if (cmd === "whoami") {
    try {
      const me = await whoami(opts.consoleUrl, auth.token, ciHeaders);
      if (opts.json) out(JSON.stringify(me, null, 2));
      else {
        out(`authenticated via ${auth.how}`);
        out(`  organization  ${me.organization_id}`);
        out(`  project       ${me.project_path ?? me.project_ref} (${me.provider})`);
        out(`  attested      ${me.attested ? "yes" : "no — identity is self-reported"}`);
      }
      return EXIT_OK;
    } catch (e) {
      err(`${(e as Error).message}`);
      return e instanceof ApiError && e.status && e.status < 500 ? EXIT_AUTH : EXIT_USAGE;
    }
  }

  // ---- policy -------------------------------------------------------------------------------
  let fetched;
  try {
    // Only meaningful for a dtrc_ token: an OIDC session already carries an attested identity.
    fetched = await fetchPolicy(opts.consoleUrl, auth.token, ciHeaders);
  } catch (e) {
    const status = e instanceof ApiError ? e.status : undefined;
    err(`could not fetch the policy${status ? ` (HTTP ${status})` : ""}: ${(e as Error).message}`);
    return status && status >= 400 && status < 500 ? EXIT_AUTH : EXIT_USAGE;
  }

  // The key we verify against decides what "verified" is worth. A pinned key proves the policy came
  // from the holder of the fleet's private key. The key the SERVER hands us proves only that the
  // bundle is internally consistent — anything that can serve the bundle can serve a matching key.
  // Both are supported; only one of them is a security claim, and the guard says which.
  const pinned = opts.pubkey?.trim() || null;
  const key = pinned ?? auth.pubkey ?? fetched.servedPubkey;
  if (!key) {
    err("no public key to verify against — pass --pubkey or set DETER_POLICY_PUBKEY");
    return EXIT_USAGE;
  }

  const verdict = verifyBundle(fetched.bundle, key);
  if (!verdict.ok) {
    err(`POLICY DID NOT VERIFY: ${verdict.reason}`);
    err(`key ${keyFingerprint(key)} · version ${fetched.bundle.version}`);
    err("refusing to write it. Treat this as a compromised distribution path until proven otherwise.");
    return EXIT_UNVERIFIED;
  }

  if (opts.outFile) writeFileSync(opts.outFile, `${fetched.bundle.policy}\n`);

  if (opts.json) {
    out(
      JSON.stringify(
        {
          ok: true,
          version: fetched.bundle.version,
          bytes: Buffer.byteLength(fetched.bundle.policy, "utf8"),
          key: keyFingerprint(key),
          pinned: Boolean(pinned),
          written: opts.outFile,
        },
        null,
        2,
      ),
    );
  } else {
    out(`policy verified · version ${fetched.bundle.version} · key ${keyFingerprint(key)}`);
    if (!pinned) {
      err(
        "key was NOT pinned — this proves the bundle is self-consistent, not that it came from you. " +
          "Set DETER_POLICY_PUBKEY to make this a real check.",
      );
    }
    if (opts.outFile) out(`written to ${opts.outFile}`);
    else out(fetched.bundle.policy);
  }
  return EXIT_OK;
}

main().then(
  (code) => process.exit(code),
  (e: unknown) => {
    err(`unexpected: ${(e as Error).stack ?? String(e)}`);
    process.exit(EXIT_USAGE);
  },
);
