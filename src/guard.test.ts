// Unit tests for the guard's two load-bearing pure parts: signature verification (what "verified"
// actually means) and OIDC token discovery (the thing that decides whether a pipeline needs a
// stored secret at all).

import assert from "node:assert/strict";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519";
import { getIdToken, looksLikeCi, OidcError } from "./oidc.js";
import { keyFingerprint, signedPayload, verifyBundle } from "./verify.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function sign(version: number, policy: string) {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const sig = ed25519.sign(signedPayload(version, policy), priv);
  return { bundle: { version, policy, sig: hex(sig) }, pubkey: hex(pub) };
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------

test("the signed payload is exactly `version\\npolicy` — the contract with the console", () => {
  // If this ever changes on one side only, the guard silently rejects every real policy (or worse,
  // accepts a forged one). Pinned here so a divergence is a failing test, not a production mystery.
  assert.equal(
    new TextDecoder().decode(signedPayload(42, "permit(principal, action, resource);")),
    "42\npermit(principal, action, resource);",
  );
});

test("accepts a real signature from the console's signer", () => {
  // Vector produced by @deter/server's signBundle with a fixed 32-byte key (all 0x42) — the same
  // one the broker's Rust verifier is pinned against. Three independent implementations, one
  // signature.
  const pubkey = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";
  const policy =
    'permit(principal == Deter::"sandbox", action == Action::"connect", resource == Net::"egress") when { context.host == "api.anthropic.com" };\n';
  const sig =
    "a5679c310de8a984445c45c5d3fd9cdc9b85068d8eace3cf99e08dd695c69723cf4c0237d964f0e17d94c1d7104d06f3b15d425c70a20beed2b4ebcf95125c0c";
  assert.deepEqual(verifyBundle({ version: 100, policy, sig }, pubkey), { ok: true });
});

test("rejects a tampered policy, version, or signature", () => {
  const { bundle, pubkey } = sign(7, 'permit(principal, action, resource) when { context.host == "ok.com" };');
  assert.ok(verifyBundle(bundle, pubkey).ok);

  // The version is INSIDE the signature, so a rollback attack changes the payload.
  assert.equal(verifyBundle({ ...bundle, version: 6 }, pubkey).ok, false);

  // Widening the policy under the original signature must fail — this is the whole point.
  const widened = bundle.policy.replace("ok.com", "evil.com");
  assert.equal(verifyBundle({ ...bundle, policy: widened }, pubkey).ok, false);

  // A different key doesn't verify.
  const other = sign(7, "x");
  assert.equal(verifyBundle(bundle, other.pubkey).ok, false);
});

test("malformed input is a verdict, never a throw", () => {
  const { bundle, pubkey } = sign(1, "p");
  for (const [b, k, why] of [
    [{ ...bundle, sig: "nothex" }, pubkey, "non-hex signature"],
    [{ ...bundle, sig: "abcd" }, pubkey, "short signature"],
    [bundle, "abcd", "short key"],
    [bundle, "zz".repeat(32), "non-hex key"],
    [{ version: 1, policy: "p" } as never, pubkey, "missing signature"],
    [{ version: "1", policy: "p", sig: bundle.sig } as never, pubkey, "non-integer version"],
  ] as const) {
    const v = verifyBundle(b, k);
    assert.equal(v.ok, false, `expected a failed verdict for ${why}`);
    assert.ok(v.ok === false && v.reason, `${why} should explain itself`);
  }
});

test("a key fingerprint is short and doesn't leak the whole key into logs", () => {
  const key = "a".repeat(32) + "b".repeat(32);
  const fp = keyFingerprint(key);
  assert.ok(fp.length < 20);
  assert.notEqual(fp, key);
  assert.equal(keyFingerprint("short"), "short");
});

// ---------------------------------------------------------------------------------------------
// Credential discovery
// ---------------------------------------------------------------------------------------------

test("an explicitly supplied ID token wins, so any platform can opt in", async () => {
  const t = await getIdToken("deter-console", { DETER_ID_TOKEN: "  tok  " } as NodeJS.ProcessEnv);
  assert.deepEqual(t, { token: "tok", source: "explicit" });
});

test("GitLab gets the exact snippet it needs, not a description of it", async () => {
  await assert.rejects(
    () => getIdToken("deter-console", { GITLAB_CI: "true" } as NodeJS.ProcessEnv),
    (e: Error) => {
      assert.ok(e instanceof OidcError);
      // The failure has to be actionable: GitLab can't be auto-detected because the job must name
      // the token, so the message carries the YAML.
      assert.match(e.message, /id_tokens:/);
      assert.match(e.message, /DETER_ID_TOKEN/);
      assert.match(e.message, /deter-console/);
      return true;
    },
  );
});

test("with no identity at all, the error names every way to provide one", async () => {
  await assert.rejects(
    () => getIdToken("deter-console", {} as NodeJS.ProcessEnv),
    (e: Error) => {
      assert.match(e.message, /id-token: write/);
      assert.match(e.message, /DETER_ID_TOKEN/);
      assert.match(e.message, /DETER_CI_TOKEN/);
      return true;
    },
  );
});

test("CI detection covers the platforms we tailor messages for", () => {
  assert.ok(looksLikeCi({ GITHUB_ACTIONS: "true" } as NodeJS.ProcessEnv));
  assert.ok(looksLikeCi({ GITLAB_CI: "true" } as NodeJS.ProcessEnv));
  assert.ok(looksLikeCi({ JENKINS_URL: "http://x" } as NodeJS.ProcessEnv));
  assert.ok(looksLikeCi({ CI: "1" } as NodeJS.ProcessEnv));
  assert.ok(!looksLikeCi({} as NodeJS.ProcessEnv));
});
