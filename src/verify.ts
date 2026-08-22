// ed25519 verification of a signed policy bundle.
//
// Deliberately a standalone copy of the verifier rather than an import from @deter/server: the guard
// ships as a tiny standalone image and must not drag the console's Fastify/Postgres dependency tree
// into a CI runner. The SIGNED PAYLOAD FORMAT is the contract both sides implement —
// `version + "\n" + policy` — and the test pins it against a vector produced by the server's signer,
// so a divergence fails loudly here rather than silently accepting an unverified policy.

import { ed25519 } from "@noble/curves/ed25519";

export interface SignedBundle {
  version: number;
  policy: string;
  sig: string;
}

/** The exact bytes covered by the signature. MUST match the console's signer. */
export function signedPayload(version: number, policy: string): Uint8Array {
  return new TextEncoder().encode(`${version}\n${policy}`);
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("not valid hex");
  }
  return new Uint8Array(Buffer.from(clean, "hex"));
}

export type Verdict = { ok: true } | { ok: false; reason: string };

/**
 * Verify a bundle against a public key (hex).
 *
 * Returns a verdict rather than throwing, and NEVER throws on malformed input: a corrupt signature
 * has to read as "not verified", not as a crash the caller might mistake for something else.
 */
export function verifyBundle(bundle: SignedBundle, pubkeyHex: string): Verdict {
  if (typeof bundle?.policy !== "string") return { ok: false, reason: "bundle has no policy" };
  if (!Number.isInteger(bundle.version)) return { ok: false, reason: "bundle has no integer version" };
  if (typeof bundle.sig !== "string") return { ok: false, reason: "bundle has no signature" };

  let sig: Uint8Array;
  let pub: Uint8Array;
  try {
    sig = hexToBytes(bundle.sig);
    pub = hexToBytes(pubkeyHex);
  } catch {
    return { ok: false, reason: "signature or public key is not valid hex" };
  }
  if (sig.length !== 64) return { ok: false, reason: `signature must be 64 bytes, got ${sig.length}` };
  if (pub.length !== 32) return { ok: false, reason: `public key must be 32 bytes, got ${pub.length}` };

  try {
    return ed25519.verify(sig, signedPayload(bundle.version, bundle.policy), pub)
      ? { ok: true }
      : { ok: false, reason: "signature does not verify against this public key" };
  } catch (e) {
    return { ok: false, reason: `verification failed: ${(e as Error).message}` };
  }
}

/** Short form of a key, for logs. Never print a whole key: it invites copy-pasting the wrong one. */
export function keyFingerprint(pubkeyHex: string): string {
  const k = pubkeyHex.trim();
  return k.length > 16 ? `${k.slice(0, 8)}…${k.slice(-8)}` : k;
}
