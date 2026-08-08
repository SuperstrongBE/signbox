/**
 * Shared XPR key-authority shape check (#39, #41) — the MVP contract for a
 * daemon-controlled permission: an EXCLUSIVE threshold-1 authority holding
 * exactly one key equal to the expected one, with no delegated accounts or
 * waits. Used by both resolveKeyAuthority (runtime) and verifyLanded
 * (onboarding), so "exclusive" means the same thing in both places.
 */

import { Numeric } from "@proton/js";

interface RequiredAuth {
  threshold?: number;
  keys?: { key?: string; weight?: number }[];
  accounts?: unknown[];
  waits?: unknown[];
}

/** Canonical PUB_K1 form, or null if the string is not a parsable public key. */
export function normalizePublicKey(key: string | undefined): string | null {
  if (typeof key !== "string") return null;
  try {
    return Numeric.publicKeyToString(Numeric.stringToPublicKey(key));
  } catch {
    return null;
  }
}

/**
 * True iff `auth` is threshold-1, holds exactly one key (weight ≥ 1) equal to
 * `expectedKey`, and delegates to no accounts or waits. Anything else — extra
 * keys, higher threshold, an account/wait, an unparsable key — is false
 * (never partially accepted).
 */
export function authorizesExclusively(auth: RequiredAuth | undefined, expectedKey: string): boolean {
  if (auth === undefined) return false;
  if (auth.threshold !== 1) return false;
  if ((Array.isArray(auth.accounts) ? auth.accounts.length : 1) !== 0) return false;
  if ((Array.isArray(auth.waits) ? auth.waits.length : 1) !== 0) return false;
  if (!Array.isArray(auth.keys) || auth.keys.length !== 1) return false;
  const only = auth.keys[0]!;
  if (typeof only.weight === "number" && only.weight < 1) return false;
  const expected = normalizePublicKey(expectedKey);
  const onChain = normalizePublicKey(only.key);
  return expected !== null && onChain !== null && onChain === expected;
}
