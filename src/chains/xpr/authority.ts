/**
 * XPR on-chain key-authority resolution (#39) — the Antelope authority model
 * behind ChainModule.resolveKeyAuthority.
 *
 * MVP contract (issue #39): the daemon signs under a DEDICATED permission whose
 * `required_auth` is threshold 1, exactly one key of weight ≥ threshold equal
 * to the daemon's key, and NO delegated accounts or waits. Full recursive /
 * multi-key / threshold authority resolution is explicitly out of scope —
 * anything that isn't this simple shape is refused, never approximated.
 *
 * Both the on-chain key and the expected key are normalized through
 * @proton/js Numeric so that legacy "EOS…" and modern "PUB_K1_…" encodings of
 * the same key compare equal.
 */

import { JsonRpc, Numeric } from "@proton/js";
import { verifiedRpc } from "./rpc.js";
import type { ChainWiring, KeyAuthorityResult } from "../registry.js";

interface AntelopeKeyWeight {
  key: string;
  weight: number;
}
interface AntelopeAuthority {
  threshold: number;
  keys: AntelopeKeyWeight[];
  accounts: unknown[];
  waits: unknown[];
}
interface AntelopePermission {
  perm_name: string;
  required_auth: AntelopeAuthority;
}

/** Canonical PUB_K1 form, or null if the string is not a parsable public key. */
function normalizePublicKey(key: string): string | null {
  try {
    return Numeric.publicKeyToString(Numeric.stringToPublicKey(key));
  } catch {
    return null;
  }
}

export async function resolveXprKeyAuthority(
  wiring: ChainWiring,
  account: string,
  permission: string,
  expectedPublicKey: string,
): Promise<KeyAuthorityResult> {
  const expected = normalizePublicKey(expectedPublicKey);
  if (expected === null) {
    return { authorized: false, reason: "declared public key is not a valid K1 key" };
  }

  const rpc = verifiedRpc(new JsonRpc(wiring.endpoints), { chainId: wiring.chainId });
  const info = (await rpc.get_account(account)) as { permissions?: AntelopePermission[] };
  const perm = info.permissions?.find((p) => p.perm_name === permission);
  if (perm === undefined) {
    return { authorized: false, reason: `permission "${permission}" not found on account` };
  }

  const auth = perm.required_auth;
  if (auth.threshold !== 1) {
    return { authorized: false, reason: "permission is not threshold-1" };
  }
  if ((auth.accounts?.length ?? 0) !== 0 || (auth.waits?.length ?? 0) !== 0) {
    return { authorized: false, reason: "permission delegates to accounts or waits" };
  }
  if (!Array.isArray(auth.keys) || auth.keys.length !== 1) {
    return { authorized: false, reason: "permission does not hold exactly one key" };
  }
  const only = auth.keys[0]!;
  if (only.weight < auth.threshold) {
    return { authorized: false, reason: "key weight is below the threshold" };
  }
  const onChain = normalizePublicKey(only.key);
  if (onChain === null || onChain !== expected) {
    return { authorized: false, reason: "on-chain key does not match the daemon key" };
  }
  return { authorized: true };
}
