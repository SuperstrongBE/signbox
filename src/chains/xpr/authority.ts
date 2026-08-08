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

import { JsonRpc } from "@proton/js";
import { verifiedRpc } from "./rpc.js";
import { authorizesExclusively, normalizePublicKey } from "./keyauth.js";
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
  if (!authorizesExclusively(perm.required_auth, expectedPublicKey)) {
    return { authorized: false, reason: "permission is not an exclusive threshold-1 key for the daemon key" };
  }
  return { authorized: true };
}
