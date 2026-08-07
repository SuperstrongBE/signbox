/**
 * Identity binding gate (#39) — makes the daemon's signing identity a
 * non-configurable invariant. A permissive or malformed policy can never turn
 * the daemon into a confused deputy: BEFORE policy evaluation, quota
 * reservation, or signing, every action must satisfy, for the bound agent:
 *
 *  1. exactly one authorization;
 *  2. its actor equals the agent (and thus the on-chain policy agent, which
 *     the policy row is keyed by);
 *  3. its permission equals the CURRENT on-chain agent permission;
 *  4. the daemon's signing key is authorized by that on-chain (account,
 *     permission) authority — a dedicated threshold-1 single-key permission
 *     (resolved + cached by the caller, fail closed).
 *
 * The private-key↔declared-public-key check (a local, request-invariant fact)
 * is enforced once at daemon startup via keystore.verifyKeyBinding, not here.
 *
 * A mismatch returns AUTHORIZATION_MISMATCH — one stable code that does not
 * reveal WHICH check failed (no oracle). The signer repeats (2) and (3) as
 * defense in depth.
 */

import type { DecodedTransaction, KeyHandle } from "../core/types.js";

export interface IdentityInputs {
  /** The agent the daemon holds a key for. */
  agent: string;
  /** The authoritative on-chain permission (policy-cache `agentperm`). */
  onChainPermission: string;
  /** The daemon's key handle (its public key is the one that must be authorized). */
  key: KeyHandle;
}

/** Verifies the CHAIN-INDEPENDENT part of the binding (points 1–3). */
export function checkLocalIdentity(tx: DecodedTransaction, id: IdentityInputs): boolean {
  for (const action of tx.actions) {
    if (action.authorization.length !== 1) return false;
    const auth = action.authorization[0]!;
    if (auth.accountIdentifier !== id.agent) return false;
    if (auth.permission !== id.onChainPermission) return false;
  }
  return true;
}
