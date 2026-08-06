/**
 * Integrity gate for an on-chain policy row (spec §8.6).
 *
 * The stored bytes must:
 *  1. hash (sha256) to the stored policyhash — the same invariant the contract
 *     enforces on-chain;
 *  2. BE the canonical JCS form, not merely hash to it;
 *  3. satisfy the policy schema.
 *
 * This is the SINGLE gate both the daemon's anti-rollback cache (PolicyCache)
 * and the CLI's `transaction explain` apply before trusting a policy, so a
 * dry-run can never disagree with what the daemon would actually enforce.
 */

import { createHash } from "node:crypto";
import { canonicalize } from "../canonical/jcs.js";
import { validatePolicy, type Policy } from "./schema.js";
import type { PolicyDialect } from "./dialect.js";

export type PolicyIntegrityError =
  | "hash_mismatch"
  | "invalid_json"
  | "not_canonical"
  | "schema_invalid";

export type PolicyIntegrityResult =
  | { ok: true; policy: Policy }
  | { ok: false; reason: PolicyIntegrityError };

/**
 * Verify a stored policy's bytes against its hash and the canonical JCS form,
 * then validate the schema. Returns the parsed policy on success, or a
 * structured reason the caller maps to its own failure mode.
 */
export function verifyStoredPolicy(
  policyjson: string,
  policyhash: string,
  dialect: PolicyDialect,
): PolicyIntegrityResult {
  const computed = createHash("sha256").update(Buffer.from(policyjson, "utf8")).digest("hex");
  if (computed !== policyhash.toLowerCase()) return { ok: false, reason: "hash_mismatch" };

  let parsed: unknown;
  try {
    parsed = JSON.parse(policyjson);
  } catch {
    return { ok: false, reason: "invalid_json" };
  }
  if (canonicalize(parsed) !== policyjson) return { ok: false, reason: "not_canonical" };

  let policy: Policy;
  try {
    policy = validatePolicy(parsed, dialect);
  } catch {
    return { ok: false, reason: "schema_invalid" };
  }
  return { ok: true, policy };
}
