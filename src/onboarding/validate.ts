/**
 * Onboarding-payload validation (#41) — structural + semantic verification of
 * an onboarding transaction BEFORE a wallet signs it.
 *
 * The companion reaches this flow from a URL fragment (the CLI's link). That
 * fragment is untrusted input: an attacker can craft one, change the actions,
 * add an updateauth, target another contract — while the payload's own
 * `summary` field says something benign. Wallet confirmation is not an
 * application-level boundary, and the displayed summary must be DERIVED from
 * the actions that will actually be signed, never from a sibling field.
 *
 * This validator is PURE (no chain SDK, no I/O): the caller supplies the two
 * on-chain FACTS it needs — the authority's real public key and whether the
 * agent account already exists — so the whole thing is unit-tested off-chain.
 * The one cross-encoding key comparison (owner == authority key) is returned
 * as a derived value for the caller (which has the chain's key codec) to make.
 *
 * The daemon's `verifyLanded` re-checks the landed state independently — this
 * is the pre-signature barrier, that is the post-landing one.
 */

import { canonicalize } from "../core/canonical/jcs.js";

export interface OnboardAction {
  account: string;
  name: string;
  authorization: { actor: string; permission: string }[];
  data: Record<string, unknown>;
}

export interface OnboardPayload {
  v: 1;
  kind: "onboard";
  network: string;
  chainId: string;
  endpoints: string[];
  signboxContract: string;
  summary: { agent: string; authority: string; permission: string; publicKey: string };
  actions: OnboardAction[];
}

/** On-chain facts the caller resolves before validating. */
export interface OnboardFacts {
  agentAccountExists: boolean;
}

export interface OnboardDerived {
  agent: string;
  authority: string;
  permission: string;
  /** The key the daemon will sign with (on the agent's `active`). */
  agentPublicKey: string;
  /** The key that will control the agent account's `owner` — must be the authority's. */
  ownerKey: string;
  ramBytes: number;
  actionCount: number;
}

export interface OnboardValidation {
  ok: boolean;
  /** Stable, non-sensitive reasons (for the UI + audit). */
  errors: string[];
  /** Present only when the structure is well-formed enough to derive it. */
  derived?: OnboardDerived;
}

const HEX64 = /^[0-9a-f]{64}$/;

function isSingleKeyAuthority(value: unknown): { key: string } | null {
  if (typeof value !== "object" || value === null) return null;
  const a = value as { threshold?: unknown; keys?: unknown; accounts?: unknown; waits?: unknown };
  if (a.threshold !== 1) return null;
  if (!Array.isArray(a.keys) || a.keys.length !== 1) return null;
  if ((Array.isArray(a.accounts) ? a.accounts.length : 0) !== 0) return null;
  if ((Array.isArray(a.waits) ? a.waits.length : 0) !== 0) return null;
  const k = a.keys[0] as { key?: unknown; weight?: unknown };
  if (typeof k.key !== "string" || (typeof k.weight === "number" && k.weight < 1)) return null;
  return { key: k.key };
}

function authEquals(auth: OnboardAction["authorization"], expected: { actor: string; permission: string }[]): boolean {
  return (
    auth.length === expected.length &&
    auth.every((a, i) => a.actor === expected[i]!.actor && a.permission === expected[i]!.permission)
  );
}

/** Is `json` the canonical, empty deny-all policy for `chainId`? */
function isEmptyDenyAllPolicy(json: unknown, chainId: string): boolean {
  if (typeof json !== "string") return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return false;
  }
  if (canonicalize(parsed) !== json) return false; // must already BE canonical
  const p = parsed as { schemaVersion?: unknown; default?: unknown; rules?: unknown; chain?: { chainId?: unknown } };
  return (
    p.schemaVersion === 1 &&
    p.default === "deny" &&
    Array.isArray(p.rules) &&
    p.rules.length === 0 &&
    typeof p.chain === "object" &&
    p.chain !== null &&
    p.chain.chainId === chainId
  );
}

/**
 * Validate an onboarding payload against the ONE documented action template:
 *
 *   eosio::newaccount            (owner = authority key, active = agent key)
 *   [eosio::buyrambytes]         (optional; payer = authority)
 *   <signboxContract>::createpolicy   (empty deny-all policy, v1)
 *
 * Any extra/reordered action, a changed contract/permission/key/chain, a
 * non-empty or non-canonical policy, or a summary that disagrees with the
 * actions, is rejected. The owner-key ↔ authority-key comparison is deferred
 * to the caller (returned as `derived.ownerKey`).
 */
export function validateOnboardingPayload(
  payload: OnboardPayload,
  facts: OnboardFacts,
): OnboardValidation {
  const errors: string[] = [];
  const fail = (m: string): OnboardValidation => ({ ok: false, errors: [...errors, m] });

  if (payload.v !== 1 || payload.kind !== "onboard") return fail("not an onboarding payload");
  if (!HEX64.test(payload.chainId)) return fail("payload chainId is malformed");
  if (typeof payload.signboxContract !== "string" || payload.signboxContract.length === 0) {
    return fail("payload has no policy contract");
  }
  if (facts.agentAccountExists) {
    return fail("the agent account already exists — this onboarding intent is stale or replayed");
  }
  const actions = payload.actions;
  if (!Array.isArray(actions) || actions.length < 2 || actions.length > 3) {
    return fail("unexpected number of onboarding actions");
  }

  // Exact sequence: newaccount, [buyrambytes], createpolicy — nothing else.
  const first = actions[0]!;
  const last = actions[actions.length - 1]!;
  const middle = actions.length === 3 ? actions[1]! : undefined;
  if (`${first.account}::${first.name}` !== "eosio::newaccount") return fail("first action must be eosio::newaccount");
  if (`${last.account}::${last.name}` !== `${payload.signboxContract}::createpolicy`) {
    return fail("last action must be createpolicy on the policy contract");
  }
  if (middle !== undefined && `${middle.account}::${middle.name}` !== "eosio::buyrambytes") {
    return fail("only eosio::buyrambytes may sit between newaccount and createpolicy");
  }

  // --- newaccount: derive the true agent/authority/keys from the ACTION ---
  const na = first.data;
  const agent = na["name"];
  const authority = na["creator"];
  if (typeof agent !== "string" || typeof authority !== "string") return fail("newaccount is missing account/creator");
  if (!authEquals(first.authorization, [{ actor: authority, permission: "active" }])) {
    return fail("newaccount authorization is not the authority");
  }
  const active = isSingleKeyAuthority(na["active"]);
  const owner = isSingleKeyAuthority(na["owner"]);
  if (active === null) return fail("agent active is not a single dedicated key");
  if (owner === null) return fail("agent owner is not a single dedicated key");

  let ramBytes = 0;
  if (middle !== undefined) {
    const d = middle.data;
    if (d["payer"] !== authority || d["receiver"] !== agent) return fail("buyrambytes payer/receiver mismatch");
    if (!authEquals(middle.authorization, [{ actor: authority, permission: "active" }])) {
      return fail("buyrambytes authorization is not the authority");
    }
    ramBytes = typeof d["bytes"] === "number" ? d["bytes"] : NaN;
    if (!Number.isInteger(ramBytes) || ramBytes < 0) return fail("buyrambytes byte count is invalid");
  }

  // --- createpolicy ---
  const cp = last.data;
  const permission = cp["agentperm"];
  if (typeof permission !== "string") return fail("createpolicy has no agentperm");
  if (cp["agent"] !== agent) return fail("createpolicy agent does not match the created account");
  if (cp["authority"] !== authority) return fail("createpolicy authority does not match the creator");
  if (cp["version"] !== 1) return fail("createpolicy version must be 1");
  if (typeof cp["policyhash"] !== "string" || !HEX64.test(cp["policyhash"])) return fail("createpolicy policyhash is malformed");
  if (!isEmptyDenyAllPolicy(cp["policyjson"], payload.chainId)) return fail("createpolicy does not register the empty deny-all policy");
  if (!authEquals(last.authorization, [
    { actor: authority, permission: "active" },
    { actor: agent, permission: "owner" },
  ])) {
    return fail("createpolicy authorization is not [authority@active, agent@owner]");
  }

  // --- the payload's own summary must not lie about what the actions do ---
  const s = payload.summary;
  if (s.agent !== agent || s.authority !== authority || s.permission !== permission || s.publicKey !== active.key) {
    return fail("the displayed summary does not match the actions to be signed");
  }

  return {
    ok: errors.length === 0,
    errors,
    derived: {
      agent,
      authority,
      permission,
      agentPublicKey: active.key,
      ownerKey: owner.key,
      ramBytes,
      actionCount: actions.length,
    },
  };
}
