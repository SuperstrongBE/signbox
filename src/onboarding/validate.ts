/**
 * Onboarding-payload validation (#41) — structural + semantic verification of
 * an onboarding transaction BEFORE a wallet signs it.
 *
 * THREAT MODEL (the correction from the #72 review): when the companion is
 * reached from a crafted URL fragment, EVERY field of the payload is
 * attacker-controlled — the actions, the `summary`, `signboxContract`, and the
 * `endpoints`. So a check that compares one payload field against another
 * proves nothing (the attacker sets both consistently), and any on-chain fact
 * read through `payload.endpoints` can be fabricated by a malicious RPC.
 *
 * Therefore this validator trusts NOTHING inside the payload as an anchor. It
 * takes a `TrustedContext` the caller resolves from COMPILED configuration
 * (the pinned chain id, the deployment contract, the chain name) and from
 * TRUSTED endpoints (whether the agent account already exists). The payload is
 * only ever compared against those trusted anchors. The one cross-encoding key
 * comparison (owner == the authority's real key) is returned as
 * `derived.ownerKey` for the caller to make against a trusted-endpoint fetch.
 *
 * Pure (no chain SDK, no I/O) and fail-closed: a malformed action shape is a
 * validation error, never a thrown exception.
 *
 * Residual (documented, tracked separately): the agent's `active` key is
 * carried in the fragment and cannot be authenticated from client-side data
 * alone without an out-of-band commitment. It is bounded here by requiring the
 * account `owner` to be EXACTLY the authority's key (so the authority keeps
 * exclusive control) and by the daemon's post-landing `verifyLanded`.
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

/**
 * Anchors the caller resolves from COMPILED config + TRUSTED endpoints — never
 * from the payload.
 */
export interface TrustedContext {
  /** Pinned chain id from compiled network config (matched to payload.chainId). */
  chainId: string;
  /** The policy's chain name (e.g. "XPR"), from compiled config. */
  chainName: string;
  /** The deployment's SignBox contract account, from compiled config. */
  signboxContract: string;
  /** Whether the agent account already exists — read from TRUSTED endpoints. */
  agentAccountExists: boolean;
}

export interface OnboardDerived {
  agent: string;
  authority: string;
  permission: string;
  /** The key the daemon will sign with (on the agent's `active`). */
  agentPublicKey: string;
  /** The key that will control `owner` — the caller MUST equal this to the authority's real key. */
  ownerKey: string;
  ramBytes: number;
  actionCount: number;
}

export interface OnboardValidation {
  ok: boolean;
  errors: string[];
  derived?: OnboardDerived;
}

const HEX64 = /^[0-9a-f]{64}$/;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A well-formed action shape (fail closed on anything else). */
function isAction(v: unknown): v is OnboardAction {
  if (!isObject(v)) return false;
  if (typeof v["account"] !== "string" || typeof v["name"] !== "string") return false;
  if (!Array.isArray(v["authorization"])) return false;
  for (const a of v["authorization"]) {
    if (!isObject(a) || typeof a["actor"] !== "string" || typeof a["permission"] !== "string") return false;
  }
  return isObject(v["data"]);
}

/** EXACT threshold-1, single-key authority with no delegated accounts/waits. */
function exclusiveSingleKey(value: unknown): { key: string } | null {
  if (!isObject(value)) return null;
  if (value["threshold"] !== 1) return null;
  const keys = value["keys"];
  if (!Array.isArray(keys) || keys.length !== 1) return null;
  if ((Array.isArray(value["accounts"]) ? (value["accounts"] as unknown[]).length : 1) !== 0) return null;
  if ((Array.isArray(value["waits"]) ? (value["waits"] as unknown[]).length : 1) !== 0) return null;
  const k = keys[0];
  if (!isObject(k) || typeof k["key"] !== "string") return null;
  if (typeof k["weight"] === "number" && k["weight"] < 1) return null;
  return { key: k["key"] };
}

function authEquals(auth: OnboardAction["authorization"], expected: { actor: string; permission: string }[]): boolean {
  return (
    auth.length === expected.length &&
    auth.every((a, i) => a.actor === expected[i]!.actor && a.permission === expected[i]!.permission)
  );
}

/** The EXACT canonical string of the generated empty deny-all policy (matches emptyPolicy()). */
export function expectedEmptyPolicyCanonical(chainName: string, chainId: string): string {
  return canonicalize({ schemaVersion: 1, default: "deny", chain: { name: chainName, chainId }, rules: [] });
}

export function validateOnboardingPayload(
  payload: OnboardPayload,
  trusted: TrustedContext,
): OnboardValidation {
  const errors: string[] = [];
  const fail = (m: string): OnboardValidation => ({ ok: false, errors: [...errors, m] });

  if (payload.v !== 1 || payload.kind !== "onboard") return fail("not an onboarding payload");

  // Anchor to compiled config — NOT to payload fields.
  if (!HEX64.test(payload.chainId) || payload.chainId !== trusted.chainId) {
    return fail("payload is for a different or unknown chain");
  }
  if (payload.signboxContract !== trusted.signboxContract) {
    return fail("payload targets a contract other than the trusted deployment");
  }
  if (trusted.agentAccountExists) {
    return fail("the agent account already exists — this onboarding intent is stale or replayed");
  }

  const actions = payload.actions;
  if (!Array.isArray(actions) || actions.length < 2 || actions.length > 3) {
    return fail("unexpected number of onboarding actions");
  }
  if (!actions.every(isAction)) return fail("an onboarding action is malformed");

  // Exact sequence: newaccount, [buyrambytes], createpolicy — nothing else.
  const first = actions[0]!;
  const last = actions[actions.length - 1]!;
  const middle = actions.length === 3 ? actions[1]! : undefined;
  if (`${first.account}::${first.name}` !== "eosio::newaccount") return fail("first action must be eosio::newaccount");
  if (last.account !== trusted.signboxContract || last.name !== "createpolicy") {
    return fail("last action must be createpolicy on the trusted contract");
  }
  if (middle !== undefined && `${middle.account}::${middle.name}` !== "eosio::buyrambytes") {
    return fail("only eosio::buyrambytes may sit between newaccount and createpolicy");
  }

  // --- newaccount ---
  const na = first.data;
  const agent = na["name"];
  const authority = na["creator"];
  if (typeof agent !== "string" || typeof authority !== "string") return fail("newaccount is missing account/creator");
  if (!authEquals(first.authorization, [{ actor: authority, permission: "active" }])) {
    return fail("newaccount authorization is not the authority");
  }
  const active = exclusiveSingleKey(na["active"]);
  const owner = exclusiveSingleKey(na["owner"]);
  if (active === null) return fail("agent active is not an exclusive single dedicated key");
  if (owner === null) return fail("agent owner is not an exclusive single dedicated key");

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

  // --- createpolicy: the policy must be the EXACT generated empty deny-all ---
  const cp = last.data;
  const permission = cp["agentperm"];
  if (typeof permission !== "string") return fail("createpolicy has no agentperm");
  if (cp["agent"] !== agent) return fail("createpolicy agent does not match the created account");
  if (cp["authority"] !== authority) return fail("createpolicy authority does not match the creator");
  if (cp["version"] !== 1) return fail("createpolicy version must be 1");
  if (typeof cp["policyhash"] !== "string" || !HEX64.test(cp["policyhash"])) return fail("createpolicy policyhash is malformed");
  if (cp["policyjson"] !== expectedEmptyPolicyCanonical(trusted.chainName, trusted.chainId)) {
    return fail("createpolicy does not register the exact empty deny-all policy");
  }
  if (!authEquals(last.authorization, [
    { actor: authority, permission: "active" },
    { actor: agent, permission: "owner" },
  ])) {
    return fail("createpolicy authorization is not [authority@active, agent@owner]");
  }

  // Consistency guard on the (untrusted) summary — not security-relevant since
  // the UI displays a summary DERIVED from these actions, but a divergence
  // still means a malformed request.
  const s = payload.summary;
  if (!isObject(s) || s.agent !== agent || s.authority !== authority || s.permission !== permission || s.publicKey !== active.key) {
    return fail("the payload summary does not match the actions");
  }

  return {
    ok: true,
    errors,
    derived: { agent, authority, permission, agentPublicKey: active.key, ownerKey: owner.key, ramBytes, actionCount: actions.length },
  };
}
