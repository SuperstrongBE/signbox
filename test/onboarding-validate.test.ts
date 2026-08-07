/**
 * Onboarding-payload validation (#41). A benign, well-formed payload passes;
 * every tampering the issue names (extra action, changed contract/permission/
 * key/chain, a lying summary, a non-empty policy, a stale/replayed intent) is
 * refused BEFORE any signature.
 */

import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/core/canonical/jcs.js";
import { validateOnboardingPayload, type OnboardPayload } from "../src/onboarding/validate.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const AGENT_KEY = "PUB_K1_agentkey000000000000000000000000000000000000000000";
const AUTHORITY_KEY = "PUB_K1_authoritykey00000000000000000000000000000000000000";
const POLICY_JSON = canonicalize({
  schemaVersion: 1,
  default: "deny",
  chain: { name: "XPR", chainId: CHAIN_ID },
  rules: [],
});
// A deterministic 64-hex placeholder — the validator checks the policy is the
// canonical empty deny-all and that policyhash is 64-hex; the contract enforces
// hash == sha256(policyjson).
const POLICY_HASH = "a".repeat(64);

function keyAuth(key: string) {
  return { threshold: 1, keys: [{ key, weight: 1 }], accounts: [], waits: [] };
}

/** A pristine, valid onboarding payload. Mutators below tamper with a clone. */
function validPayload(): OnboardPayload {
  return {
    v: 1,
    kind: "onboard",
    network: "testnet",
    chainId: CHAIN_ID,
    endpoints: ["https://testnet.example"],
    signboxContract: "signbox",
    summary: { agent: "funagent", authority: "rockerone", permission: "agentperm", publicKey: AGENT_KEY },
    actions: [
      {
        account: "eosio",
        name: "newaccount",
        authorization: [{ actor: "rockerone", permission: "active" }],
        data: { creator: "rockerone", name: "funagent", owner: keyAuth(AUTHORITY_KEY), active: keyAuth(AGENT_KEY) },
      },
      {
        account: "signbox",
        name: "createpolicy",
        authorization: [
          { actor: "rockerone", permission: "active" },
          { actor: "funagent", permission: "owner" },
        ],
        data: {
          agent: "funagent",
          authority: "rockerone",
          agentperm: "agentperm",
          version: 1,
          policyhash: POLICY_HASH,
          policyjson: POLICY_JSON,
        },
      },
    ],
  };
}

const FRESH = { agentAccountExists: false };

function clone(p: OnboardPayload): OnboardPayload {
  return JSON.parse(JSON.stringify(p));
}

describe("validateOnboardingPayload (#41)", () => {
  it("accepts a pristine payload and derives the summary from the actions", () => {
    const r = validateOnboardingPayload(validPayload(), FRESH);
    expect(r.ok).toBe(true);
    expect(r.derived).toMatchObject({
      agent: "funagent",
      authority: "rockerone",
      permission: "agentperm",
      agentPublicKey: AGENT_KEY,
      ownerKey: AUTHORITY_KEY, // the caller cross-checks this against the chain
      actionCount: 2,
    });
  });

  it("accepts the optional buyrambytes in the middle", () => {
    const p = clone(validPayload());
    p.actions.splice(1, 0, {
      account: "eosio",
      name: "buyrambytes",
      authorization: [{ actor: "rockerone", permission: "active" }],
      data: { payer: "rockerone", receiver: "funagent", bytes: 4096 },
    });
    expect(validateOnboardingPayload(p, FRESH).ok).toBe(true);
  });

  it("rejects an EXTRA action (e.g. a smuggled updateauth/transfer)", () => {
    const p = clone(validPayload());
    p.actions.splice(1, 0, {
      account: "eosio",
      name: "updateauth",
      authorization: [{ actor: "funagent", permission: "owner" }],
      data: { account: "funagent", permission: "active", parent: "owner", auth: keyAuth("PUB_K1_attacker") },
    });
    expect(validateOnboardingPayload(p, FRESH).ok).toBe(false);
  });

  it("rejects a changed OWNER key (account-takeover vector) — surfaced for the caller's check", () => {
    // Structurally still valid; the derived ownerKey is the attacker's, which
    // the caller compares against the on-chain authority key and refuses.
    const p = clone(validPayload());
    (p.actions[0]!.data as { owner: unknown }).owner = keyAuth("PUB_K1_attacker00000000000000000000000000000000000000000");
    const r = validateOnboardingPayload(p, FRESH);
    expect(r.ok).toBe(true);
    expect(r.derived!.ownerKey).toBe("PUB_K1_attacker00000000000000000000000000000000000000000");
    expect(r.derived!.ownerKey).not.toBe(AUTHORITY_KEY);
  });

  it("rejects a changed ACTIVE (agent) key that disagrees with the summary", () => {
    const p = clone(validPayload());
    (p.actions[0]!.data as { active: unknown }).active = keyAuth("PUB_K1_attacker00000000000000000000000000000000000000000");
    expect(validateOnboardingPayload(p, FRESH).ok).toBe(false); // summary.publicKey no longer matches
  });

  it("rejects a changed CONTRACT on createpolicy", () => {
    const p = clone(validPayload());
    p.actions[1]!.account = "evilcontract";
    expect(validateOnboardingPayload(p, FRESH).ok).toBe(false);
  });

  it("rejects a changed PERMISSION when the summary still claims the old one", () => {
    const p = clone(validPayload());
    (p.actions[1]!.data as { agentperm: string }).agentperm = "owner";
    expect(validateOnboardingPayload(p, FRESH).ok).toBe(false);
  });

  it("rejects a non-empty / non-canonical policy", () => {
    const withRule = clone(validPayload());
    (withRule.actions[1]!.data as { policyjson: string }).policyjson = canonicalize({
      schemaVersion: 1,
      default: "deny",
      chain: { name: "XPR", chainId: CHAIN_ID },
      rules: [{ id: "x", effect: "allow", match: { action: "transfer" } }],
    });
    expect(validateOnboardingPayload(withRule, FRESH).ok).toBe(false);

    const nonCanonical = clone(validPayload());
    (nonCanonical.actions[1]!.data as { policyjson: string }).policyjson =
      '{"default":"deny","schemaVersion":1,"chain":{"chainId":"' + CHAIN_ID + '","name":"XPR"},"rules":[]}';
    expect(validateOnboardingPayload(nonCanonical, FRESH).ok).toBe(false);
  });

  it("rejects a policy for the WRONG chain", () => {
    const p = clone(validPayload());
    (p.actions[1]!.data as { policyjson: string }).policyjson = canonicalize({
      schemaVersion: 1,
      default: "deny",
      chain: { name: "XPR", chainId: "b".repeat(64) },
      rules: [],
    });
    expect(validateOnboardingPayload(p, FRESH).ok).toBe(false);
  });

  it("rejects a LYING summary (actions benign, summary claims a different agent)", () => {
    const p = clone(validPayload());
    p.summary.agent = "someoneelse";
    expect(validateOnboardingPayload(p, FRESH).ok).toBe(false);
  });

  it("rejects a STALE/REPLAYED intent (agent already exists on-chain)", () => {
    expect(validateOnboardingPayload(validPayload(), { agentAccountExists: true }).ok).toBe(false);
  });

  it("rejects wrong authorization structure on newaccount", () => {
    const p = clone(validPayload());
    p.actions[0]!.authorization = [{ actor: "mallory", permission: "active" }];
    expect(validateOnboardingPayload(p, FRESH).ok).toBe(false);
  });
});
