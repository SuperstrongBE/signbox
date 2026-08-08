/**
 * Onboarding-payload validation (#41, hardened per the #72 review).
 *
 * The validator trusts NOTHING inside the payload as an anchor: chain id,
 * contract and the empty policy are checked against a caller-supplied
 * TrustedContext (compiled config), not against sibling payload fields. Every
 * tampering — including a payload that changes BOTH the action AND its own
 * "trusted-looking" field — is refused, and malformed shapes fail closed.
 */

import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/core/canonical/jcs.js";
import { emptyPolicy } from "../src/core/policy/schema.js";
import {
  validateOnboardingPayload,
  expectedEmptyPolicyCanonical,
  type OnboardPayload,
  type TrustedContext,
} from "../src/onboarding/validate.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const AGENT_KEY = "PUB_K1_agentkey000000000000000000000000000000000000000000";
const AUTHORITY_KEY = "PUB_K1_authoritykey00000000000000000000000000000000000000";
const POLICY_JSON = expectedEmptyPolicyCanonical("XPR", CHAIN_ID);
const POLICY_HASH = "a".repeat(64);

/** Compiled, trusted anchors (what the web resolves from NETWORKS/SIGNBOX_CONTRACT). */
const TRUSTED: TrustedContext = {
  chainId: CHAIN_ID,
  chainName: "XPR",
  signboxContract: "signbox",
  agentAccountExists: false,
};

function keyAuth(key: string) {
  return { threshold: 1, keys: [{ key, weight: 1 }], accounts: [], waits: [] };
}

function validPayload(): OnboardPayload {
  return {
    v: 1,
    kind: "onboard",
    network: "testnet",
    chainId: CHAIN_ID,
    endpoints: ["https://attacker.example"], // untrusted — must be ignored
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

function clone(p: OnboardPayload): OnboardPayload {
  return JSON.parse(JSON.stringify(p));
}

describe("expectedEmptyPolicyCanonical", () => {
  it("matches the daemon's generated empty policy byte-for-byte (no drift)", () => {
    expect(expectedEmptyPolicyCanonical("XPR", CHAIN_ID)).toBe(canonicalize(emptyPolicy("XPR", CHAIN_ID)));
  });
});

describe("validateOnboardingPayload (#41, trust-anchored)", () => {
  it("accepts a pristine payload and derives the summary from the actions", () => {
    const r = validateOnboardingPayload(validPayload(), TRUSTED);
    expect(r.ok).toBe(true);
    expect(r.derived).toMatchObject({ agent: "funagent", authority: "rockerone", agentPublicKey: AGENT_KEY, ownerKey: AUTHORITY_KEY, actionCount: 2 });
  });

  it("accepts the optional buyrambytes", () => {
    const p = clone(validPayload());
    p.actions.splice(1, 0, {
      account: "eosio",
      name: "buyrambytes",
      authorization: [{ actor: "rockerone", permission: "active" }],
      data: { payer: "rockerone", receiver: "funagent", bytes: 4096 },
    });
    expect(validateOnboardingPayload(p, TRUSTED).ok).toBe(true);
  });

  it("rejects an EXTRA action", () => {
    const p = clone(validPayload());
    p.actions.splice(1, 0, {
      account: "eosio",
      name: "updateauth",
      authorization: [{ actor: "funagent", permission: "owner" }],
      data: { account: "funagent", permission: "active", parent: "owner", auth: keyAuth("PUB_K1_attacker") },
    });
    expect(validateOnboardingPayload(p, TRUSTED).ok).toBe(false);
  });

  it("rejects a changed contract even when the payload's OWN signboxContract is changed to match", () => {
    const p = clone(validPayload());
    p.actions[1]!.account = "evilcontract";
    p.signboxContract = "evilcontract"; // attacker makes the payload self-consistent
    expect(validateOnboardingPayload(p, TRUSTED).ok).toBe(false); // still != TRUSTED.signboxContract
  });

  it("rejects a different chain even when the payload is self-consistent", () => {
    const p = clone(validPayload());
    p.chainId = "b".repeat(64);
    // policy re-signed for the other chain too — self-consistent but wrong.
    (p.actions[1]!.data as { policyjson: string }).policyjson = expectedEmptyPolicyCanonical("XPR", "b".repeat(64));
    expect(validateOnboardingPayload(p, TRUSTED).ok).toBe(false); // != TRUSTED.chainId
  });

  it("rejects an owner that is NOT an exclusive single key (attacker co-key)", () => {
    const p = clone(validPayload());
    (p.actions[0]!.data as { owner: unknown }).owner = {
      threshold: 1,
      keys: [{ key: AUTHORITY_KEY, weight: 1 }, { key: "PUB_K1_attacker", weight: 1 }],
      accounts: [],
      waits: [],
    };
    expect(validateOnboardingPayload(p, TRUSTED).ok).toBe(false);
  });

  it("rejects an active/owner that delegates to an account or a wait", () => {
    const withAccount = clone(validPayload());
    (withAccount.actions[0]!.data as { active: unknown }).active = {
      threshold: 1,
      keys: [{ key: AGENT_KEY, weight: 1 }],
      accounts: [{ permission: { actor: "x", permission: "active" }, weight: 1 }],
      waits: [],
    };
    expect(validateOnboardingPayload(withAccount, TRUSTED).ok).toBe(false);
  });

  it("rejects a changed active key that disagrees with the summary", () => {
    const p = clone(validPayload());
    (p.actions[0]!.data as { active: unknown }).active = keyAuth("PUB_K1_attacker00000000000000000000000000000000000000000");
    expect(validateOnboardingPayload(p, TRUSTED).ok).toBe(false);
  });

  it("rejects a non-empty / non-canonical / extra-field policy (exact match required)", () => {
    const withRule = clone(validPayload());
    (withRule.actions[1]!.data as { policyjson: string }).policyjson = canonicalize({
      schemaVersion: 1, default: "deny", chain: { name: "XPR", chainId: CHAIN_ID },
      rules: [{ id: "x", effect: "allow", match: { action: "transfer" } }],
    });
    expect(validateOnboardingPayload(withRule, TRUSTED).ok).toBe(false);

    const extraField = clone(validPayload());
    (extraField.actions[1]!.data as { policyjson: string }).policyjson = canonicalize({
      schemaVersion: 1, default: "deny", chain: { name: "XPR", chainId: CHAIN_ID }, rules: [], maxActionsPerTransaction: 5,
    });
    expect(validateOnboardingPayload(extraField, TRUSTED).ok).toBe(false);

    const noChainName = clone(validPayload());
    (noChainName.actions[1]!.data as { policyjson: string }).policyjson = canonicalize({
      schemaVersion: 1, default: "deny", chain: { chainId: CHAIN_ID }, rules: [],
    });
    expect(validateOnboardingPayload(noChainName, TRUSTED).ok).toBe(false);
  });

  it("rejects a lying summary", () => {
    const p = clone(validPayload());
    p.summary.agent = "someoneelse";
    expect(validateOnboardingPayload(p, TRUSTED).ok).toBe(false);
  });

  it("rejects a stale/replayed intent (agent already exists)", () => {
    expect(validateOnboardingPayload(validPayload(), { ...TRUSTED, agentAccountExists: true }).ok).toBe(false);
  });

  it("FAILS CLOSED (returns an error, never throws) on malformed action shapes", () => {
    const missingAuth = clone(validPayload());
    delete (missingAuth.actions[0] as { authorization?: unknown }).authorization;
    expect(() => validateOnboardingPayload(missingAuth, TRUSTED)).not.toThrow();
    expect(validateOnboardingPayload(missingAuth, TRUSTED).ok).toBe(false);

    const nonArrayAuth = clone(validPayload());
    (nonArrayAuth.actions[0] as { authorization: unknown }).authorization = "nope";
    expect(() => validateOnboardingPayload(nonArrayAuth, TRUSTED)).not.toThrow();
    expect(validateOnboardingPayload(nonArrayAuth, TRUSTED).ok).toBe(false);

    const nullData = clone(validPayload());
    (nullData.actions[1] as { data: unknown }).data = null;
    expect(() => validateOnboardingPayload(nullData, TRUSTED)).not.toThrow();
    expect(validateOnboardingPayload(nullData, TRUSTED).ok).toBe(false);
  });
});
