/**
 * verifyLanded owner check (#41, defense in depth) — the daemon's
 * post-landing verification must catch a forged onboarding that put the agent
 * account's OWNER under an attacker's key, not just check the active key.
 */

import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { JsonRpc } from "@proton/js";
import { XprOnboardingBackend } from "../src/chains/xpr/onboarding.js";
import { generateK1KeyPair } from "../src/chains/xpr/keygen.js";
import type { OnboardingInput } from "../src/onboarding/flow.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
// Real, distinct K1 public keys (the authority check normalizes strictly, so
// fixtures must be parsable keys).
let AGENT_KEY: string, AUTHORITY_KEY: string, ATTACKER: string;
beforeAll(async () => {
  [AGENT_KEY, AUTHORITY_KEY, ATTACKER] = (
    await Promise.all([generateK1KeyPair(), generateK1KeyPair(), generateK1KeyPair()])
  ).map((k) => k.publicKey);
});
const HEAD = () => new Date(Date.now() - 500).toISOString().replace("Z", "");

const input: OnboardingInput = {
  chain: { chain: "XPR", network: "testnet", chainId: CHAIN_ID },
  authority: "rockerone",
  agent: "funagent",
  permission: "active",
  exportPolicy: "non-exportable",
  keystorePath: "/tmp/x.keystore.json",
};

function keyAuth(key: string) {
  return { threshold: 1, keys: [{ key, weight: 1 }], accounts: [], waits: [] };
}

/**
 * Stub the JsonRpc fetch funnel. `agentActive`/`agentOwner` are the landed
 * required_auth objects for the agent's active/owner permissions.
 */
function stub(agentActive: unknown, agentOwner: unknown): () => void {
  const proto = JsonRpc.prototype as unknown as Record<string, unknown>;
  const saved = proto["fetch"];
  proto["fetch"] = async (path: string, body: unknown) => {
    if (path === "/v1/chain/get_info") return { chain_id: CHAIN_ID, head_block_time: HEAD() };
    if (path === "/v1/chain/get_account") {
      const name = (body as { account_name: string }).account_name;
      if (name === "rockerone") {
        return { permissions: [{ perm_name: "active", required_auth: keyAuth(AUTHORITY_KEY) }] };
      }
      return {
        permissions: [
          { perm_name: "active", required_auth: agentActive },
          { perm_name: "owner", required_auth: agentOwner },
        ],
      };
    }
    if (path === "/v1/chain/get_table_rows") {
      return {
        rows: [{ agent: "funagent", authority: "rockerone", agentperm: "active", policyhash: "a".repeat(64) }],
        more: false,
      };
    }
    return {};
  };
  return () => {
    proto["fetch"] = saved;
  };
}

function coKey(a: string, b: string) {
  return { threshold: 1, keys: [{ key: a, weight: 1 }, { key: b, weight: 1 }], accounts: [], waits: [] };
}

function backend() {
  return new XprOnboardingBackend({ endpoints: ["http://127.0.0.1:1"], chainId: CHAIN_ID, signboxContract: "signbox" });
}

describe("verifyLanded — owner binding (#41)", () => {
  let restore: (() => void) | undefined;
  afterEach(() => {
    restore?.();
    restore = undefined;
  });

  const run = () => backend().verifyLanded({ input, agentPublicKey: AGENT_KEY, emptyPolicyHash: "a".repeat(64) });

  it("accepts an exclusive active (agent key) + exclusive owner (authority key)", async () => {
    restore = stub(keyAuth(AGENT_KEY), keyAuth(AUTHORITY_KEY));
    expect((await run()).ok).toBe(true);
  });

  it("REFUSES an owner that is an attacker's key (takeover)", async () => {
    restore = stub(keyAuth(AGENT_KEY), keyAuth(ATTACKER));
    const r = await run();
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/owner is not exclusively the authority/);
  });

  it("REFUSES a NON-EXCLUSIVE owner (authority key + attacker co-key, threshold 1)", async () => {
    restore = stub(keyAuth(AGENT_KEY), coKey(AUTHORITY_KEY, ATTACKER));
    const r = await run();
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/owner is not exclusively the authority/);
  });

  it("REFUSES a NON-EXCLUSIVE active (agent key + attacker co-key, threshold 1)", async () => {
    restore = stub(coKey(AGENT_KEY, ATTACKER), keyAuth(AUTHORITY_KEY));
    const r = await run();
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/permission is not exclusively the agent key/);
  });
});
