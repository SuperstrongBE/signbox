/**
 * verifyLanded owner check (#41, defense in depth) — the daemon's
 * post-landing verification must catch a forged onboarding that put the agent
 * account's OWNER under an attacker's key, not just check the active key.
 */

import { afterEach, describe, expect, it } from "vitest";
import { JsonRpc } from "@proton/js";
import { XprOnboardingBackend } from "../src/chains/xpr/onboarding.js";
import type { OnboardingInput } from "../src/onboarding/flow.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const AGENT_KEY = "PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63";
const AUTHORITY_KEY = "PUB_K1_8fbFHVFtgKPBqA7L2h9YQ7dw1J8xr1n9L4kQ8mV4d6r7s8t9uP";
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

/** Stub the JsonRpc fetch funnel with crafted get_info/get_account/get_table_rows. */
function stub(agentOwnerKey: string): () => void {
  const proto = JsonRpc.prototype as unknown as Record<string, unknown>;
  const saved = proto["fetch"];
  proto["fetch"] = async (path: string, body: unknown) => {
    if (path === "/v1/chain/get_info") return { chain_id: CHAIN_ID, head_block_time: HEAD() };
    if (path === "/v1/chain/get_account") {
      const name = (body as { account_name: string }).account_name;
      if (name === "rockerone") {
        return { permissions: [{ perm_name: "active", required_auth: keyAuth(AUTHORITY_KEY) }] };
      }
      // funagent: active holds the agent key; owner holds `agentOwnerKey`.
      return {
        permissions: [
          { perm_name: "active", required_auth: keyAuth(AGENT_KEY) },
          { perm_name: "owner", required_auth: keyAuth(agentOwnerKey) },
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

function backend() {
  return new XprOnboardingBackend({ endpoints: ["http://127.0.0.1:1"], chainId: CHAIN_ID, signboxContract: "signbox" });
}

describe("verifyLanded — owner binding (#41)", () => {
  let restore: (() => void) | undefined;
  afterEach(() => {
    restore?.();
    restore = undefined;
  });

  it("accepts when the agent owner is the authority's key", async () => {
    restore = stub(AUTHORITY_KEY);
    const r = await backend().verifyLanded({ input, agentPublicKey: AGENT_KEY, emptyPolicyHash: "a".repeat(64) });
    expect(r.ok).toBe(true);
  });

  it("REFUSES when the agent owner is an attacker's key (account takeover)", async () => {
    restore = stub("PUB_K1_5jXAcompletely00different00attacker00key0000000000000");
    const r = await backend().verifyLanded({ input, agentPublicKey: AGENT_KEY, emptyPolicyHash: "a".repeat(64) });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/owner is not controlled by the authority/);
  });
});
