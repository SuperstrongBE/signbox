/**
 * Identity binding gate (#39) — the daemon's signing identity is a
 * non-configurable invariant. Even under a maximally-permissive allow policy,
 * an action whose actor/permission is not the bound agent, or whose key is not
 * on-chain-authorized, is refused BEFORE quota reservation or signing.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignBoxDaemon, type AgentRuntime } from "../src/daemon/server.js";
import { AuthorityCache } from "../src/daemon/authorityCache.js";
import { xprDialect } from "../src/chains/xpr/dialect.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { validatePolicy } from "../src/core/policy/schema.js";
import type {
  ChainContext,
  DecodedTransaction,
  KeyHandle,
  SignedTransactionResult,
  TransactionSigner,
} from "../src/core/types.js";
import type { QuotaDemand } from "../src/core/policy/engine.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const CHAIN: ChainContext = { chain: "XPR", network: "testnet", chainId: CHAIN_ID };
const TOKEN = "tok_0123456789abcdefghij";
const NOW = Date.parse("2026-08-06T12:00:00.000Z");

const KEY: KeyHandle = {
  keyId: "superagent",
  publicKey: "PUB_K1_agentkey",
  exportPolicy: "non-exportable",
  chain: CHAIN,
  agent: "superagent",
  permission: "xp2vr3",
};

/** The most permissive shape a bad operator could write: allow ANY transfer. */
function broadAllowPolicy() {
  return validatePolicy(
    {
      schemaVersion: 1,
      default: "deny",
      chain: { name: "XPR", chainId: CHAIN_ID },
      maxActionsPerTransaction: 4,
      rules: [{ id: "allow-anything", effect: "allow", match: { action: "transfer" } }],
    },
    xprDialect,
  );
}

class CountingSigner implements TransactionSigner {
  calls = 0;
  async sign(_tx: DecodedTransaction, _key: KeyHandle): Promise<SignedTransactionResult> {
    this.calls += 1;
    return { signature: "SIG_K1_x", transactionDigest: "d".repeat(64), signedTransaction: {} };
  }
}

class CountingQuota {
  reserves = 0;
  reserve(_agent: string, _demands: QuotaDemand[], _now: number) {
    this.reserves += 1;
    return { ok: true as const, reservationId: "r1" };
  }
  commit() {}
  release() {}
}

function action(actor: string, permission: string) {
  return {
    account: "eosio.token",
    name: "transfer",
    authorization: [{ actor, permission }],
    data: { from: actor, to: "alice", quantity: "1.0000 XPR", memo: "" },
  };
}

function request(actions: unknown[]): string {
  return JSON.stringify({
    requestId: "req-00000001",
    agent: "superagent",
    chain: "XPR",
    network: "testnet",
    chainId: CHAIN_ID,
    transaction: { actions },
    requestedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 60_000).toISOString(),
    nonce: `nonce_${Math.random().toString(36).slice(2)}_0123456789`,
    token: TOKEN,
  });
}

describe("identity binding gate (#39)", () => {
  let signer: CountingSigner;
  let quota: CountingQuota;

  function buildDaemon(authorized: boolean): SignBoxDaemon {
    signer = new CountingSigner();
    quota = new CountingQuota();
    const daemon = new SignBoxDaemon(
      { socketPath: join(mkdtempSync(join(tmpdir(), "signbox-identity-")), "signbox.sock") },
      {
        dialect: xprDialect,
        decode: (input, context) => decodeXprTransaction(input, context),
        signer,
        quotas: quota as unknown as never,
        authority: new AuthorityCache(async () => ({ authorized })),
        now: () => NOW,
      },
    );
    const runtime: AgentRuntime = {
      agent: "superagent",
      permission: "xp2vr3",
      chain: CHAIN,
      policy: broadAllowPolicy(),
      policyVersion: 1,
      enabled: true,
      token: Buffer.from(TOKEN, "utf8"),
      key: KEY,
    };
    daemon.registerAgent(runtime);
    return daemon;
  }

  beforeEach(() => {
    signer = new CountingSigner();
  });

  it("signs when actor, permission and on-chain authority all bind", async () => {
    const daemon = buildDaemon(true);
    const res = await daemon.handleRequest(request([action("superagent", "xp2vr3")]));
    expect(res).toMatchObject({ status: "signed" });
    expect(signer.calls).toBe(1);
  });

  it("refuses a wrong ACTOR under a broad allow — signer never called, no quota", async () => {
    const daemon = buildDaemon(true);
    const res = await daemon.handleRequest(request([action("mallory", "xp2vr3")]));
    expect(res).toMatchObject({ status: "denied", code: "AUTHORIZATION_MISMATCH" });
    expect(signer.calls).toBe(0);
    expect(quota.reserves).toBe(0);
  });

  it("refuses a wrong PERMISSION under a broad allow", async () => {
    const daemon = buildDaemon(true);
    const res = await daemon.handleRequest(request([action("superagent", "owner")]));
    expect(res).toMatchObject({ status: "denied", code: "AUTHORIZATION_MISMATCH" });
    expect(signer.calls).toBe(0);
  });

  it("checks EVERY action — one bad actor in a multi-action tx refuses all", async () => {
    const daemon = buildDaemon(true);
    const res = await daemon.handleRequest(
      request([action("superagent", "xp2vr3"), action("mallory", "xp2vr3")]),
    );
    expect(res).toMatchObject({ status: "denied", code: "AUTHORIZATION_MISMATCH" });
    expect(signer.calls).toBe(0);
  });

  it("refuses when the key is not authorized on-chain (rotation/revocation), fail closed", async () => {
    const daemon = buildDaemon(false); // authority says: not bound
    const res = await daemon.handleRequest(request([action("superagent", "xp2vr3")]));
    expect(res).toMatchObject({ status: "denied", code: "AUTHORIZATION_MISMATCH" });
    expect(signer.calls).toBe(0);
    expect(quota.reserves).toBe(0);
  });
});
