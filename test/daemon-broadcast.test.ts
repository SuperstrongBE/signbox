import { beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignBoxDaemon, type AgentRuntime } from "../src/daemon/server.js";
import { QuotaJournal } from "../src/daemon/quotaJournal.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { validatePolicy } from "../src/core/policy/schema.js";
import type { BroadcastOutcome, TransactionBroadcaster } from "../src/daemon/broadcaster.js";
import type {
  ChainContext,
  DecodedTransaction,
  KeyHandle,
  SignedTransactionResult,
  TransactionSigner,
} from "../src/core/types.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const CHAIN: ChainContext = { chain: "XPR", network: "testnet", chainId: CHAIN_ID };
const TOKEN = "tok_0123456789abcdefghij";
const NOW = Date.parse("2026-07-29T12:00:00.000Z");
const RULE = "allow-1xpr";

const KEY: KeyHandle = {
  keyId: "k1",
  publicKey: "PUB_K1_test",
  exportPolicy: "non-exportable",
  chain: CHAIN,
  agent: "superagent",
  permission: "active",
};

/** A financial policy: an allow rule with limits → a quota reservation. */
function statefulPolicy() {
  return validatePolicy({
    schemaVersion: 1,
    default: "deny",
    chain: { name: "XPR", chainId: CHAIN_ID },
    rules: [
      {
        id: RULE,
        effect: "allow",
        match: {
          contract: "eosio.token",
          action: "transfer",
          "authorization.actor": "$agent",
          "data.from": "$agent",
          "data.quantity.symbol": "XPR",
        },
        limits: { maxPerTransaction: "1000.0000 XPR", maxPerHour: "2500.0000 XPR" },
      },
    ],
  });
}

class FakeSigner implements TransactionSigner {
  async sign(_tx: DecodedTransaction, _key: KeyHandle): Promise<SignedTransactionResult> {
    return {
      signature: "SIG_K1_fake",
      transactionDigest: "d".repeat(64),
      signedTransaction: { signatures: ["SIG_K1_fake"], packedTransaction: "aabb", compression: 0 },
    };
  }
}

class FakeBroadcaster implements TransactionBroadcaster {
  calls = 0;
  lastSigned: unknown;
  constructor(private readonly outcome: BroadcastOutcome) {}
  async broadcast(signed: unknown): Promise<BroadcastOutcome> {
    this.calls += 1;
    this.lastSigned = signed;
    return this.outcome;
  }
}

function makeRequest(broadcast: boolean): string {
  return JSON.stringify({
    requestId: "req-00000001",
    agent: "superagent",
    chain: "XPR",
    network: "testnet",
    chainId: CHAIN_ID,
    transaction: {
      actions: [
        {
          account: "eosio.token",
          name: "transfer",
          authorization: [{ actor: "superagent", permission: "active" }],
          data: { from: "superagent", to: "alice", quantity: "10.0000 XPR", memo: "" },
        },
      ],
    },
    ...(broadcast ? { broadcast: true } : {}),
    requestedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 60_000).toISOString(),
    nonce: `nonce_${Math.random().toString(36).slice(2)}_0123456789`,
    token: TOKEN,
  });
}

const TEN_XPR = 100_000n; // 10.0000 XPR in minimal units (precision 4)

function build(outcome: BroadcastOutcome): {
  daemon: SignBoxDaemon;
  quotas: QuotaJournal;
  broadcaster: FakeBroadcaster;
} {
  const dir = mkdtempSync(join(tmpdir(), "signbox-bcast-"));
  const quotas = new QuotaJournal(join(dir, "state.db"));
  const broadcaster = new FakeBroadcaster(outcome);
  const daemon = new SignBoxDaemon(
    { socketPath: join(dir, "signbox.sock") },
    { decode: decodeXprTransaction, signer: new FakeSigner(), broadcaster, quotas, now: () => NOW },
  );
  const runtime: AgentRuntime = {
    agent: "superagent",
    permission: "active",
    chain: CHAIN,
    policy: statefulPolicy(),
    policyVersion: 1,
    enabled: true,
    token: Buffer.from(TOKEN, "utf8"),
    key: KEY,
  };
  daemon.registerAgent(runtime);
  return { daemon, quotas, broadcaster };
}

const consumed = (quotas: QuotaJournal): bigint =>
  quotas.consumed("superagent", RULE, "XPR", 4, 3_600_000, NOW);

describe("daemon-owned submit path (§13) — quota follows the chain outcome", () => {
  it("accepted broadcast commits the reserved quota and returns the receipt", async () => {
    const { daemon, quotas, broadcaster } = build({ status: "accepted", receipt: { transaction_id: "abc123" } });
    const response = await daemon.handleRequest(makeRequest(true));

    expect(response).toMatchObject({
      status: "signed",
      broadcast: { status: "accepted", receipt: { transaction_id: "abc123" }, quota: "committed" },
    });
    expect(broadcaster.calls).toBe(1);
    expect(consumed(quotas)).toBe(TEN_XPR); // committed → counts
    // The signed bytes NEVER leave the daemon on the submit path.
    expect((response as { signedTransaction?: unknown }).signedTransaction).toBeUndefined();
  });

  it("a deterministic chain rejection RELEASES the quota — nothing was spent", async () => {
    const { daemon, quotas, broadcaster } = build({ status: "rejected", reason: "tx_net_usage_exceeded" });
    const response = await daemon.handleRequest(makeRequest(true));

    expect(response).toMatchObject({
      status: "signed",
      broadcast: { status: "rejected", reason: "tx_net_usage_exceeded", quota: "released" },
    });
    expect(broadcaster.calls).toBe(1);
    expect(consumed(quotas)).toBe(0n); // released → the failed tx frees its quota
    expect((response as { signedTransaction?: unknown }).signedTransaction).toBeUndefined();
  });

  it("an ambiguous failure KEEPS the quota (fail closed — it may have landed)", async () => {
    const { daemon, quotas } = build({ status: "ambiguous", reason: "socket timeout" });
    const response = await daemon.handleRequest(makeRequest(true));

    expect(response).toMatchObject({
      status: "signed",
      broadcast: { status: "ambiguous", reason: "socket timeout", quota: "committed" },
    });
    expect(consumed(quotas)).toBe(TEN_XPR); // held — never risk a double-spend
  });

  it("without --broadcast the signature is returned and the quota commits on signing", async () => {
    const { daemon, quotas, broadcaster } = build({ status: "accepted", receipt: {} });
    const response = await daemon.handleRequest(makeRequest(false));

    expect(response).toMatchObject({ status: "signed" });
    expect((response as { broadcast?: unknown }).broadcast).toBeUndefined();
    expect((response as { signedTransaction?: unknown }).signedTransaction).toBeDefined();
    expect(broadcaster.calls).toBe(0); // the daemon did not submit
    expect(consumed(quotas)).toBe(TEN_XPR);
  });
});
