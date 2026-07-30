import { beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignBoxDaemon } from "../src/daemon/server.js";
import { PolicyCache } from "../src/daemon/policyCache.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { canonicalize } from "../src/core/canonical/jcs.js";
import { emptyPolicy } from "../src/core/policy/schema.js";
import type { PolicyReader, PolicyRowRaw } from "../src/daemon/chainPolicyReader.js";
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
const NOW = Date.parse("2026-07-30T12:00:00.000Z");

const KEY: KeyHandle = {
  keyId: "k1",
  publicKey: "PUB_K1_test",
  exportPolicy: "non-exportable",
  chain: CHAIN,
  agent: "superagent",
  permission: "xp2vr3",
};

function onchainRow(enabled: boolean): PolicyRowRaw {
  const canonical = canonicalize({
    schemaVersion: 1,
    default: "deny",
    chain: { name: "XPR", chainId: CHAIN_ID },
    rules: [
      {
        id: "allow-transfer",
        effect: "allow",
        match: { contract: "eosio.token", action: "transfer", "data.from": "$agent" },
      },
    ],
  });
  return {
    agent: "superagent",
    authority: "superdev",
    agentperm: "xp2vr3",
    version: 4,
    policyhash: createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("hex"),
    policyjson: canonical,
    enabled,
    updatedat: NOW,
  };
}

class FakeReader implements PolicyReader {
  row: PolicyRowRaw | null;
  down = false;
  constructor(row: PolicyRowRaw | null) {
    this.row = row;
  }
  async read(): Promise<PolicyRowRaw | null> {
    if (this.down) throw new Error("rpc down");
    return this.row;
  }
}

class FakeSigner implements TransactionSigner {
  calls = 0;
  async sign(_tx: DecodedTransaction, _k: KeyHandle): Promise<SignedTransactionResult> {
    this.calls += 1;
    return { signature: "SIG_K1_fake", transactionDigest: "f".repeat(64) };
  }
}

function request(): string {
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
          authorization: [{ actor: "superagent", permission: "xp2vr3" }],
          data: { from: "superagent", to: "alice", quantity: "1.0000 XPR", memo: "" },
        },
      ],
    },
    requestedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 60_000).toISOString(),
    nonce: `nonce_${Math.random().toString(36).slice(2)}_0123456789`,
    token: TOKEN,
  });
}

describe("daemon with on-chain policy cache (§14)", () => {
  let signer: FakeSigner;

  function makeDaemon(reader: PolicyReader): SignBoxDaemon {
    signer = new FakeSigner();
    const cache = new PolicyCache(":memory:", reader, {}, () => NOW);
    const daemon = new SignBoxDaemon(
      { socketPath: join(mkdtempSync(join(tmpdir(), "signbox-daemon-")), "s.sock") },
      { decode: decodeXprTransaction, signer, policyCache: cache, now: () => NOW },
    );
    // The registered policy is a deny-all placeholder: the cache must override
    // it with the on-chain policy, or nothing would ever be allowed.
    daemon.registerAgent({
      agent: "superagent",
      permission: "xp2vr3",
      chain: CHAIN,
      policy: emptyPolicy("XPR", CHAIN_ID),
      policyVersion: 0,
      enabled: true,
      token: Buffer.from(TOKEN, "utf8"),
      key: KEY,
    });
    return daemon;
  }

  it("signs using the on-chain policy (not the registered placeholder)", async () => {
    const daemon = makeDaemon(new FakeReader(onchainRow(true)));
    const response = await daemon.handleRequest(request());
    // The registered policy denies all; only the cached on-chain policy allows.
    expect(response).toMatchObject({ status: "signed", policyVersion: 4 });
    expect(signer.calls).toBe(1);
  });

  it("refuses with POLICY_UNAVAILABLE when the chain policy cannot be confirmed", async () => {
    const reader = new FakeReader(onchainRow(true));
    reader.down = true;
    const daemon = makeDaemon(reader);
    const response = await daemon.handleRequest(request());
    expect(response).toMatchObject({ status: "denied", code: "POLICY_UNAVAILABLE" });
    expect(signer.calls).toBe(0);
  });

  it("honors an on-chain disable as a canonical kill-switch (§14.6)", async () => {
    const daemon = makeDaemon(new FakeReader(onchainRow(false)));
    const response = await daemon.handleRequest(request());
    expect(response).toMatchObject({ status: "denied", code: "AGENT_DISABLED" });
    expect(signer.calls).toBe(0);
  });

  it("refuses an unregistered-on-chain agent even if locally known", async () => {
    const daemon = makeDaemon(new FakeReader(null));
    const response = await daemon.handleRequest(request());
    expect(response).toMatchObject({ status: "denied", code: "POLICY_UNAVAILABLE" });
    expect(signer.calls).toBe(0);
  });
});
