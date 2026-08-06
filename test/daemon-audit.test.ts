import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignBoxDaemon } from "../src/daemon/server.js";
import { AuditLog } from "../src/daemon/auditLog.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { validatePolicy } from "../src/core/policy/schema.js";
import type {
  ChainContext,
  DecodedTransaction,
  KeyHandle,
  SignedTransactionResult,
  TransactionSigner,
} from "../src/core/types.js";
import { xprDialect } from "../src/chains/xpr/dialect.js";

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

class FakeSigner implements TransactionSigner {
  async sign(_tx: DecodedTransaction, _k: KeyHandle): Promise<SignedTransactionResult> {
    return { signature: "SIG_K1_fake", transactionDigest: "d".repeat(64) };
  }
}

function policy() {
  return validatePolicy({
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
  }, xprDialect);
}

function request(to = "alice"): string {
  return JSON.stringify({
    requestId: `req-${Math.random().toString(36).slice(2, 10)}`,
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
          data: { from: "superagent", to, quantity: "1.0000 XPR", memo: "" },
        },
      ],
    },
    requestedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 60_000).toISOString(),
    nonce: `nonce_${Math.random().toString(36).slice(2)}_0123456789`,
    token: TOKEN,
  });
}

function makeDaemon(): { daemon: SignBoxDaemon; audit: AuditLog } {
  const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "signbox-audit-")), "state.db"));
  const daemon = new SignBoxDaemon(
    { socketPath: join(mkdtempSync(join(tmpdir(), "signbox-daemon-")), "s.sock") },
    { dialect: xprDialect, decode: decodeXprTransaction, signer: new FakeSigner(), audit, now: () => NOW },
  );
  daemon.registerAgent({
    agent: "superagent",
    permission: "xp2vr3",
    chain: CHAIN,
    policy: policy(),
    policyVersion: 7,
    enabled: true,
    token: Buffer.from(TOKEN, "utf8"),
    key: KEY,
  });
  return { daemon, audit };
}

describe("daemon records every decision to the audit log (§16)", () => {
  it("records a signed decision with digest, rule and policy version", async () => {
    const { daemon, audit } = makeDaemon();
    await daemon.handleRequest(request());
    const [entry] = audit.tail(1);
    expect(entry).toMatchObject({
      agent: "superagent",
      decision: "signed",
      ruleIds: ["allow-transfer"],
      policyVersion: 7,
      digest: "d".repeat(64),
      contracts: ["eosio.token::transfer"],
    });
    audit.close();
  });

  it("records a denied decision with its code and the contracts seen", async () => {
    const { daemon, audit } = makeDaemon();
    // A wrong-contract transfer is denied by default.
    const req = JSON.parse(request());
    req.transaction.actions[0].account = "eviltoken";
    await daemon.handleRequest(JSON.stringify(req));
    const [entry] = audit.tail(1);
    expect(entry).toMatchObject({
      decision: "denied",
      code: "DEFAULT_DENY",
      contracts: ["eviltoken::transfer"],
    });
    expect(entry!.digest).toBeUndefined();
    audit.close();
  });

  it("records unauthenticated attempts without leaking the transaction", async () => {
    const { daemon, audit } = makeDaemon();
    const req = JSON.parse(request());
    req.token = "tok_wrongwrongwrongwrong";
    await daemon.handleRequest(JSON.stringify(req));
    const [entry] = audit.tail(1);
    expect(entry).toMatchObject({ decision: "denied", code: "UNAUTHENTICATED" });
    // Denied before decode → no contracts captured.
    expect(entry!.contracts).toEqual([]);
    audit.close();
  });

  it("keeps an intact, verifiable chain across mixed decisions", async () => {
    const { daemon, audit } = makeDaemon();
    await daemon.handleRequest(request("alice"));
    const bad = JSON.parse(request());
    bad.transaction.actions[0].account = "eviltoken";
    await daemon.handleRequest(JSON.stringify(bad));
    await daemon.handleRequest(request("bob"));
    expect(audit.verify()).toEqual({ ok: true, count: 3 });
    audit.close();
  });
});
