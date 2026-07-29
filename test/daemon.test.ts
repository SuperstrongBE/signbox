import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { connect } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignBoxDaemon, type AgentRuntime } from "../src/daemon/server.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { validatePolicy } from "../src/core/policy/schema.js";
import type {
  ChainContext,
  DecodedTransaction,
  KeyHandle,
  SignedTransactionResult,
  TransactionSigner,
} from "../src/core/types.js";
import type { SignResponseJson } from "../src/daemon/protocol.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const CHAIN: ChainContext = { chain: "XPR", network: "testnet", chainId: CHAIN_ID };
const TOKEN = "tok_0123456789abcdefghij";
const BASE_NOW = Date.parse("2026-07-29T12:00:00.000Z");

const KEY: KeyHandle = {
  keyId: "k1",
  publicKey: "PUB_K1_test",
  exportPolicy: "non-exportable",
  chain: CHAIN,
  agent: "superagent",
  permission: "xp2vr3",
};

function statelessPolicy() {
  return validatePolicy({
    schemaVersion: 1,
    default: "deny",
    chain: { name: "XPR", chainId: CHAIN_ID },
    rules: [
      {
        id: "allow-small-xpr-tips",
        effect: "allow",
        match: {
          contract: "eosio.token",
          action: "transfer",
          "authorization.actor": "$agent",
          "authorization.permission": "$agentPermission",
          "data.from": "$agent",
          "data.quantity.symbol": "XPR",
          "data.to": { notIn: ["blocked.gm"] },
        },
        limits: { maxPerTransaction: "1000.0000 XPR" },
      },
    ],
  });
}

function statefulPolicy() {
  const policy = statelessPolicy();
  policy.rules[0]!.limits = { maxPerTransaction: "1000.0000 XPR", maxPerHour: "2500.0000 XPR" };
  return policy;
}

class FakeSigner implements TransactionSigner {
  calls = 0;
  async sign(_tx: DecodedTransaction, _key: KeyHandle): Promise<SignedTransactionResult> {
    this.calls += 1;
    return {
      signature: "SIG_K1_fake",
      transactionDigest: "d".repeat(64),
      signedTransaction: { signatures: ["SIG_K1_fake"] },
    };
  }
}

function makeRequest(overrides?: Partial<Record<string, unknown>>): string {
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
          data: { from: "superagent", to: "alice", quantity: "10.0000 XPR", memo: "" },
        },
      ],
    },
    requestedAt: new Date(BASE_NOW).toISOString(),
    expiresAt: new Date(BASE_NOW + 60_000).toISOString(),
    nonce: `nonce_${Math.random().toString(36).slice(2)}_0123456789`,
    token: TOKEN,
    ...overrides,
  });
}

describe("SignBox daemon pipeline", () => {
  let daemon: SignBoxDaemon;
  let signer: FakeSigner;
  let nowMs: number;

  function agentRuntime(overrides?: Partial<AgentRuntime>): AgentRuntime {
    return {
      agent: "superagent",
      permission: "xp2vr3",
      chain: CHAIN,
      policy: statelessPolicy(),
      policyVersion: 7,
      enabled: true,
      token: Buffer.from(TOKEN, "utf8"),
      key: KEY,
      ...overrides,
    };
  }

  beforeEach(() => {
    signer = new FakeSigner();
    nowMs = BASE_NOW;
    daemon = new SignBoxDaemon(
      { socketPath: join(mkdtempSync(join(tmpdir(), "signbox-daemon-")), "signbox.sock") },
      {
        decode: (input, context) => decodeXprTransaction(input, context),
        signer,
        now: () => nowMs,
      },
    );
    daemon.registerAgent(agentRuntime());
  });

  it("signs a compliant transaction", async () => {
    const response = await daemon.handleRequest(makeRequest());
    expect(response).toMatchObject({
      status: "signed",
      signature: "SIG_K1_fake",
      policyVersion: 7,
    });
    expect(signer.calls).toBe(1);
  });

  it("denies with UNAUTHENTICATED on a wrong token — signer never called", async () => {
    const response = await daemon.handleRequest(makeRequest({ token: "tok_wrongwrongwrongwrong" }));
    expect(response).toMatchObject({ status: "denied", code: "UNAUTHENTICATED" });
    expect(signer.calls).toBe(0);
  });

  it("answers unknown agents and bad tokens identically (no agent enumeration)", async () => {
    const unknownAgent = await daemon.handleRequest(makeRequest({ agent: "ghost" }));
    const badToken = await daemon.handleRequest(makeRequest({ token: "tok_wrongwrongwrongwrong" }));
    expect((unknownAgent as { code: string }).code).toBe((badToken as { code: string }).code);
    expect((unknownAgent as { safeReason: string }).safeReason).toBe(
      (badToken as { safeReason: string }).safeReason,
    );
  });

  it("denies a replayed nonce (§15.7)", async () => {
    const nonce = "nonce_replay_0123456789abcdef";
    const first = await daemon.handleRequest(makeRequest({ nonce }));
    expect(first.status).toBe("signed");
    const second = await daemon.handleRequest(
      makeRequest({ nonce, requestId: "req-00000002" }),
    );
    expect(second).toMatchObject({ status: "denied", code: "NONCE_REUSED" });
    expect(signer.calls).toBe(1);
  });

  it("denies expired requests", async () => {
    nowMs = BASE_NOW + 120_000; // past expiresAt
    const response = await daemon.handleRequest(makeRequest());
    expect(response).toMatchObject({ status: "denied", code: "REQUEST_EXPIRED" });
  });

  it("denies requests with an excessive validity window", async () => {
    const response = await daemon.handleRequest(
      makeRequest({ expiresAt: new Date(BASE_NOW + 3_600_000).toISOString() }),
    );
    expect(response).toMatchObject({ status: "denied", code: "REQUEST_EXPIRED" });
  });

  it("kill-switch: disableAgent refuses immediately, enableAgent restores (§14.6)", async () => {
    daemon.disableAgent("superagent");
    const denied = await daemon.handleRequest(makeRequest());
    expect(denied).toMatchObject({ status: "denied", code: "AGENT_DISABLED" });
    daemon.enableAgent("superagent");
    const signed = await daemon.handleRequest(makeRequest({ requestId: "req-00000003" }));
    expect(signed.status).toBe("signed");
  });

  it("denies on chain mismatch (INV-013)", async () => {
    const response = await daemon.handleRequest(makeRequest({ network: "mainnet" }));
    expect(response).toMatchObject({ status: "denied", code: "CHAIN_MISMATCH" });
  });

  it("denies a policy-refused transaction — signer never called", async () => {
    const request = makeRequest();
    const parsed = JSON.parse(request);
    parsed.transaction.actions[0].data.to = "blocked.gm";
    const response = await daemon.handleRequest(JSON.stringify(parsed));
    expect(response).toMatchObject({ status: "denied", code: "DEFAULT_DENY", policyVersion: 7 });
    expect(signer.calls).toBe(0);
  });

  it("fails closed when the policy needs stateful quotas and no journal exists (§8.5)", async () => {
    const stateful = new SignBoxDaemon(
      { socketPath: join(mkdtempSync(join(tmpdir(), "signbox-daemon-")), "signbox.sock") },
      { decode: decodeXprTransaction, signer, now: () => nowMs },
    );
    stateful.registerAgent(agentRuntime({ policy: statefulPolicy() }));
    const response = await stateful.handleRequest(makeRequest());
    expect(response).toMatchObject({ status: "denied", code: "QUOTA_UNAVAILABLE" });
    expect(signer.calls).toBe(0);
  });

  it("denies malformed JSON with SCHEMA_INVALID", async () => {
    const response = await daemon.handleRequest("{not json");
    expect(response).toMatchObject({ status: "denied", code: "SCHEMA_INVALID" });
  });

  it("denies a packed-transaction attempt (string transaction) — INV-014", async () => {
    const response = await daemon.handleRequest(makeRequest({ transaction: "aabbcc001122" }));
    expect(response).toMatchObject({ status: "denied", code: "SCHEMA_INVALID" });
    expect(signer.calls).toBe(0);
  });

  it("denies unknown request fields", async () => {
    const response = await daemon.handleRequest(makeRequest({ packedTransaction: "aabb" }));
    expect(response).toMatchObject({ status: "denied", code: "SCHEMA_INVALID" });
  });

  it("no refused transaction ever reaches the signer (§17.2)", async () => {
    const refusals = [
      makeRequest({ token: "tok_wrongwrongwrongwrong" }),
      makeRequest({ network: "mainnet" }),
      makeRequest({ transaction: "deadbeef" }),
      "{broken",
    ];
    for (const line of refusals) {
      const response = await daemon.handleRequest(line);
      expect(response.status).toBe("denied");
    }
    expect(signer.calls).toBe(0);
  });
});

describe("SignBox daemon over a real Unix socket", () => {
  let daemon: SignBoxDaemon;
  let socketPath: string;
  let signer: FakeSigner;

  beforeEach(async () => {
    signer = new FakeSigner();
    socketPath = join(mkdtempSync(join(tmpdir(), "signbox-daemon-")), "signbox.sock");
    daemon = new SignBoxDaemon(
      { socketPath },
      { decode: decodeXprTransaction, signer, now: () => BASE_NOW },
    );
    daemon.registerAgent({
      agent: "superagent",
      permission: "xp2vr3",
      chain: CHAIN,
      policy: statelessPolicy(),
      policyVersion: 7,
      enabled: true,
      token: Buffer.from(TOKEN, "utf8"),
      key: KEY,
    });
    await daemon.start();
  });

  afterEach(async () => {
    await daemon.stop();
  });

  function roundTrip(line: string): Promise<SignResponseJson> {
    return new Promise((resolve, reject) => {
      const socket = connect(socketPath);
      let buffered = "";
      socket.setEncoding("utf8");
      socket.on("error", reject);
      socket.on("data", (chunk: string) => {
        buffered += chunk;
        const idx = buffered.indexOf("\n");
        if (idx !== -1) {
          socket.end();
          resolve(JSON.parse(buffered.slice(0, idx)) as SignResponseJson);
        }
      });
      socket.write(line + "\n");
    });
  }

  it("signs end-to-end over the socket", async () => {
    const response = await roundTrip(makeRequest());
    expect(response).toMatchObject({ status: "signed", signature: "SIG_K1_fake" });
  });

  it("destroys the connection on oversized input (fail closed)", async () => {
    const closed = new Promise<boolean>((resolve) => {
      const socket = connect(socketPath);
      socket.on("close", () => resolve(true));
      socket.on("error", () => resolve(true));
      socket.write("x".repeat(80 * 1024));
    });
    await expect(closed).resolves.toBe(true);
    expect(signer.calls).toBe(0);
  });

  it("refuses to start on an existing socket path", async () => {
    const second = new SignBoxDaemon(
      { socketPath },
      { decode: decodeXprTransaction, signer, now: () => BASE_NOW },
    );
    await expect(second.start()).rejects.toThrow();
  });
});
