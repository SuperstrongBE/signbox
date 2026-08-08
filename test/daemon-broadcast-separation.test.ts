/**
 * Sign / broadcast separation (#42).
 *
 * Signing and broadcasting are INDEPENDENT capabilities:
 *  - a sign-only agent can never trigger a network submission (no fused
 *    broadcast, and the standalone broadcast op is refused) — and it is never
 *    silently signed or silently submitted instead (no capability up/down-grade);
 *  - the standalone broadcast op submits already-signed bytes and can NEVER
 *    reach the signer (a broadcast-only principal cannot obtain a signature);
 *  - broadcasting can be disabled entirely (no broadcaster wired → refused);
 *  - the audit log distinguishes signed / denied / broadcast and the
 *    accepted / rejected / ambiguous submission outcomes.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JsonRpc } from "@proton/js";
import {
  SignBoxDaemon,
  type AgentCapabilities,
  type AgentRuntime,
  type DaemonDependencies,
} from "../src/daemon/server.js";
import { QuotaJournal } from "../src/daemon/quotaJournal.js";
import { AuditLog } from "../src/daemon/auditLog.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { validatePolicy } from "../src/core/policy/schema.js";
import { XprTransactionBroadcaster } from "../src/chains/xpr/broadcaster.js";
import type { BroadcastOutcome, TransactionBroadcaster } from "../src/daemon/broadcaster.js";
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
const NOW = Date.parse("2026-07-29T12:00:00.000Z");

const KEY: KeyHandle = {
  keyId: "k1",
  publicKey: "PUB_K1_test",
  exportPolicy: "non-exportable",
  chain: CHAIN,
  agent: "superagent",
  permission: "active",
};

/** The opaque signed blob every path shuttles around (never re-signed). */
const SIGNED = { signatures: ["SIG_K1_fake"], packedTransaction: "aabb", compression: 0 };

/** A simple allow rule with NO limits → a sign that reserves no quota. */
function allowPolicy() {
  return validatePolicy(
    {
      schemaVersion: 1,
      default: "deny",
      chain: { name: "XPR", chainId: CHAIN_ID },
      rules: [
        {
          id: "allow-transfer",
          effect: "allow",
          match: {
            contract: "eosio.token",
            action: "transfer",
            "authorization.actor": "$agent",
            "data.from": "$agent",
          },
        },
      ],
    },
    xprDialect,
  );
}

/** Counts sign() calls so tests can prove the broadcast path never signs. */
class CountingSigner implements TransactionSigner {
  calls = 0;
  async sign(_tx: DecodedTransaction, _key: KeyHandle): Promise<SignedTransactionResult> {
    this.calls += 1;
    return {
      signature: "SIG_K1_fake",
      transactionDigest: "d".repeat(64),
      signedTransaction: SIGNED,
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

function build(opts: {
  capabilities?: AgentCapabilities;
  withBroadcaster?: boolean;
  outcome?: BroadcastOutcome;
}): { daemon: SignBoxDaemon; signer: CountingSigner; broadcaster: FakeBroadcaster | undefined; audit: AuditLog } {
  const dir = mkdtempSync(join(tmpdir(), "signbox-sep-"));
  const quotas = new QuotaJournal(join(dir, "state.db"));
  const audit = new AuditLog(join(dir, "audit.db"));
  const signer = new CountingSigner();
  const broadcaster =
    opts.withBroadcaster === false
      ? undefined
      : new FakeBroadcaster(opts.outcome ?? { status: "accepted", receipt: { transaction_id: "abc123" } });

  const deps: DaemonDependencies = {
    dialect: xprDialect,
    decode: decodeXprTransaction,
    signer,
    quotas,
    audit,
    now: () => NOW,
  };
  if (broadcaster !== undefined) deps.broadcaster = broadcaster;

  const daemon = new SignBoxDaemon({ socketPath: join(dir, "signbox.sock") }, deps);
  const runtime: AgentRuntime = {
    agent: "superagent",
    permission: "active",
    chain: CHAIN,
    policy: allowPolicy(),
    policyVersion: 1,
    enabled: true,
    token: Buffer.from(TOKEN, "utf8"),
    key: KEY,
  };
  if (opts.capabilities !== undefined) runtime.capabilities = opts.capabilities;
  daemon.registerAgent(runtime);
  return { daemon, signer, broadcaster, audit };
}

const nonce = (): string => `nonce_${Math.random().toString(36).slice(2)}_0123456789`;

function signReq(broadcast: boolean, over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    requestId: "req-sign-0001",
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
    nonce: nonce(),
    token: TOKEN,
    ...over,
  });
}

function bcastReq(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    op: "broadcast",
    requestId: "req-bcast-001",
    agent: "superagent",
    chain: "XPR",
    network: "testnet",
    chainId: CHAIN_ID,
    signedTransaction: SIGNED,
    requestedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 60_000).toISOString(),
    nonce: nonce(),
    token: TOKEN,
    ...over,
  });
}

describe("capability separation on the sign path (#42)", () => {
  it("a sign-only agent CANNOT broadcast — denied, nothing signed or sent", async () => {
    const { daemon, signer, broadcaster } = build({ capabilities: { sign: true, broadcast: false } });
    const res = await daemon.handleRequest(signReq(true));
    expect(res).toMatchObject({ status: "denied", code: "CAPABILITY_DENIED" });
    // Denied BEFORE any signing or submission — no silent sign-instead-of-broadcast.
    expect(signer.calls).toBe(0);
    expect(broadcaster?.calls).toBe(0);
    expect((res as { signature?: unknown }).signature).toBeUndefined();
  });

  it("a sign-only agent CAN sign (broadcast:false) — signature returned, nothing submitted", async () => {
    const { daemon, signer, broadcaster } = build({ capabilities: { sign: true, broadcast: false } });
    const res = await daemon.handleRequest(signReq(false));
    expect(res).toMatchObject({ status: "signed" });
    expect(signer.calls).toBe(1);
    expect(broadcaster?.calls).toBe(0);
    expect((res as { signedTransaction?: unknown }).signedTransaction).toBeDefined();
  });

  it("broadcast requested with the capability but broadcasting disabled → BROADCAST_UNAVAILABLE, not signed", async () => {
    const { daemon, signer } = build({ capabilities: { sign: true, broadcast: true }, withBroadcaster: false });
    const res = await daemon.handleRequest(signReq(true));
    expect(res).toMatchObject({ status: "denied", code: "BROADCAST_UNAVAILABLE" });
    expect(signer.calls).toBe(0); // refused before signing — no signature to leak
  });

  it("an agent without the sign capability is denied on the sign path", async () => {
    const { daemon, signer } = build({ capabilities: { sign: false, broadcast: true } });
    const res = await daemon.handleRequest(signReq(false));
    expect(res).toMatchObject({ status: "denied", code: "CAPABILITY_DENIED" });
    expect(signer.calls).toBe(0);
  });

  it("omitting capabilities defaults to sign-only (broadcast refused)", async () => {
    const { daemon, broadcaster } = build({}); // no capabilities
    expect(await daemon.handleRequest(signReq(false))).toMatchObject({ status: "signed" });
    expect(await daemon.handleRequest(signReq(true))).toMatchObject({
      status: "denied",
      code: "CAPABILITY_DENIED",
    });
    expect(broadcaster?.calls).toBe(0);
  });
});

describe("standalone broadcast op (#42)", () => {
  it("submits an already-signed tx WITHOUT ever reaching the signer", async () => {
    const { daemon, signer, broadcaster } = build({ capabilities: { sign: true, broadcast: true } });
    const res = await daemon.handleRequest(bcastReq());
    expect(res).toMatchObject({ status: "broadcast", report: { status: "accepted", quota: "none" } });
    expect(signer.calls).toBe(0); // the broadcast path can never sign
    expect(broadcaster?.calls).toBe(1);
    expect(broadcaster?.lastSigned).toEqual(SIGNED);
  });

  it("a broadcast-only principal (no sign capability) can still broadcast", async () => {
    const { daemon, signer } = build({ capabilities: { sign: false, broadcast: true } });
    expect(await daemon.handleRequest(bcastReq())).toMatchObject({ status: "broadcast" });
    expect(signer.calls).toBe(0);
  });

  it("without the broadcast capability the standalone op is denied — nothing submitted", async () => {
    const { daemon, broadcaster } = build({ capabilities: { sign: true, broadcast: false } });
    const res = await daemon.handleRequest(bcastReq());
    expect(res).toMatchObject({ status: "denied", code: "CAPABILITY_DENIED" });
    expect(broadcaster?.calls).toBe(0);
  });

  it("with broadcasting disabled the standalone op is denied BROADCAST_UNAVAILABLE", async () => {
    const { daemon } = build({ capabilities: { sign: true, broadcast: true }, withBroadcaster: false });
    expect(await daemon.handleRequest(bcastReq())).toMatchObject({
      status: "denied",
      code: "BROADCAST_UNAVAILABLE",
    });
  });

  it("reports rejected and ambiguous outcomes, always with quota 'none'", async () => {
    const rejected = build({
      capabilities: { sign: true, broadcast: true },
      outcome: { status: "rejected", reason: "eosio_assert" },
    });
    expect(await rejected.daemon.handleRequest(bcastReq())).toMatchObject({
      status: "broadcast",
      report: { status: "rejected", reason: "eosio_assert", quota: "none" },
    });

    const ambiguous = build({
      capabilities: { sign: true, broadcast: true },
      outcome: { status: "ambiguous", reason: "socket timeout" },
    });
    expect(await ambiguous.daemon.handleRequest(bcastReq())).toMatchObject({
      status: "broadcast",
      report: { status: "ambiguous", reason: "socket timeout", quota: "none" },
    });
  });

  it("refuses a bad token, a wrong chain, an expired window, and a replayed nonce", async () => {
    const { daemon } = build({ capabilities: { sign: true, broadcast: true } });
    expect(await daemon.handleRequest(bcastReq({ token: "tok_wrongwrongwrongwrong" }))).toMatchObject({
      status: "denied",
      code: "UNAUTHENTICATED",
    });
    expect(await daemon.handleRequest(bcastReq({ chainId: "b".repeat(64) }))).toMatchObject({
      status: "denied",
      code: "CHAIN_MISMATCH",
    });
    expect(
      await daemon.handleRequest(
        bcastReq({ requestedAt: new Date(NOW - 120_000).toISOString(), expiresAt: new Date(NOW - 60_000).toISOString() }),
      ),
    ).toMatchObject({ status: "denied", code: "REQUEST_EXPIRED" });

    const fixed = nonce();
    expect(await daemon.handleRequest(bcastReq({ nonce: fixed }))).toMatchObject({ status: "broadcast" });
    expect(await daemon.handleRequest(bcastReq({ nonce: fixed }))).toMatchObject({
      status: "denied",
      code: "NONCE_REUSED",
    });
  });
});

describe("audit distinguishes the outcomes (#42)", () => {
  it("fused sign+broadcast → decision 'signed' with broadcast 'accepted'", async () => {
    const { daemon, audit } = build({ capabilities: { sign: true, broadcast: true } });
    await daemon.handleRequest(signReq(true));
    const [entry] = audit.tail(1);
    expect(entry).toMatchObject({ decision: "signed", broadcast: "accepted" });
    expect(audit.verify().ok).toBe(true);
  });

  it("standalone broadcast → decision 'broadcast' with the submission outcome", async () => {
    const { daemon, audit } = build({
      capabilities: { sign: true, broadcast: true },
      outcome: { status: "rejected", reason: "eosio_assert" },
    });
    await daemon.handleRequest(bcastReq());
    const [entry] = audit.tail(1);
    expect(entry).toMatchObject({ decision: "broadcast", broadcast: "rejected", contracts: [] });
  });

  it("a capability denial is audited as 'denied' with the code", async () => {
    const { daemon, audit } = build({ capabilities: { sign: true, broadcast: false } });
    await daemon.handleRequest(bcastReq());
    const [entry] = audit.tail(1);
    expect(entry).toMatchObject({ decision: "denied", code: "CAPABILITY_DENIED" });
  });

  it("a plain sign carries NO broadcast field, and a mixed chain still verifies (backward-compatible hash)", async () => {
    const { daemon, audit } = build({ capabilities: { sign: true, broadcast: true } });
    await daemon.handleRequest(signReq(false)); // plain sign — no broadcast field
    await daemon.handleRequest(signReq(true)); // fused — broadcast field present
    await daemon.handleRequest(bcastReq()); // standalone broadcast
    const entries = audit.tail(3);
    const plain = entries.find((e) => e.decision === "signed" && e.broadcast === undefined);
    expect(plain).toBeDefined();
    // Mixing entries with and without the field must not break the chain.
    expect(audit.verify()).toMatchObject({ ok: true });
  });
});

describe("XPR broadcaster classifies a duplicate as accepted (it landed) (#42)", () => {
  let restore: (() => void) | undefined;
  afterEach(() => {
    restore?.();
    restore = undefined;
  });

  function stubFetch(pushHandler: () => never): void {
    const proto = JsonRpc.prototype as unknown as Record<string, unknown>;
    const saved = proto["fetch"];
    const head = new Date(Date.now() - 500).toISOString().replace("Z", "");
    proto["fetch"] = async (path: string) => {
      if (path === "/v1/chain/get_info") return { chain_id: CHAIN_ID, head_block_time: head };
      if (path === "/v1/chain/push_transaction") return pushHandler();
      return {};
    };
    restore = () => {
      proto["fetch"] = saved;
    };
  }

  const broadcaster = () => new XprTransactionBroadcaster({ endpoints: ["http://127.0.0.1:1"], chainId: CHAIN_ID });

  it("a duplicate_transaction is idempotent success → accepted", async () => {
    stubFetch(() => {
      const e = new Error("duplicate");
      (e as { json?: unknown }).json = { error: { code: 3040008, name: "tx_duplicate_exception", what: "duplicate" } };
      throw e;
    });
    const out = await broadcaster().broadcast(SIGNED);
    expect(out.status).toBe("accepted");
  });

  it("a deterministic node error → rejected; a bare transport error → ambiguous", async () => {
    stubFetch(() => {
      const e = new Error("assertion failure");
      (e as { json?: unknown }).json = { error: { code: 3050003, what: "eosio_assert_message assertion failure" } };
      throw e;
    });
    expect((await broadcaster().broadcast(SIGNED)).status).toBe("rejected");

    stubFetch(() => {
      throw new Error("socket hang up"); // no .json → transport failure
    });
    expect((await broadcaster().broadcast(SIGNED)).status).toBe("ambiguous");
  });
});
