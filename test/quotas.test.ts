import { describe, expect, it, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { QuotaJournal } from "../src/daemon/quotaJournal.js";
import { SignBoxDaemon, type AgentRuntime } from "../src/daemon/server.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { validatePolicy } from "../src/core/policy/schema.js";
import { parseAsset } from "../src/core/asset.js";
import type { QuotaDemand } from "../src/core/policy/engine.js";
import type {
  ChainContext,
  DecodedTransaction,
  KeyHandle,
  SignedTransactionResult,
  TransactionSigner,
} from "../src/core/types.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const CHAIN: ChainContext = { chain: "XPR", network: "testnet", chainId: CHAIN_ID };
const NOW = Date.parse("2026-07-29T12:00:00.000Z");
const HOUR = 3_600_000;

function demand(overrides?: Partial<QuotaDemand>): QuotaDemand {
  return {
    ruleId: "allow-small-xpr-tips",
    amount: parseAsset("1000.0000 XPR"),
    recipient: "alice",
    maxPerHour: parseAsset("2500.0000 XPR"),
    ...overrides,
  };
}

describe("QuotaJournal", () => {
  let journal: QuotaJournal;

  beforeEach(() => {
    journal = new QuotaJournal(":memory:");
  });

  it("reserves within the hourly cap and refuses beyond it", () => {
    expect(journal.reserve("superagent", [demand()], NOW).ok).toBe(true);
    expect(journal.reserve("superagent", [demand()], NOW).ok).toBe(true);
    // 2000 consumed, cap 2500: a third 1000 must refuse.
    const third = journal.reserve("superagent", [demand()], NOW);
    expect(third).toEqual({ ok: false, reason: "limit" });
  });

  it("lets the window slide: old events stop counting", () => {
    expect(journal.reserve("superagent", [demand()], NOW).ok).toBe(true);
    expect(journal.reserve("superagent", [demand()], NOW).ok).toBe(true);
    // One hour later the first two are out of the hourly window.
    const later = journal.reserve("superagent", [demand()], NOW + HOUR + 1);
    expect(later.ok).toBe(true);
  });

  it("enforces the daily cap independently", () => {
    const d = () =>
      demand({ maxPerHour: parseAsset("999999.0000 XPR"), maxPerDay: parseAsset("1500.0000 XPR") });
    expect(journal.reserve("superagent", [d()], NOW).ok).toBe(true);
    // Hourly would allow it; daily refuses.
    expect(journal.reserve("superagent", [d()], NOW + 2 * HOUR)).toEqual({
      ok: false,
      reason: "limit",
    });
  });

  it("enforces the per-recipient cooldown", () => {
    const d = () => demand({ cooldownPerRecipientMs: 60_000, maxPerHour: undefined });
    expect(journal.reserve("superagent", [d()], NOW).ok).toBe(true);
    expect(journal.reserve("superagent", [d()], NOW + 30_000)).toEqual({
      ok: false,
      reason: "cooldown",
    });
    // A different recipient is unaffected…
    expect(journal.reserve("superagent", [{ ...d(), recipient: "bob" }], NOW + 30_000).ok).toBe(
      true,
    );
    // …and the same recipient recovers after the window.
    expect(journal.reserve("superagent", [d()], NOW + 61_000).ok).toBe(true);
  });

  it("release returns the reserved capacity", () => {
    const first = journal.reserve("superagent", [demand()], NOW);
    const second = journal.reserve("superagent", [demand()], NOW);
    expect(first.ok && second.ok).toBe(true);
    expect(journal.reserve("superagent", [demand()], NOW).ok).toBe(false);
    if (second.ok) journal.release(second.reservationId);
    expect(journal.reserve("superagent", [demand()], NOW).ok).toBe(true);
  });

  it("commit is idempotent by digest: duplicates never double-count", () => {
    const a = journal.reserve("superagent", [demand()], NOW);
    const b = journal.reserve("superagent", [demand()], NOW);
    expect(a.ok && b.ok).toBe(true);
    if (a.ok) journal.commit(a.reservationId, "superagent", "d".repeat(64));
    if (b.ok) journal.commit(b.reservationId, "superagent", "d".repeat(64));
    // Only ONE of the two 1000 XPR commits counts: 1000 used, 2500 cap,
    // so a 1000 reservation still fits (it would not if both counted… it
    // would; 2000+1000>2500).
    expect(journal.consumed("superagent", "allow-small-xpr-tips", "XPR", 4, HOUR, NOW)).toBe(
      10_000_000n,
    );
  });

  it("multi-demand reservations are all-or-nothing", () => {
    const ok = demand();
    const over = demand({ amount: parseAsset("2000.0000 XPR") });
    // 1000 + 2000 > 2500: the whole reservation must fail…
    expect(journal.reserve("superagent", [ok, over], NOW)).toEqual({ ok: false, reason: "limit" });
    // …and the first demand must NOT have been persisted.
    expect(journal.consumed("superagent", "allow-small-xpr-tips", "XPR", 4, HOUR, NOW)).toBe(0n);
  });

  it("refuses caps in another symbol or precision as ambiguous", () => {
    const mismatched = demand({ maxPerHour: parseAsset("2500.000000 XUSDC") });
    expect(journal.reserve("superagent", [mismatched], NOW)).toEqual({
      ok: false,
      reason: "ambiguous",
    });
  });

  it("isolates agents and rules from each other", () => {
    expect(journal.reserve("superagent", [demand()], NOW).ok).toBe(true);
    expect(journal.reserve("superagent", [demand()], NOW).ok).toBe(true);
    expect(journal.reserve("otheragent", [demand()], NOW).ok).toBe(true);
    expect(journal.reserve("superagent", [demand({ ruleId: "other-rule" })], NOW).ok).toBe(true);
  });

  it("survives a close/reopen on a file-backed database (§8.5)", () => {
    const path = join(mkdtempSync(join(tmpdir(), "signbox-quota-")), "quota.db");
    const first = new QuotaJournal(path);
    expect(first.reserve("superagent", [demand()], NOW).ok).toBe(true);
    expect(first.reserve("superagent", [demand()], NOW).ok).toBe(true);
    first.close();
    const reopened = new QuotaJournal(path);
    expect(reopened.reserve("superagent", [demand()], NOW)).toEqual({
      ok: false,
      reason: "limit",
    });
    reopened.close();
  });
});

describe("daemon pipeline with quota journal", () => {
  const TOKEN = "tok_0123456789abcdefghij";
  const KEY: KeyHandle = {
    keyId: "k1",
    publicKey: "PUB_K1_test",
    exportPolicy: "non-exportable",
    chain: CHAIN,
    agent: "superagent",
    permission: "xp2vr3",
  };

  class CountingSigner implements TransactionSigner {
    calls = 0;
    failNext = false;
    async sign(_tx: DecodedTransaction, _key: KeyHandle): Promise<SignedTransactionResult> {
      this.calls += 1;
      if (this.failNext) {
        this.failNext = false;
        throw new Error("simulated signing failure");
      }
      return { signature: "SIG_K1_fake", transactionDigest: `${this.calls}`.padStart(64, "0") };
    }
  }

  function statefulPolicy() {
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
            "data.from": "$agent",
            "data.quantity.symbol": "XPR",
          },
          limits: {
            maxPerTransaction: "1000.0000 XPR",
            maxPerHour: "2500.0000 XPR",
            cooldownPerRecipientMs: 60_000,
          },
        },
      ],
    });
  }

  function makeRequest(n: number, to = "alice"): string {
    return JSON.stringify({
      requestId: `req-0000000${n}`,
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
            data: { from: "superagent", to, quantity: "1000.0000 XPR", memo: "" },
          },
        ],
      },
      requestedAt: new Date(NOW).toISOString(),
      expiresAt: new Date(NOW + 60_000).toISOString(),
      nonce: `nonce_${n}_abcdefghij0123456789`,
      token: TOKEN,
    });
  }

  let daemon: SignBoxDaemon;
  let signer: CountingSigner;

  beforeEach(() => {
    signer = new CountingSigner();
    daemon = new SignBoxDaemon(
      { socketPath: join(mkdtempSync(join(tmpdir(), "signbox-daemon-")), "signbox.sock") },
      {
        decode: decodeXprTransaction,
        signer,
        quotas: new QuotaJournal(":memory:"),
        now: () => NOW,
      },
    );
    daemon.registerAgent({
      agent: "superagent",
      permission: "xp2vr3",
      chain: CHAIN,
      policy: statefulPolicy(),
      policyVersion: 1,
      enabled: true,
      token: Buffer.from(TOKEN, "utf8"),
      key: KEY,
    } satisfies AgentRuntime);
  });

  it("signs under the cap, then refuses with LIMIT_EXCEEDED over it", async () => {
    expect((await daemon.handleRequest(makeRequest(1, "alice"))).status).toBe("signed");
    expect((await daemon.handleRequest(makeRequest(2, "bob"))).status).toBe("signed");
    // 2000 consumed, hourly cap 2500: the third 1000 refuses before signing.
    const third = await daemon.handleRequest(makeRequest(3, "carol"));
    expect(third).toMatchObject({ status: "denied", code: "LIMIT_EXCEEDED" });
    expect(signer.calls).toBe(2);
  });

  it("enforces the recipient cooldown through the pipeline", async () => {
    expect((await daemon.handleRequest(makeRequest(1, "alice"))).status).toBe("signed");
    const again = await daemon.handleRequest(makeRequest(2, "alice"));
    expect(again).toMatchObject({ status: "denied", code: "LIMIT_EXCEEDED" });
  });

  it("releases the reservation when signing fails — quota is not burned", async () => {
    signer.failNext = true;
    const failed = await daemon.handleRequest(makeRequest(1, "alice"));
    expect(failed).toMatchObject({ status: "denied", code: "INTERNAL_ERROR" });
    // The failed attempt must not have consumed quota or armed the cooldown.
    const retry = await daemon.handleRequest(makeRequest(2, "alice"));
    expect(retry.status).toBe("signed");
  });

  it("concurrent requests can never jointly exceed the cap (§15.6)", async () => {
    const results = await Promise.all(
      Array.from({ length: 6 }, (_, i) => daemon.handleRequest(makeRequest(i + 1, `user${i + 1}`))),
    );
    const signed = results.filter((r) => r.status === "signed").length;
    // Cap 2500, each 1000: at most 2 can ever be signed.
    expect(signed).toBe(2);
    expect(signer.calls).toBe(2);
  });
});
