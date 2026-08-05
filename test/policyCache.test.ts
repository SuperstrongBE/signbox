import { beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PolicyCache } from "../src/daemon/policyCache.js";
import { canonicalize } from "../src/core/canonical/jcs.js";
import type { PolicyReader, PolicyRowRaw } from "../src/daemon/chainPolicyReader.js";
import { xprDialect } from "../src/chains/xpr/dialect.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const NOW = Date.parse("2026-07-30T12:00:00.000Z");

function policyDoc(opts?: { financial?: boolean; extraRuleId?: string }) {
  const rule: Record<string, unknown> = {
    id: opts?.extraRuleId ?? "allow-transfer",
    effect: "allow",
    match: { contract: "eosio.token", action: "transfer", "data.from": "$agent" },
  };
  if (opts?.financial) rule["limits"] = { maxPerTransaction: "100.0000 XPR" };
  return {
    schemaVersion: 1,
    default: "deny",
    chain: { name: "XPR", chainId: CHAIN_ID },
    rules: [rule],
  };
}

/** Build a raw row with a correct canonical json + matching hash. */
function rowFor(agent: string, version: number, opts?: { financial?: boolean; enabled?: boolean }): PolicyRowRaw {
  const canonical = canonicalize(policyDoc({ financial: opts?.financial ?? false }));
  const hash = createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("hex");
  return {
    agent,
    authority: "superdev",
    agentperm: "xp2vr3",
    version,
    policyhash: hash,
    policyjson: canonical,
    enabled: opts?.enabled ?? true,
    updatedat: NOW,
  };
}

class FakeReader implements PolicyReader {
  row: PolicyRowRaw | null;
  reads = 0;
  throwNext = false;
  constructor(row: PolicyRowRaw | null) {
    this.row = row;
  }
  async read(agent: string): Promise<PolicyRowRaw | null> {
    this.reads += 1;
    if (this.throwNext) {
      this.throwNext = false;
      throw new Error("rpc unreachable");
    }
    return this.row !== null && this.row.agent === agent ? this.row : null;
  }
}

function dbPath(): string {
  return join(mkdtempSync(join(tmpdir(), "signbox-cache-")), "cache.db");
}

describe("PolicyCache — validation", () => {
  it("fetches, validates and returns a policy", async () => {
    const reader = new FakeReader(rowFor("superagent", 5));
    const cache = new PolicyCache(":memory:", reader, xprDialect, {}, () => NOW);
    const result = await cache.get("superagent", NOW);
    expect("unavailable" in result).toBe(false);
    if (!("unavailable" in result)) {
      expect(result.version).toBe(5);
      expect(result.enabled).toBe(true);
      expect(result.policy.rules[0]!.id).toBe("allow-transfer");
    }
    cache.close();
  });

  it("refuses a hash that does not match the json", async () => {
    const row = rowFor("superagent", 1);
    row.policyhash = "b".repeat(64);
    const cache = new PolicyCache(":memory:", new FakeReader(row), {}, () => NOW);
    expect(await cache.get("superagent", NOW)).toEqual({ unavailable: "POLICY_UNAVAILABLE" });
    cache.close();
  });

  it("refuses non-canonical json even if the hash matches its bytes", async () => {
    // Whitespace-formatted json: hash matches these bytes, but it is not JCS.
    const doc = policyDoc();
    const nonCanonical = JSON.stringify(doc, null, 2);
    const row = rowFor("superagent", 1);
    row.policyjson = nonCanonical;
    row.policyhash = createHash("sha256").update(Buffer.from(nonCanonical, "utf8")).digest("hex");
    const cache = new PolicyCache(":memory:", new FakeReader(row), {}, () => NOW);
    expect(await cache.get("superagent", NOW)).toEqual({ unavailable: "POLICY_UNAVAILABLE" });
    cache.close();
  });

  it("refuses a schema-invalid policy", async () => {
    const badDoc = { schemaVersion: 1, default: "allow", chain: { name: "XPR", chainId: CHAIN_ID }, rules: [] };
    const canonical = canonicalize(badDoc);
    const row: PolicyRowRaw = {
      agent: "superagent",
      authority: "superdev",
      agentperm: "xp2vr3",
      version: 1,
      policyhash: createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("hex"),
      policyjson: canonical,
      enabled: true,
      updatedat: NOW,
    };
    const cache = new PolicyCache(":memory:", new FakeReader(row), {}, () => NOW);
    expect(await cache.get("superagent", NOW)).toEqual({ unavailable: "POLICY_UNAVAILABLE" });
    cache.close();
  });

  it("refuses an unregistered agent", async () => {
    const cache = new PolicyCache(":memory:", new FakeReader(null), {}, () => NOW);
    expect(await cache.get("ghost", NOW)).toEqual({ unavailable: "POLICY_UNAVAILABLE" });
    cache.close();
  });

  it("fails closed when the RPC is unreachable (strict default)", async () => {
    const reader = new FakeReader(rowFor("superagent", 1));
    reader.throwNext = true;
    const cache = new PolicyCache(":memory:", reader, xprDialect, {}, () => NOW);
    expect(await cache.get("superagent", NOW)).toEqual({ unavailable: "POLICY_UNAVAILABLE" });
    cache.close();
  });
});

describe("PolicyCache — anti-rollback (§14.5)", () => {
  it("refuses a version below the highest ever seen", async () => {
    const reader = new FakeReader(rowFor("superagent", 7));
    const cache = new PolicyCache(":memory:", reader, xprDialect, {}, () => NOW);
    expect("unavailable" in (await cache.get("superagent", NOW))).toBe(false);

    // A lying RPC now serves an older, more permissive version.
    reader.row = rowFor("superagent", 6);
    const later = await cache.get("superagent", NOW + 60_000);
    expect(later).toEqual({ unavailable: "POLICY_UNAVAILABLE" });
    cache.close();
  });

  it("persists the watermark across a restart (same db file)", async () => {
    const path = dbPath();
    const reader = new FakeReader(rowFor("superagent", 9));
    const first = new PolicyCache(path, reader, xprDialect, {}, () => NOW);
    await first.get("superagent", NOW);
    first.close();

    // New cache instance, same file; RPC tries to downgrade.
    const reader2 = new FakeReader(rowFor("superagent", 8));
    const second = new PolicyCache(path, reader2, xprDialect, {}, () => NOW + 60_000);
    expect(await second.get("superagent", NOW + 60_000)).toEqual({
      unavailable: "POLICY_UNAVAILABLE",
    });
    second.close();
  });

  it("accepts an equal or higher version", async () => {
    const reader = new FakeReader(rowFor("superagent", 3));
    const cache = new PolicyCache(":memory:", reader, xprDialect, {}, () => NOW);
    await cache.get("superagent", NOW);
    reader.row = rowFor("superagent", 4);
    const next = await cache.get("superagent", NOW + 60_000);
    expect("unavailable" in next).toBe(false);
    if (!("unavailable" in next)) expect(next.version).toBe(4);
    cache.close();
  });
});

describe("PolicyCache — freshness (30s / 10s)", () => {
  it("does not re-fetch a fresh non-financial policy within 30s", async () => {
    const reader = new FakeReader(rowFor("superagent", 1, { financial: false }));
    const cache = new PolicyCache(":memory:", reader, xprDialect, {}, () => NOW);
    await cache.get("superagent", NOW);
    await cache.get("superagent", NOW + 20_000); // < 30s
    expect(reader.reads).toBe(1);
    cache.close();
  });

  it("re-fetches a non-financial policy after 30s", async () => {
    const reader = new FakeReader(rowFor("superagent", 1, { financial: false }));
    const cache = new PolicyCache(":memory:", reader, xprDialect, {}, () => NOW);
    await cache.get("superagent", NOW);
    await cache.get("superagent", NOW + 31_000);
    expect(reader.reads).toBe(2);
    cache.close();
  });

  it("re-confirms a financial policy after 10s (tighter freshness)", async () => {
    const reader = new FakeReader(rowFor("superagent", 1, { financial: true }));
    const cache = new PolicyCache(":memory:", reader, xprDialect, {}, () => NOW);
    await cache.get("superagent", NOW);
    await cache.get("superagent", NOW + 9_000); // < 10s: no refetch
    expect(reader.reads).toBe(1);
    await cache.get("superagent", NOW + 11_000); // > 10s: refetch
    expect(reader.reads).toBe(2);
    cache.close();
  });

  it("controlled grace serves the last-good policy when strict is off", async () => {
    const reader = new FakeReader(rowFor("superagent", 1));
    const cache = new PolicyCache(
      ":memory:", reader, xprDialect, { strict: false, graceMs: 60_000 },
      () => NOW,
    );
    await cache.get("superagent", NOW);
    reader.throwNext = true;
    const graced = await cache.get("superagent", NOW + 40_000); // stale, RPC down, within grace
    expect("unavailable" in graced).toBe(false);
    cache.close();
  });
});

describe("PolicyCache — enabled flag", () => {
  it("propagates the on-chain enabled flag", async () => {
    const reader = new FakeReader(rowFor("superagent", 1, { enabled: false }));
    const cache = new PolicyCache(":memory:", reader, xprDialect, {}, () => NOW);
    const result = await cache.get("superagent", NOW);
    expect("unavailable" in result).toBe(false);
    if (!("unavailable" in result)) expect(result.enabled).toBe(false);
    cache.close();
  });
});
