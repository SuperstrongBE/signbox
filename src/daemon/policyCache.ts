/**
 * On-chain policy cache with anti-rollback (spec §14).
 *
 * The contract is the source of truth (§14.1); this cache avoids one RPC read
 * per signature (§14.2) while never being authoritative on its own (§15.2).
 * It is backed by SQLite so the anti-rollback watermark and last-good policy
 * survive restarts.
 *
 * Freshness (project decision):
 * - background refresh every 30 s bounds staleness in the happy path;
 * - a financial policy (any allow rule carrying value limits) is re-confirmed
 *   synchronously before signing if the cache is older than 10 s;
 * - strict mode (default) refuses when the policy cannot be confirmed (§14.4);
 * - anti-rollback: a version lower than the highest ever seen for an agent is
 *   refused — a lying RPC or a restored cache can never silently downgrade to
 *   a more permissive policy (§14.5).
 *
 * Every failure resolves to POLICY_UNAVAILABLE (fail closed, INV-010); the
 * reason is never leaked to the caller.
 */

import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { canonicalize } from "../core/canonical/jcs.js";
import { validatePolicy, type Policy } from "../core/policy/schema.js";
import type { PolicyReader } from "./chainPolicyReader.js";

export interface CachedPolicy {
  policy: Policy;
  version: number;
  /** On-chain enabled flag (distinct from the local kill-switch). */
  enabled: boolean;
  isFinancial: boolean;
  verifiedAtMs: number;
}

export type PolicyUnavailable = { unavailable: "POLICY_UNAVAILABLE" };

export interface PolicyCacheOptions {
  /** Background refresh cadence. */
  refreshIntervalMs?: number;
  /** Synchronous re-confirm threshold for financial policies. */
  financialFreshnessMs?: number;
  /** Staleness tolerated for non-financial policies before a sync refresh. */
  nonFinancialFreshnessMs?: number;
  /** Strict mode refuses when a policy cannot be confirmed (default true). */
  strict?: boolean;
  /** Controlled-grace window used ONLY when strict === false (§14.4). */
  graceMs?: number;
  /** Label recorded as the cache source endpoint. */
  source?: string;
}

const DEFAULTS = {
  refreshIntervalMs: 30_000,
  financialFreshnessMs: 10_000,
  nonFinancialFreshnessMs: 30_000,
  strict: true,
  graceMs: 0,
  source: "chain",
} as const;

type RefreshResult =
  | { ok: true }
  | {
      ok: false;
      reason: "unreachable" | "not_registered" | "hash_mismatch" | "not_canonical" | "invalid_json" | "schema_invalid" | "rollback";
    };

interface CacheRow {
  agent: string;
  version: number;
  policyjson: string;
  enabled: number;
  is_financial: number;
  verified_at_ms: number;
  highest_seen_version: number;
}

export class PolicyCache {
  private readonly db: Database.Database;
  private readonly opts: Required<PolicyCacheOptions>;
  private readonly memory = new Map<string, CachedPolicy>();
  private timer: NodeJS.Timeout | undefined;

  constructor(
    dbPath: string,
    private readonly reader: PolicyReader,
    options: PolicyCacheOptions = {},
    private readonly now: () => number = Date.now,
  ) {
    this.opts = { ...DEFAULTS, ...options };
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS policy_cache (
        agent TEXT PRIMARY KEY,
        authority TEXT NOT NULL,
        permission TEXT NOT NULL,
        version INTEGER NOT NULL,
        policyhash TEXT NOT NULL,
        policyjson TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        is_financial INTEGER NOT NULL,
        verified_at_ms INTEGER NOT NULL,
        source TEXT NOT NULL,
        highest_seen_version INTEGER NOT NULL
      );
    `);
  }

  close(): void {
    this.stopBackgroundRefresh();
    this.db.close();
  }

  /** Highest version ever accepted for an agent (persisted anti-rollback watermark). */
  private highestSeen(agent: string): number {
    const row = this.db
      .prepare(`SELECT highest_seen_version AS v FROM policy_cache WHERE agent = ?`)
      .get(agent) as { v: number } | undefined;
    return row?.v ?? 0;
  }

  /**
   * Fetch, validate and store the current policy for an agent. Returns a
   * structured result; the caller maps any failure to POLICY_UNAVAILABLE.
   */
  async refresh(agent: string): Promise<RefreshResult> {
    let raw;
    try {
      raw = await this.reader.read(agent);
    } catch {
      return { ok: false, reason: "unreachable" };
    }
    if (raw === null) return { ok: false, reason: "not_registered" };

    // Integrity: sha256 of the stored bytes must equal the stored hash — the
    // same invariant the contract enforces on-chain (§8.6).
    const computed = createHash("sha256").update(Buffer.from(raw.policyjson, "utf8")).digest("hex");
    if (computed !== raw.policyhash) return { ok: false, reason: "hash_mismatch" };

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.policyjson);
    } catch {
      return { ok: false, reason: "invalid_json" };
    }
    // Canonicalization correctness: the stored bytes must BE the canonical
    // form, not merely hash to it (§8.6).
    if (canonicalize(parsed) !== raw.policyjson) return { ok: false, reason: "not_canonical" };

    let policy: Policy;
    try {
      policy = validatePolicy(parsed);
    } catch {
      return { ok: false, reason: "schema_invalid" };
    }

    // Anti-rollback: never accept a version below the highest ever seen (§14.5).
    const highest = this.highestSeen(agent);
    if (raw.version < highest) return { ok: false, reason: "rollback" };

    const isFinancial = policy.rules.some((r) => r.effect === "allow" && r.limits !== undefined);
    const verifiedAtMs = this.now();

    this.db
      .prepare(
        `INSERT INTO policy_cache
           (agent, authority, permission, version, policyhash, policyjson, enabled,
            is_financial, verified_at_ms, source, highest_seen_version)
         VALUES (@agent, @authority, @permission, @version, @policyhash, @policyjson, @enabled,
            @is_financial, @verified_at_ms, @source, @highest_seen)
         ON CONFLICT(agent) DO UPDATE SET
            authority=@authority, permission=@permission, version=@version,
            policyhash=@policyhash, policyjson=@policyjson, enabled=@enabled,
            is_financial=@is_financial, verified_at_ms=@verified_at_ms, source=@source,
            highest_seen_version=MAX(highest_seen_version, @highest_seen)`,
      )
      .run({
        agent,
        authority: raw.authority,
        permission: raw.agentperm,
        version: raw.version,
        policyhash: raw.policyhash,
        policyjson: raw.policyjson,
        enabled: raw.enabled ? 1 : 0,
        is_financial: isFinancial ? 1 : 0,
        verified_at_ms: verifiedAtMs,
        source: this.opts.source,
        highest_seen: raw.version,
      });

    this.memory.set(agent, { policy, version: raw.version, enabled: raw.enabled, isFinancial, verifiedAtMs });
    return { ok: true };
  }

  /** Load a cached policy into memory from SQLite (after a restart). */
  private hydrate(agent: string): CachedPolicy | undefined {
    const row = this.db
      .prepare(
        `SELECT agent, version, policyjson, enabled, is_financial, verified_at_ms, highest_seen_version
         FROM policy_cache WHERE agent = ?`,
      )
      .get(agent) as CacheRow | undefined;
    if (row === undefined) return undefined;
    let policy: Policy;
    try {
      policy = validatePolicy(JSON.parse(row.policyjson));
    } catch {
      return undefined;
    }
    const cached: CachedPolicy = {
      policy,
      version: row.version,
      enabled: row.enabled === 1,
      isFinancial: row.is_financial === 1,
      verifiedAtMs: row.verified_at_ms,
    };
    this.memory.set(agent, cached);
    return cached;
  }

  /**
   * Return the active policy for an agent, honoring freshness and strict mode.
   * Re-fetches synchronously when the cache is stale for the policy's class.
   */
  async get(agent: string, nowMs: number): Promise<CachedPolicy | PolicyUnavailable> {
    let cached = this.memory.get(agent) ?? this.hydrate(agent);
    const freshnessMs = cached?.isFinancial
      ? this.opts.financialFreshnessMs
      : this.opts.nonFinancialFreshnessMs;
    const stale = cached === undefined || nowMs - cached.verifiedAtMs > freshnessMs;

    if (stale) {
      const result = await this.refresh(agent);
      if (!result.ok) {
        // Controlled grace (§14.4) — never the default.
        if (
          cached !== undefined &&
          !this.opts.strict &&
          nowMs - cached.verifiedAtMs <= this.opts.graceMs
        ) {
          return cached;
        }
        return { unavailable: "POLICY_UNAVAILABLE" };
      }
      cached = this.memory.get(agent);
    }

    if (cached === undefined) return { unavailable: "POLICY_UNAVAILABLE" };
    return cached;
  }

  /** Refresh cadence (§14.3). Errors are swallowed; get() re-confirms per policy. */
  startBackgroundRefresh(agents: string[]): void {
    if (this.timer !== undefined) return;
    this.timer = setInterval(() => {
      for (const agent of agents) {
        void this.refresh(agent).catch(() => undefined);
      }
    }, this.opts.refreshIntervalMs);
    // Do not keep the process alive solely for the refresh timer.
    this.timer.unref?.();
  }

  stopBackgroundRefresh(): void {
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }
}
