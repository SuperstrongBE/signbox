/**
 * Stateful quota journal (spec §8.5, §15.6).
 *
 * Enforces the stateful policy limits — maxPerHour, maxPerDay,
 * cooldownPerRecipientMs — that the pure engine cannot: it emits
 * QuotaDemands, and the daemon must RESERVE them here atomically BEFORE
 * signing, then COMMIT after the signature exists (§13). A failed signing
 * releases the reservation.
 *
 * Guarantees:
 * - reservation is all-or-nothing inside one SQLite transaction: two
 *   concurrent requests can never both fit under the same cap (§15.6);
 * - amounts are summed as bigint from TEXT storage — no floats, no i64
 *   overflow (§8.6);
 * - idempotence by digest: committing a digest already committed for the
 *   same agent releases the duplicate instead of double-counting (the
 *   chain deduplicates identical transactions anyway);
 * - honesty (§8.5): this is a LOCAL best-effort guarantee. The journal
 *   survives daemon restarts (file-backed), but a deleted or restored
 *   database resets the counters. Absolute caps belong on-chain.
 */

import Database from "better-sqlite3";
import { randomUUID } from "node:crypto";
import type { QuotaDemand } from "../core/policy/engine.js";
import type { AssetAmount } from "../core/asset.js";

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
/** Events older than this can no longer influence any window or cooldown. */
const RETENTION_MS = 2 * DAY_MS;

export type ReserveResult =
  | { ok: true; reservationId: string }
  | { ok: false; reason: "limit" | "cooldown" | "ambiguous" };

interface EventRow {
  units: string;
}

export class QuotaJournal {
  private readonly db: Database.Database;

  /** `path` may be a file path or ":memory:" (tests). */
  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("busy_timeout = 5000");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS quota_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reservation_id TEXT NOT NULL,
        agent TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        digest TEXT,
        recipient TEXT,
        units TEXT NOT NULL,
        symbol TEXT NOT NULL,
        precision INTEGER NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('reserved','committed','released')),
        created_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_quota_window
        ON quota_events (agent, rule_id, created_at_ms);
      CREATE INDEX IF NOT EXISTS idx_quota_reservation
        ON quota_events (reservation_id);
      CREATE INDEX IF NOT EXISTS idx_quota_digest
        ON quota_events (agent, digest);
    `);
  }

  close(): void {
    this.db.close();
  }

  /**
   * Atomically reserve all demands, or none. Reserved amounts count against
   * the caps immediately, so a concurrent request sees them (§15.6).
   */
  reserve(agent: string, demands: QuotaDemand[], nowMs: number): ReserveResult {
    const reservationId = randomUUID();
    const insert = this.db.prepare(`
      INSERT INTO quota_events
        (reservation_id, agent, rule_id, digest, recipient, units, symbol, precision, state, created_at_ms)
      VALUES (?, ?, ?, NULL, ?, ?, ?, ?, 'reserved', ?)
    `);

    const transaction = this.db.transaction(() => {
      // Opportunistic pruning: events past every window and cooldown.
      this.db
        .prepare(`DELETE FROM quota_events WHERE created_at_ms < ?`)
        .run(nowMs - RETENTION_MS);

      for (const demand of demands) {
        const { amount } = demand;

        if (demand.maxPerHour !== undefined) {
          this.checkWindow(agent, demand.ruleId, amount, demand.maxPerHour, HOUR_MS, nowMs);
        }
        if (demand.maxPerDay !== undefined) {
          this.checkWindow(agent, demand.ruleId, amount, demand.maxPerDay, DAY_MS, nowMs);
        }
        if (demand.cooldownPerRecipientMs !== undefined) {
          if (demand.recipient === undefined) {
            throw new ReserveRefusal("ambiguous");
          }
          if (this.countToRecipient(agent, demand.ruleId, demand.recipient, demand.cooldownPerRecipientMs, nowMs) > 0) {
            throw new ReserveRefusal("cooldown");
          }
        }

        // Count-based rate limits (count each matching action). A prior
        // reservation in this same batch is visible here, so a multi-action
        // transaction counts every action toward the window.
        if (demand.maxCountPerHour !== undefined) {
          if (this.countInWindow(agent, demand.ruleId, HOUR_MS, nowMs) >= demand.maxCountPerHour) {
            throw new ReserveRefusal("limit");
          }
        }
        if (demand.maxCountPerDay !== undefined) {
          if (this.countInWindow(agent, demand.ruleId, DAY_MS, nowMs) >= demand.maxCountPerDay) {
            throw new ReserveRefusal("limit");
          }
        }
        if (demand.maxCountPerRecipientPerHour !== undefined) {
          if (demand.recipient === undefined) {
            throw new ReserveRefusal("ambiguous");
          }
          if (
            this.countToRecipient(agent, demand.ruleId, demand.recipient, HOUR_MS, nowMs) >=
            demand.maxCountPerRecipientPerHour
          ) {
            throw new ReserveRefusal("limit");
          }
        }

        insert.run(
          reservationId,
          agent,
          demand.ruleId,
          demand.recipient ?? null,
          amount.units.toString(),
          amount.symbol,
          amount.precision,
          nowMs,
        );
      }
    });

    try {
      transaction();
      return { ok: true, reservationId };
    } catch (error) {
      if (error instanceof ReserveRefusal) {
        return { ok: false, reason: error.reason };
      }
      throw error;
    }
  }

  /**
   * Attach the signed digest to a reservation. If the same digest is already
   * committed for this agent, the duplicate reservation is RELEASED instead
   * of double-counting (idempotence by digest, §8.5).
   */
  commit(reservationId: string, agent: string, digest: string): void {
    const transaction = this.db.transaction(() => {
      const existing = this.db
        .prepare(
          `SELECT COUNT(*) AS n FROM quota_events
           WHERE agent = ? AND digest = ? AND state = 'committed'`,
        )
        .get(agent, digest) as { n: number };
      if (existing.n > 0) {
        this.db
          .prepare(`UPDATE quota_events SET state = 'released' WHERE reservation_id = ?`)
          .run(reservationId);
        return;
      }
      this.db
        .prepare(
          `UPDATE quota_events SET state = 'committed', digest = ? WHERE reservation_id = ?`,
        )
        .run(digest, reservationId);
    });
    transaction();
  }

  /** Return the reserved capacity, e.g. after a failed signing (§13). */
  release(reservationId: string): void {
    this.db
      .prepare(`UPDATE quota_events SET state = 'released' WHERE reservation_id = ?`)
      .run(reservationId);
  }

  /** Sum of non-released units for a rule window — bigint, never floats. */
  consumed(agent: string, ruleId: string, symbol: string, precision: number, windowMs: number, nowMs: number): bigint {
    const rows = this.db
      .prepare(
        `SELECT units FROM quota_events
         WHERE agent = ? AND rule_id = ? AND symbol = ? AND precision = ?
           AND state != 'released' AND created_at_ms > ?`,
      )
      .all(agent, ruleId, symbol, precision, nowMs - windowMs) as EventRow[];
    let total = 0n;
    for (const row of rows) total += BigInt(row.units);
    return total;
  }

  /** Count of non-released events for a rule in a window (count-based limits). */
  countInWindow(agent: string, ruleId: string, windowMs: number, nowMs: number): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS n FROM quota_events
         WHERE agent = ? AND rule_id = ? AND state != 'released' AND created_at_ms > ?`,
      )
      .get(agent, ruleId, nowMs - windowMs) as { n: number };
    return row.n;
  }

  /** Count of non-released events to a recipient for a rule in a window. */
  countToRecipient(
    agent: string,
    ruleId: string,
    recipient: string,
    windowMs: number,
    nowMs: number,
  ): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS n FROM quota_events
         WHERE agent = ? AND rule_id = ? AND recipient = ?
           AND state != 'released' AND created_at_ms > ?`,
      )
      .get(agent, ruleId, recipient, nowMs - windowMs) as { n: number };
    return row.n;
  }

  private checkWindow(
    agent: string,
    ruleId: string,
    amount: AssetAmount,
    cap: AssetAmount,
    windowMs: number,
    nowMs: number,
  ): void {
    // A cap in another symbol or precision cannot be compared: refuse
    // rather than coerce (§8.6, INV-010).
    if (cap.symbol !== amount.symbol || cap.precision !== amount.precision) {
      throw new ReserveRefusal("ambiguous");
    }
    const used = this.consumed(agent, ruleId, amount.symbol, amount.precision, windowMs, nowMs);
    if (used + amount.units > cap.units) {
      throw new ReserveRefusal("limit");
    }
  }
}

class ReserveRefusal extends Error {
  constructor(readonly reason: "limit" | "cooldown" | "ambiguous") {
    super(`quota reservation refused: ${reason}`);
  }
}
