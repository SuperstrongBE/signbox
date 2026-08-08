/**
 * Hash-chained audit log (spec §16).
 *
 * Every decision — signed or denied — is recorded. Each entry embeds the
 * hash of the previous one, so any insertion, deletion or edit breaks the
 * chain and is detectable by `verify()`.
 *
 * What is NEVER recorded (§16): private key, passphrase, decrypted keystore,
 * or transaction `data` values. Only the decision, the contract::action
 * names, the matching rule ids, the policy version and the transaction
 * digest are stored — enough to audit WHAT was decided, not the payload.
 */

import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import { canonicalize } from "../core/canonical/jcs.js";

export interface AuditEntryInput {
  requestId: string;
  agent: string;
  /**
   * The primary decision (#42): `signed`/`denied` for the sign path, `broadcast`
   * for a standalone broadcast submission. A fused sign+broadcast records
   * `signed` AND carries the `broadcast` outcome below — both are auditable.
   */
  decision: "signed" | "denied" | "broadcast";
  /** Deny code, when denied. */
  code?: string;
  /** Matching allow rule ids, when signed. */
  ruleIds?: string[];
  policyVersion?: number;
  /** "contract::action" per action — names only, never data. */
  contracts: string[];
  /** Transaction digest, when signed. */
  digest?: string;
  /**
   * Network-submission outcome (#42), present whenever the daemon broadcast:
   * on the fused sign+broadcast path and on the standalone broadcast op.
   * Distinguishes accepted / rejected / ambiguous ("unknown") submissions.
   */
  broadcast?: "accepted" | "rejected" | "ambiguous";
  timestampMs: number;
}

export interface AuditRecord extends AuditEntryInput {
  seq: number;
  prevHash: string;
  entryHash: string;
}

const GENESIS_HASH = "0".repeat(64);

interface AuditRow {
  seq: number;
  request_id: string;
  agent: string;
  decision: string;
  code: string | null;
  rule_ids: string | null;
  policy_version: number | null;
  contracts: string;
  digest: string | null;
  broadcast: string | null;
  timestamp_ms: number;
  prev_hash: string;
  entry_hash: string;
}

/**
 * The exact fields covered by the chain hash (order fixed by JCS).
 *
 * `broadcast` is included ONLY when present (#42): entries written before the
 * field existed never carried it, so omitting the key when undefined keeps
 * their canonical form — and thus their hash — byte-for-byte identical. Adding
 * it unconditionally would break `verify()` on every pre-existing log.
 */
function hashableFields(seq: number, prevHash: string, e: AuditEntryInput): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    seq,
    prevHash,
    requestId: e.requestId,
    agent: e.agent,
    decision: e.decision,
    code: e.code ?? null,
    ruleIds: e.ruleIds ?? null,
    policyVersion: e.policyVersion ?? null,
    contracts: e.contracts,
    digest: e.digest ?? null,
    timestampMs: e.timestampMs,
  };
  if (e.broadcast !== undefined) fields["broadcast"] = e.broadcast;
  return fields;
}

function computeHash(seq: number, prevHash: string, e: AuditEntryInput): string {
  return createHash("sha256")
    .update(Buffer.from(canonicalize(hashableFields(seq, prevHash, e)), "utf8"))
    .digest("hex");
}

export class AuditLog {
  private readonly db: Database.Database;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audit_log (
        seq INTEGER PRIMARY KEY,
        request_id TEXT NOT NULL,
        agent TEXT NOT NULL,
        decision TEXT NOT NULL,
        code TEXT,
        rule_ids TEXT,
        policy_version INTEGER,
        contracts TEXT NOT NULL,
        digest TEXT,
        broadcast TEXT,
        timestamp_ms INTEGER NOT NULL,
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log (agent, timestamp_ms);
    `);
    // Migration (#42): a log created before the broadcast column existed lacks
    // it — add it nullable. Old rows read back as broadcast:null, which never
    // enters the hash (see hashableFields), so verify() stays intact.
    const cols = this.db.prepare(`PRAGMA table_info(audit_log)`).all() as { name: string }[];
    if (!cols.some((c) => c.name === "broadcast")) {
      this.db.exec(`ALTER TABLE audit_log ADD COLUMN broadcast TEXT`);
    }
  }

  close(): void {
    this.db.close();
  }

  /** Append one decision to the chain. Never throws on caller data. */
  append(entry: AuditEntryInput): AuditRecord {
    const insert = this.db.transaction((): AuditRecord => {
      const last = this.db
        .prepare(`SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1`)
        .get() as { seq: number; entry_hash: string } | undefined;
      const seq = (last?.seq ?? 0) + 1;
      const prevHash = last?.entry_hash ?? GENESIS_HASH;
      const entryHash = computeHash(seq, prevHash, entry);
      this.db
        .prepare(
          `INSERT INTO audit_log
             (seq, request_id, agent, decision, code, rule_ids, policy_version,
              contracts, digest, broadcast, timestamp_ms, prev_hash, entry_hash)
           VALUES (@seq, @request_id, @agent, @decision, @code, @rule_ids, @policy_version,
              @contracts, @digest, @broadcast, @timestamp_ms, @prev_hash, @entry_hash)`,
        )
        .run({
          seq,
          request_id: entry.requestId,
          agent: entry.agent,
          decision: entry.decision,
          code: entry.code ?? null,
          rule_ids: entry.ruleIds !== undefined ? JSON.stringify(entry.ruleIds) : null,
          policy_version: entry.policyVersion ?? null,
          contracts: JSON.stringify(entry.contracts),
          digest: entry.digest ?? null,
          broadcast: entry.broadcast ?? null,
          timestamp_ms: entry.timestampMs,
          prev_hash: prevHash,
          entry_hash: entryHash,
        });
      return { ...entry, seq, prevHash, entryHash };
    });
    return insert();
  }

  private toRecord(row: AuditRow): AuditRecord {
    const record: AuditRecord = {
      seq: row.seq,
      requestId: row.request_id,
      agent: row.agent,
      decision: row.decision as "signed" | "denied" | "broadcast",
      contracts: JSON.parse(row.contracts) as string[],
      timestampMs: row.timestamp_ms,
      prevHash: row.prev_hash,
      entryHash: row.entry_hash,
    };
    if (row.code !== null) record.code = row.code;
    if (row.rule_ids !== null) record.ruleIds = JSON.parse(row.rule_ids) as string[];
    if (row.policy_version !== null) record.policyVersion = row.policy_version;
    if (row.digest !== null) record.digest = row.digest;
    if (row.broadcast !== null) record.broadcast = row.broadcast as "accepted" | "rejected" | "ambiguous";
    return record;
  }

  /** Most recent entries first. */
  tail(limit = 20): AuditRecord[] {
    const rows = this.db
      .prepare(`SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?`)
      .all(limit) as AuditRow[];
    return rows.map((r) => this.toRecord(r));
  }

  query(opts: { agent?: string; sinceMs?: number; limit?: number } = {}): AuditRecord[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM audit_log
         WHERE (@agent IS NULL OR agent = @agent)
           AND timestamp_ms >= @since
         ORDER BY seq DESC LIMIT @limit`,
      )
      .all({
        agent: opts.agent ?? null,
        since: opts.sinceMs ?? 0,
        limit: opts.limit ?? 100,
      }) as AuditRow[];
    return rows.map((r) => this.toRecord(r));
  }

  /**
   * Walk the chain and recompute every hash. Returns the first broken seq if
   * an entry was inserted, deleted or edited, or ok with the entry count.
   */
  verify(): { ok: true; count: number } | { ok: false; brokenAt: number; reason: string } {
    const rows = this.db.prepare(`SELECT * FROM audit_log ORDER BY seq ASC`).all() as AuditRow[];
    let prevHash = GENESIS_HASH;
    let expectedSeq = 1;
    for (const row of rows) {
      if (row.seq !== expectedSeq) {
        return { ok: false, brokenAt: row.seq, reason: "sequence gap (deleted or reordered entry)" };
      }
      if (row.prev_hash !== prevHash) {
        return { ok: false, brokenAt: row.seq, reason: "previous-hash link broken" };
      }
      const recomputed = computeHash(row.seq, row.prev_hash, this.toRecord(row));
      if (recomputed !== row.entry_hash) {
        return { ok: false, brokenAt: row.seq, reason: "entry hash mismatch (edited entry)" };
      }
      prevHash = row.entry_hash;
      expectedSeq += 1;
    }
    return { ok: true, count: rows.length };
  }
}
