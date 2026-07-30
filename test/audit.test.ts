import { beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { AuditLog, type AuditEntryInput } from "../src/daemon/auditLog.js";

const NOW = Date.parse("2026-07-30T12:00:00.000Z");

function signedEntry(overrides?: Partial<AuditEntryInput>): AuditEntryInput {
  return {
    requestId: "req-1",
    agent: "superagent",
    decision: "signed",
    ruleIds: ["allow-transfer"],
    policyVersion: 3,
    contracts: ["eosio.token::transfer"],
    digest: "d".repeat(64),
    timestampMs: NOW,
    ...overrides,
  };
}

function fileDb(): string {
  return join(mkdtempSync(join(tmpdir(), "signbox-audit-")), "state.db");
}

describe("AuditLog", () => {
  let audit: AuditLog;
  beforeEach(() => {
    audit = new AuditLog(":memory:");
  });

  it("chains entries: each prevHash links to the previous entryHash", () => {
    const a = audit.append(signedEntry({ requestId: "r1" }));
    const b = audit.append(signedEntry({ requestId: "r2" }));
    expect(a.seq).toBe(1);
    expect(b.seq).toBe(2);
    expect(a.prevHash).toBe("0".repeat(64));
    expect(b.prevHash).toBe(a.entryHash);
  });

  it("records denials with their code and no digest", () => {
    const d = audit.append({
      requestId: "r1",
      agent: "superagent",
      decision: "denied",
      code: "DEFAULT_DENY",
      contracts: ["eviltoken::transfer"],
      timestampMs: NOW,
    });
    expect(d.decision).toBe("denied");
    expect(d.code).toBe("DEFAULT_DENY");
    expect(d.digest).toBeUndefined();
  });

  it("never stores secret material — only contract::action names", () => {
    audit.append(signedEntry());
    const [entry] = audit.tail(1);
    expect(entry!.contracts).toEqual(["eosio.token::transfer"]);
    // No `data` / recipient / amount fields exist on the record shape at all.
    expect(JSON.stringify(entry)).not.toMatch(/alice|quantity|PVT_|passphrase/);
  });

  it("verify() passes on an intact chain", () => {
    for (let i = 0; i < 5; i++) audit.append(signedEntry({ requestId: `r${i}` }));
    expect(audit.verify()).toEqual({ ok: true, count: 5 });
  });

  it("tail and query return newest first and filter by agent/time", () => {
    audit.append(signedEntry({ requestId: "r1", agent: "superagent", timestampMs: NOW }));
    audit.append(signedEntry({ requestId: "r2", agent: "otheragent", timestampMs: NOW + 1000 }));
    audit.append(signedEntry({ requestId: "r3", agent: "superagent", timestampMs: NOW + 2000 }));
    expect(audit.tail(1)[0]!.requestId).toBe("r3");
    const forSuper = audit.query({ agent: "superagent" });
    expect(forSuper.map((e) => e.requestId)).toEqual(["r3", "r1"]);
    const recent = audit.query({ sinceMs: NOW + 1500 });
    expect(recent.map((e) => e.requestId)).toEqual(["r3"]);
  });
});

describe("AuditLog — tamper detection", () => {
  it("detects an edited entry (hash mismatch)", () => {
    const path = fileDb();
    const audit = new AuditLog(path);
    for (let i = 0; i < 3; i++) audit.append(signedEntry({ requestId: `r${i}` }));
    audit.close();

    // Tamper directly in the database: flip a decision on entry 2.
    const raw = new Database(path);
    raw.prepare(`UPDATE audit_log SET decision = 'denied' WHERE seq = 2`).run();
    raw.close();

    const reopened = new AuditLog(path);
    const result = reopened.verify();
    expect(result).toMatchObject({ ok: false, brokenAt: 2 });
    reopened.close();
  });

  it("detects a deleted entry (sequence gap)", () => {
    const path = fileDb();
    const audit = new AuditLog(path);
    for (let i = 0; i < 3; i++) audit.append(signedEntry({ requestId: `r${i}` }));
    audit.close();

    const raw = new Database(path);
    raw.prepare(`DELETE FROM audit_log WHERE seq = 2`).run();
    raw.close();

    const reopened = new AuditLog(path);
    expect(reopened.verify()).toMatchObject({ ok: false, brokenAt: 3 });
    reopened.close();
  });
});
