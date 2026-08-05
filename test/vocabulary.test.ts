/**
 * Shared policy vocabulary (#45 C.1) — the SAME patterns drive the daemon's
 * validator and the web editor's compiler. These tests pin that the exported
 * regexes agree with validatePolicy's actual accept/reject behavior, so a
 * drift between the two can't reappear silently.
 */

import { describe, expect, it } from "vitest";
import { MATCH_PATH_RE, RULE_ID_RE, SELECT_FIELD_RE } from "../src/core/policy/vocabulary.js";
import { validatePolicy } from "../src/core/policy/schema.js";

function policyWithMatchKey(key: string) {
  return {
    schemaVersion: 1,
    default: "deny",
    chain: { name: "XPR", chainId: "a".repeat(64) },
    rules: [{ id: "r1", effect: "allow", match: { [key]: "x" } }],
  };
}

const ACCEPTED = ["contract", "action", "authorization.actor", "authorization.permission", "data.to", "data.quantity.amount"];
const REJECTED = ["authorization.foo", "data", "memo", "data..to", "data.to!", "authorization"];

describe("policy vocabulary — regex ↔ validator parity", () => {
  it("accepts exactly what the validator accepts (match paths)", () => {
    for (const key of ACCEPTED) {
      expect(MATCH_PATH_RE.test(key), key).toBe(true);
      expect(() => validatePolicy(policyWithMatchKey(key)), key).not.toThrow();
    }
  });

  it("rejects exactly what the validator rejects (match paths)", () => {
    for (const key of REJECTED) {
      expect(MATCH_PATH_RE.test(key), key).toBe(false);
      expect(() => validatePolicy(policyWithMatchKey(key)), key).toThrow();
    }
  });

  it("rule ids and select fields follow the shared patterns", () => {
    expect(RULE_ID_RE.test("allow-small-tips")).toBe(true);
    expect(RULE_ID_RE.test("Bad_Id")).toBe(false);
    expect(SELECT_FIELD_RE.test("producers")).toBe(true);
    expect(SELECT_FIELD_RE.test("nested.field")).toBe(false);
  });
});
