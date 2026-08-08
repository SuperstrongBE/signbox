/**
 * Lossless-load guard for the web policy editor (#38).
 *
 * A policy is editable ONLY if it survives decompile → recompile unchanged
 * (semantically). Anything the graph can't fully represent — an unsupported
 * limit, an unrepresentable provider or match path, an unknown field, a newer
 * schema version — must open read-only with the original document preserved,
 * never as a graph that would silently drop part of it on save. Unparsable
 * input is invalid. These regressions guard exactly that.
 */

import { describe, expect, it } from "vitest";
import { loadPolicyForEditing } from "../web/src/editor/roundtrip";
import { decompilePolicy } from "../web/src/editor/decompile";
import { compilePolicy } from "../web/src/editor/compile";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";

function policy(rules: unknown[], extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    schemaVersion: 1,
    default: "deny",
    chain: { name: "XPR", chainId: CHAIN_ID },
    rules,
    ...extra,
  });
}

const ALLOW_WITH_LIMIT = {
  id: "allow-payments",
  effect: "allow",
  match: { contract: "eosio.token", action: "transfer", "data.from": "funagent", "data.quantity.symbol": "XPR" },
  limits: { maxPerTransaction: "100.0000 XPR" },
};
const DENY_RULE = {
  id: "deny-baddie",
  effect: "deny",
  match: { contract: "eosio.token", action: "transfer", "data.to": "baddie" },
};
const IN_LIST_RULE = {
  id: "allow-list",
  effect: "allow",
  match: { contract: "eosio.token", action: "transfer", "data.to": { in: ["alice", "bob"] } },
};
const LOOKUP_RULE = {
  id: "allow-whitelisted",
  effect: "allow",
  match: { contract: "eosio.token", action: "transfer" },
  providers: [
    {
      provider: "xpr.rpc.tableRow",
      args: { contract: "whitelister", scope: "whitelister", table: "lists", key: "$agent" },
      select: "allowed",
      op: "contains",
      value: "$data.to",
    },
  ],
};

describe("loadPolicyForEditing — lossless policies are editable (#38)", () => {
  it("the empty deny-all policy is editable", () => {
    expect(loadPolicyForEditing(policy([]), CHAIN_ID).mode).toBe("editable");
  });

  it("an allow rule with a value limit is editable", () => {
    expect(loadPolicyForEditing(policy([ALLOW_WITH_LIMIT]), CHAIN_ID).mode).toBe("editable");
  });

  it("a deny rule is editable", () => {
    expect(loadPolicyForEditing(policy([DENY_RULE]), CHAIN_ID).mode).toBe("editable");
  });

  it("an in-list match is editable", () => {
    expect(loadPolicyForEditing(policy([IN_LIST_RULE]), CHAIN_ID).mode).toBe("editable");
  });

  it("a table-row lookup provider is editable", () => {
    expect(loadPolicyForEditing(policy([LOOKUP_RULE]), CHAIN_ID).mode).toBe("editable");
  });

  it("an explicit maxActionsPerTransaction is editable (default 1 also matches when omitted)", () => {
    expect(loadPolicyForEditing(policy([ALLOW_WITH_LIMIT], { maxActionsPerTransaction: 3 }), CHAIN_ID).mode).toBe(
      "editable",
    );
    expect(loadPolicyForEditing(policy([]), CHAIN_ID).mode).toBe("editable"); // omitted == 1
  });

  it("several representable rules together are editable", () => {
    expect(loadPolicyForEditing(policy([ALLOW_WITH_LIMIT, DENY_RULE, IN_LIST_RULE]), CHAIN_ID).mode).toBe("editable");
  });
});

describe("loadPolicyForEditing — lossy policies are read-only, original preserved (#38)", () => {
  function expectReadonlyPreserving(json: string) {
    const r = loadPolicyForEditing(json, CHAIN_ID);
    expect(r.mode).toBe("readonly");
    if (r.mode !== "readonly") return;
    expect(r.reasons.length).toBeGreaterThan(0);
    // The on-chain document is preserved verbatim (semantically identical).
    expect(JSON.parse(r.original)).toEqual(JSON.parse(json));
    return r;
  }

  it("an unknown top-level field can't be silently dropped", () => {
    expectReadonlyPreserving(policy([], { experimentalCap: 5 }));
  });

  it("a newer schemaVersion is read-only (needs explicit migration)", () => {
    const r = loadPolicyForEditing(policy([]).replace('"schemaVersion":1', '"schemaVersion":2'), CHAIN_ID);
    expect(r.mode).toBe("readonly");
    if (r.mode === "readonly") expect(r.reasons.join(" ")).toMatch(/schemaVersion/i);
  });

  it("a limit the editor can't represent (maxPerHour) is read-only", () => {
    expectReadonlyPreserving(
      policy([
        { id: "r", effect: "allow", match: { contract: "eosio.token", action: "transfer" }, limits: { maxPerHour: "50.0000 XPR" } },
      ]),
    );
  });

  it("a provider with op:eq (not representable) is read-only", () => {
    expectReadonlyPreserving(
      policy([
        {
          id: "r",
          effect: "allow",
          match: { contract: "eosio.token", action: "transfer" },
          providers: [
            { provider: "xpr.rpc.tableRow", args: { contract: "c", table: "t", key: "$agent" }, select: "flag", op: "eq", value: "yes" },
          ],
        },
      ]),
    );
  });

  it("a match path the editor can't represent (data.memo) is read-only", () => {
    expectReadonlyPreserving(
      policy([{ id: "r", effect: "allow", match: { contract: "eosio.token", action: "transfer", "data.memo": "hi" } }]),
    );
  });
});

describe("loadPolicyForEditing — unparsable input is invalid (#38)", () => {
  it("non-JSON is invalid", () => {
    expect(loadPolicyForEditing("{not json", CHAIN_ID).mode).toBe("invalid");
  });

  it("a JSON non-object is invalid", () => {
    expect(loadPolicyForEditing("[1,2,3]", CHAIN_ID).mode).toBe("invalid");
  });
});

describe("rule ids survive the round trip (#38)", () => {
  it("decompile → compile keeps the original rule id (not a regenerated slug)", () => {
    const { state } = decompilePolicy(policy([ALLOW_WITH_LIMIT]));
    const recompiled = compilePolicy(state.nodes, state.wires, CHAIN_ID);
    expect(recompiled?.policy.rules[0]?.id).toBe("allow-payments");
  });

  it("a new rule (no stored id) still gets a generated id", () => {
    // Decompiling a policy whose rule id would differ from the slug proves the
    // preserved id wins; here we assert the slug fallback still works when empty.
    const { state } = decompilePolicy(policy([{ ...DENY_RULE, id: "deny-baddie" }]));
    const decision = state.nodes.find((n) => n.type === "decision");
    if (decision !== undefined) decision.fields["id"] = ""; // simulate a freshly-added rule
    const recompiled = compilePolicy(state.nodes, state.wires, CHAIN_ID);
    expect(recompiled?.policy.rules[0]?.id).not.toBe("");
    expect(typeof recompiled?.policy.rules[0]?.id).toBe("string");
  });
});
