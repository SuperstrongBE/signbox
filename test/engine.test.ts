import { describe, expect, it } from "vitest";
import { evaluatePolicy, type EvaluationContext } from "../src/core/policy/engine.js";
import { emptyPolicy, validatePolicy, type Policy } from "../src/core/policy/schema.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import type { ChainContext, DecodedTransaction } from "../src/core/types.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const CHAIN: ChainContext = { chain: "XPR", network: "mainnet", chainId: CHAIN_ID };
const CTX: EvaluationContext = {
  agent: "superagent",
  agentPermission: "xp2vr3",
  chainId: CHAIN_ID,
  policyVersion: 3,
};

/** The spec §8.2 example policy, verbatim structure. */
const SPEC_POLICY: Policy = validatePolicy({
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
        "data.quantity.amount": { lte: "1000.0000" },
        "data.to": { notIn: ["blocked.gm", "xyz"] },
      },
      limits: {
        maxPerTransaction: "1000.0000 XPR",
        maxPerHour: "2500.0000 XPR",
        maxPerDay: "5000.0000 XPR",
        cooldownPerRecipientMs: 60000,
      },
    },
    {
      id: "deny-xusdc",
      effect: "deny",
      match: {
        contract: "xtokens",
        action: "transfer",
        "data.quantity.symbol": "XUSDC",
      },
    },
  ],
});

function transfer(overrides?: {
  to?: string;
  quantity?: string;
  actor?: string;
  permission?: string;
  contract?: string;
  from?: string;
}): DecodedTransaction {
  return decodeXprTransaction(
    {
      actions: [
        {
          account: overrides?.contract ?? "eosio.token",
          name: "transfer",
          authorization: [
            {
              actor: overrides?.actor ?? "superagent",
              permission: overrides?.permission ?? "xp2vr3",
            },
          ],
          data: {
            from: overrides?.from ?? "superagent",
            to: overrides?.to ?? "alice",
            quantity: overrides?.quantity ?? "10.0000 XPR",
            memo: "tip",
          },
        },
      ],
    },
    CHAIN,
  );
}

describe("policy engine — INV-001 deny by default", () => {
  it("denies everything with an empty policy", () => {
    const { decision } = evaluatePolicy(transfer(), emptyPolicy("XPR", CHAIN_ID), CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "DEFAULT_DENY", policyVersion: 3 });
  });

  it("denies an empty transaction", () => {
    const { decision } = evaluatePolicy({ context: CHAIN, actions: [] }, SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "EMPTY_TRANSACTION" });
  });
});

describe("policy engine — allow path", () => {
  it("allows a compliant transfer and reports the governing rule", () => {
    const { decision, quotaDemands } = evaluatePolicy(transfer(), SPEC_POLICY, CTX);
    expect(decision).toEqual({
      effect: "allow",
      ruleIds: ["allow-small-xpr-tips"],
      policyVersion: 3,
    });
    // Stateful limits surface as quota demands for atomic reservation (§8.5).
    expect(quotaDemands).toHaveLength(1);
    expect(quotaDemands[0]).toMatchObject({
      ruleId: "allow-small-xpr-tips",
      recipient: "alice",
      cooldownPerRecipientMs: 60000,
    });
    expect(quotaDemands[0]!.amount).toEqual({ units: 100_000n, symbol: "XPR", precision: 4 });
  });

  it("allows exactly at the cap boundary", () => {
    const { decision } = evaluatePolicy(transfer({ quantity: "1000.0000 XPR" }), SPEC_POLICY, CTX);
    expect(decision.effect).toBe("allow");
  });
});

describe("policy engine — refusals", () => {
  it("denies above the per-transaction cap", () => {
    const { decision } = evaluatePolicy(transfer({ quantity: "1000.0001 XPR" }), SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny" });
    // Either the lte match fails (DEFAULT_DENY) or the limit trips — both refuse,
    // and the safe reason never leaks the threshold value.
    if (decision.effect === "deny") {
      expect(decision.safeReason).not.toContain("1000");
    }
  });

  it("denies a blocked recipient", () => {
    const { decision } = evaluatePolicy(transfer({ to: "blocked.gm" }), SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "DEFAULT_DENY" });
  });

  it("explicit deny wins over allow (§8.3) — XUSDC transfer", () => {
    const tx = decodeXprTransaction(
      {
        actions: [
          {
            account: "xtokens",
            name: "transfer",
            authorization: [{ actor: "superagent", permission: "xp2vr3" }],
            data: { from: "superagent", to: "alice", quantity: "1.000000 XUSDC", memo: "" },
          },
        ],
      },
      CHAIN,
    );
    const { decision } = evaluatePolicy(tx, SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "RULE_DENY" });
  });

  it("denies a wrong actor (confused deputy, §15.5)", () => {
    const { decision } = evaluatePolicy(transfer({ actor: "mallory" }), SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "DEFAULT_DENY" });
  });

  it("denies a wrong permission", () => {
    const { decision } = evaluatePolicy(transfer({ permission: "active" }), SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "DEFAULT_DENY" });
  });

  it("denies a wrong token contract carrying the right symbol (§17.4)", () => {
    const { decision } = evaluatePolicy(transfer({ contract: "eviltoken" }), SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "DEFAULT_DENY" });
  });

  it("denies a second injected action even if the first is allowed (§17.4, Q8)", () => {
    const tx = decodeXprTransaction(
      {
        actions: [
          {
            account: "eosio.token",
            name: "transfer",
            authorization: [{ actor: "superagent", permission: "xp2vr3" }],
            data: { from: "superagent", to: "alice", quantity: "1.0000 XPR", memo: "" },
          },
          {
            account: "eosio",
            name: "updateauth",
            authorization: [{ actor: "superagent", permission: "xp2vr3" }],
            data: { account: "superagent", permission: "active" },
          },
        ],
      },
      CHAIN,
    );
    const { decision } = evaluatePolicy(tx, SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "DEFAULT_DENY" });
  });

  it("denies on chain ID substitution (§17.4)", () => {
    const otherChain = { ...CHAIN, chainId: "b".repeat(64) };
    const tx = { ...transfer(), context: otherChain };
    const { decision } = evaluatePolicy(tx, SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "CHAIN_MISMATCH" });
  });

  it("denies incorrect decimals as ambiguous, never coerces (§17.4)", () => {
    // 5 decimals against a 4-decimal bound: comparison must refuse.
    const { decision } = evaluatePolicy(transfer({ quantity: "10.00000 XPR" }), SPEC_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "AMBIGUOUS_VALUE" });
  });

  it("denies homograph symbols (Cyrillic ХРR is not XPR)", () => {
    const { decision } = evaluatePolicy(transfer({ quantity: "10.0000 ХРR" }), SPEC_POLICY, CTX);
    // The homograph never parses as an asset, so quantity stays a raw string:
    // the symbol match fails and nothing is allowed.
    expect(decision).toMatchObject({ effect: "deny" });
  });

  it("safe reasons never leak rule internals (§11.6)", () => {
    const cases = [
      transfer({ to: "blocked.gm" }),
      transfer({ quantity: "9999.0000 XPR" }),
      transfer({ actor: "mallory" }),
    ];
    for (const tx of cases) {
      const { decision } = evaluatePolicy(tx, SPEC_POLICY, CTX);
      if (decision.effect === "deny") {
        expect(decision.safeReason).not.toMatch(/blocked\.gm|1000|2500|5000|allow-small/);
      } else {
        throw new Error("expected a refusal");
      }
    }
  });
});

describe("policy schema validation (§7.5 — the daemon is the sole validator)", () => {
  it("rejects unknown top-level fields", () => {
    expect(() => validatePolicy({ ...SPEC_POLICY, extra: true })).toThrow();
  });

  it("rejects default allow", () => {
    expect(() => validatePolicy({ ...SPEC_POLICY, default: "allow" })).toThrow();
  });

  it("rejects unknown match paths", () => {
    expect(() =>
      validatePolicy({
        ...SPEC_POLICY,
        rules: [{ id: "x", effect: "allow", match: { "shell.exec": "rm" } }],
      }),
    ).toThrow();
  });

  it("rejects duplicate rule ids", () => {
    expect(() =>
      validatePolicy({
        ...SPEC_POLICY,
        rules: [
          { id: "dup", effect: "allow", match: { contract: "a" } },
          { id: "dup", effect: "deny", match: { contract: "b" } },
        ],
      }),
    ).toThrow();
  });

  it("rejects deny rules with limits", () => {
    expect(() =>
      validatePolicy({
        ...SPEC_POLICY,
        rules: [
          {
            id: "bad",
            effect: "deny",
            match: { contract: "a" },
            limits: { maxPerTransaction: "1.0000 XPR" },
          },
        ],
      }),
    ).toThrow();
  });

  it("rejects malformed limit assets at load time", () => {
    expect(() =>
      validatePolicy({
        ...SPEC_POLICY,
        rules: [
          {
            id: "bad",
            effect: "allow",
            match: { contract: "a" },
            limits: { maxPerTransaction: "1.0 lol" },
          },
        ],
      }),
    ).toThrow();
  });
});
