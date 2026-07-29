import { describe, expect, it } from "vitest";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { ValidationError } from "../src/core/errors.js";
import type { ChainContext } from "../src/core/types.js";

const CHAIN: ChainContext = { chain: "XPR", network: "testnet", chainId: "a".repeat(64) };

const VALID = {
  actions: [
    {
      account: "eosio.token",
      name: "transfer",
      authorization: [{ actor: "superagent", permission: "xp2vr3" }],
      data: { from: "superagent", to: "alice", quantity: "12.0000 XPR", memo: "hi" },
    },
  ],
};

describe("XPR transaction decoding — INV-014", () => {
  it("normalizes a valid transaction to the chain-agnostic form", () => {
    const tx = decodeXprTransaction(VALID, CHAIN);
    expect(tx.actions).toHaveLength(1);
    expect(tx.actions[0]).toMatchObject({
      contract: "eosio.token",
      action: "transfer",
      authorization: [{ accountIdentifier: "superagent", permission: "xp2vr3" }],
    });
  });

  it("expands asset strings into integer-comparable structures (§8.6)", () => {
    const tx = decodeXprTransaction(VALID, CHAIN);
    expect(tx.actions[0]!.data["quantity"]).toEqual({
      amount: "12.0000",
      symbol: "XPR",
      precision: 4,
    });
    // Non-asset strings stay untouched.
    expect(tx.actions[0]!.data["memo"]).toBe("hi");
  });

  it("rejects packed transaction payloads categorically", () => {
    expect(() => decodeXprTransaction("aabbccdd00112233", CHAIN)).toThrow(ValidationError);
    expect(() => decodeXprTransaction(Buffer.from("deadbeef", "hex"), CHAIN)).toThrow(
      ValidationError,
    );
  });

  it("rejects hex/string data — data must be a JSON object", () => {
    const tx = {
      actions: [{ ...VALID.actions[0], data: "00ffab" }],
    };
    expect(() => decodeXprTransaction(tx, CHAIN)).toThrow(ValidationError);
  });

  it("rejects unknown top-level fields (§15.5): CFA, delay, extensions, TAPOS", () => {
    for (const extra of [
      { context_free_actions: [] },
      { delay_sec: 0 },
      { transaction_extensions: [] },
      { expiration: "2026-01-01T00:00:00" },
      { ref_block_num: 1 },
      { signatures: [] },
    ]) {
      expect(() => decodeXprTransaction({ ...VALID, ...extra }, CHAIN)).toThrow(ValidationError);
    }
  });

  it("rejects unknown action-level fields", () => {
    const tx = { actions: [{ ...VALID.actions[0], hex_data: "00" }] };
    expect(() => decodeXprTransaction(tx, CHAIN)).toThrow(ValidationError);
  });

  it("rejects more than one authorization per action (fail closed)", () => {
    const tx = {
      actions: [
        {
          ...VALID.actions[0],
          authorization: [
            { actor: "superagent", permission: "xp2vr3" },
            { actor: "mallory", permission: "active" },
          ],
        },
      ],
    };
    expect(() => decodeXprTransaction(tx, CHAIN)).toThrow(ValidationError);
  });

  it("rejects empty transactions", () => {
    expect(() => decodeXprTransaction({ actions: [] }, CHAIN)).toThrow(ValidationError);
  });

  it("rejects invalid account names", () => {
    const tx = {
      actions: [{ ...VALID.actions[0], account: "EOSIO.TOKEN" }],
    };
    expect(() => decodeXprTransaction(tx, CHAIN)).toThrow(ValidationError);
    const tx2 = {
      actions: [{ ...VALID.actions[0], account: "waytoolongaccountname" }],
    };
    expect(() => decodeXprTransaction(tx2, CHAIN)).toThrow(ValidationError);
  });

  it("rejects prototype-polluting keys in data", () => {
    const data = JSON.parse('{"from":"superagent","__proto__x":1}');
    // Keys outside [a-zA-Z0-9_] are rejected; craft one with a dash.
    const tx = { actions: [{ ...VALID.actions[0], data: { ...data, "bad-key": 1 } }] };
    expect(() => decodeXprTransaction(tx, CHAIN)).toThrow(ValidationError);
  });

  it("rejects non-finite numbers in data", () => {
    const tx = { actions: [{ ...VALID.actions[0], data: { from: "a", n: Infinity } }] };
    expect(() => decodeXprTransaction(tx, CHAIN)).toThrow(ValidationError);
  });

  it("rejects excessive nesting depth", () => {
    let nested: Record<string, unknown> = { leaf: 1 };
    for (let i = 0; i < 12; i++) nested = { child: nested };
    const tx = { actions: [{ ...VALID.actions[0], data: nested }] };
    expect(() => decodeXprTransaction(tx, CHAIN)).toThrow(ValidationError);
  });

  it("rejects oversized transactions", () => {
    const tx = {
      actions: [{ ...VALID.actions[0], data: { memo: "x".repeat(40 * 1024) } }],
    };
    expect(() => decodeXprTransaction(tx, CHAIN)).toThrow(ValidationError);
  });
});
