import { describe, expect, it } from "vitest";
import { READ_ONLY_METHODS, XprChainReadRelay } from "../src/chains/xpr/relay.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";

describe("chain read relay — allow-list (INV-011)", () => {
  const relay = new XprChainReadRelay({ endpoints: ["https://example.invalid"], chainId: CHAIN_ID });

  it("refuses any state-changing / non-whitelisted method before touching the network", async () => {
    for (const method of [
      "push_transaction",
      "push_transactions",
      "send_transaction",
      "push_ro_transaction",
      "send_read_only_transaction",
      "compute_transaction",
      "not_a_method",
    ]) {
      await expect(relay.call(method, {})).rejects.toThrow(/not permitted/);
    }
  });

  it("whitelists only read-only chain methods, and never a submit method", () => {
    expect(READ_ONLY_METHODS.has("get_account")).toBe(true);
    expect(READ_ONLY_METHODS.has("get_currency_balance")).toBe(true);
    expect(READ_ONLY_METHODS.has("get_abi")).toBe(true);
    expect(READ_ONLY_METHODS.has("get_table_rows")).toBe(true);
    for (const forbidden of ["push_transaction", "send_transaction", "compute_transaction"]) {
      expect(READ_ONLY_METHODS.has(forbidden)).toBe(false);
    }
  });
});
