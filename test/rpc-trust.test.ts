/**
 * RPC trust hardening (#40) — the chain-id pin must actually FIRE before any
 * data leaves an endpoint, and stale/lying nodes must fail closed.
 *
 * Regression background: pinChainId only wrapped get_info; a path that never
 * called get_info (the policy reader's get_table_rows, the relay's fetch,
 * get_abi) fetched data with a DECORATIVE pin — the verification never
 * executed. verifiedRpc guards the fetch choke point (every JsonRpc method
 * funnels through it, exactly like production) behind a fresh verification.
 */

import { describe, expect, it } from "vitest";
import { JsonRpc } from "@proton/js";
import { verifiedRpc } from "../src/chains/xpr/rpc.js";
import { XprPolicyReader } from "../src/chains/xpr/policyReader.js";
import { XprChainReadRelay } from "../src/chains/xpr/relay.js";
import { SigningError } from "../src/chains/xpr/adapter.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const OTHER_ID = "b".repeat(64);
const T0 = Date.parse("2026-08-06T12:00:00.000Z");
const FRESH_HEAD = "2026-08-06T11:59:59.500"; // 500ms behind T0 — healthy

interface StubOptions {
  chainId?: string;
  headTime?: string | undefined;
}

/**
 * Stub the INSTANCE `fetch` — the single funnel every JsonRpc method routes
 * through (get_info included), mirroring production exactly. Counts calls
 * per path.
 */
function stubRpc(opts: StubOptions = {}) {
  const rpc = new JsonRpc(["http://127.0.0.1:1"]);
  const calls = new Map<string, number>();
  (rpc as unknown as Record<string, unknown>)["fetch"] = async (path: string) => {
    calls.set(path, (calls.get(path) ?? 0) + 1);
    if (path === "/v1/chain/get_info") {
      return {
        chain_id: opts.chainId ?? CHAIN_ID,
        ...(opts.headTime !== undefined ? { head_block_time: opts.headTime } : {}),
      };
    }
    if (path === "/v1/chain/get_table_rows") return { rows: [], more: false };
    return { ok: true };
  };
  const count = (path: string) => calls.get(`/v1/chain/${path}`) ?? 0;
  return { rpc, count };
}

describe("verifiedRpc — the pin fires before data calls", () => {
  it("verifies chain id + liveness BEFORE the first data call", async () => {
    const { rpc, count } = stubRpc({ headTime: FRESH_HEAD });
    verifiedRpc(rpc, { chainId: CHAIN_ID, now: () => T0 });
    await rpc.get_table_rows({});
    expect(count("get_info")).toBe(1); // the verification actually executed
    expect(count("get_table_rows")).toBe(1);
  });

  it("refuses a cross-chain endpoint before any data is fetched", async () => {
    const { rpc, count } = stubRpc({ chainId: OTHER_ID, headTime: FRESH_HEAD });
    verifiedRpc(rpc, { chainId: CHAIN_ID, now: () => T0 });
    await expect(rpc.get_table_rows({})).rejects.toThrow(SigningError);
    expect(count("get_table_rows")).toBe(0); // data never left the endpoint
  });

  it("refuses a stale head (frozen node) and a missing head_block_time", async () => {
    const stale = stubRpc({ headTime: "2026-08-06T11:50:00.000" }); // 10 min behind
    verifiedRpc(stale.rpc, { chainId: CHAIN_ID, now: () => T0 });
    await expect(stale.rpc.get_abi("signbox")).rejects.toThrow(/stale/);
    expect(stale.count("get_abi")).toBe(0);

    const headless = stubRpc({});
    verifiedRpc(headless.rpc, { chainId: CHAIN_ID, now: () => T0 });
    await expect(headless.rpc.get_table_rows({})).rejects.toThrow(/head_block_time/);
    expect(headless.count("get_table_rows")).toBe(0);
  });

  it("re-verifies after the freshness window, not before", async () => {
    let nowMs = T0;
    const { rpc, count } = stubRpc({ headTime: FRESH_HEAD });
    verifiedRpc(rpc, { chainId: CHAIN_ID, freshnessMs: 30_000, maxHeadLagMs: 3_600_000, now: () => nowMs });
    await rpc.get_table_rows({});
    await rpc.get_table_rows({});
    expect(count("get_info")).toBe(1); // within the window: one verification
    nowMs = T0 + 31_000;
    await rpc.get_table_rows({});
    expect(count("get_info")).toBe(2); // window expired: re-verified
    expect(count("get_table_rows")).toBe(3);
  });

  it("concurrent data calls share ONE in-flight verification (no race, no storm)", async () => {
    const { rpc, count } = stubRpc({ headTime: FRESH_HEAD });
    verifiedRpc(rpc, { chainId: CHAIN_ID, now: () => T0 });
    await Promise.all([rpc.get_table_rows({}), rpc.get_table_rows({}), rpc.get_abi("x")]);
    expect(count("get_info")).toBe(1); // one shared verification
    expect(count("get_table_rows")).toBe(2);
    expect(count("get_abi")).toBe(1);
  });
});

describe("consumers fail closed through the verified pin (#40)", () => {
  it("the policy reader refuses an unreachable endpoint (verification first)", async () => {
    const reader = new XprPolicyReader({
      endpoints: ["http://127.0.0.1:1"],
      chainId: CHAIN_ID,
      contractAccount: "signbox",
    });
    await expect(reader.read("funagent")).rejects.toThrow();
  });

  it("the relay caps pathological response sizes", async () => {
    // Stub at the prototype so the relay's internally-built rpc inherits it.
    const proto = JsonRpc.prototype as unknown as Record<string, unknown>;
    const savedFetch = proto["fetch"];
    proto["fetch"] = async (path: string) => {
      if (path === "/v1/chain/get_info") {
        return { chain_id: CHAIN_ID, head_block_time: new Date(Date.now() - 500).toISOString().replace("Z", "") };
      }
      return { blob: "x".repeat(600 * 1024) }; // > 512 KiB
    };
    try {
      const relay = new XprChainReadRelay({ endpoints: ["http://127.0.0.1:1"], chainId: CHAIN_ID });
      await expect(relay.call("get_table_rows", {})).rejects.toThrow(/size limit/);
    } finally {
      proto["fetch"] = savedFetch;
    }
  });
});
