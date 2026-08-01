import { beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignBoxDaemon, type AgentRuntime } from "../src/daemon/server.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { emptyPolicy } from "../src/core/policy/schema.js";
import type { ChainReadRelay } from "../src/daemon/chainRelay.js";
import type { ChainContext, KeyHandle } from "../src/core/types.js";
import type { ReadResponseJson } from "../src/daemon/protocol.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const CHAIN: ChainContext = { chain: "XPR", network: "testnet", chainId: CHAIN_ID };
const TOKEN = "tok_0123456789abcdefghij";
const NOW = Date.parse("2026-07-30T12:00:00.000Z");

const KEY: KeyHandle = {
  keyId: "k1",
  publicKey: "PUB_K1_agentkey",
  exportPolicy: "non-exportable",
  chain: CHAIN,
  agent: "funagent",
  permission: "active",
};

class FakeRelay implements ChainReadRelay {
  calls: { method: string; params: unknown }[] = [];
  constructor(private readonly impl: (method: string, params: unknown) => Promise<unknown>) {}
  async call(method: string, params: unknown): Promise<unknown> {
    this.calls.push({ method, params });
    return this.impl(method, params);
  }
}

function readRequest(over: Record<string, unknown>): string {
  return JSON.stringify({
    requestId: "req-00000001",
    agent: "funagent",
    requestedAt: new Date(NOW).toISOString(),
    expiresAt: new Date(NOW + 30_000).toISOString(),
    token: TOKEN,
    ...over,
  });
}

describe("daemon read ops — whoami / query", () => {
  let daemon: SignBoxDaemon;
  let relay: FakeRelay;

  beforeEach(() => {
    relay = new FakeRelay(async (method) => {
      if (method === "get_currency_balance") return ["12.3456 XPR"];
      if (method === "get_abi") return { account_name: "eosio.token", abi: { actions: [{ name: "transfer" }] } };
      throw new Error(`method "${method}" is not permitted by the read-only relay`);
    });
    const runtime: AgentRuntime = {
      agent: "funagent",
      permission: "active",
      chain: CHAIN,
      policy: emptyPolicy("XPR", CHAIN_ID),
      policyVersion: 1,
      enabled: true,
      token: Buffer.from(TOKEN, "utf8"),
      key: KEY,
    };
    daemon = new SignBoxDaemon(
      { socketPath: join(mkdtempSync(join(tmpdir(), "signbox-read-")), "signbox.sock") },
      { decode: decodeXprTransaction, signer: { sign: async () => ({ signature: "", transactionDigest: "" }) }, relay, now: () => NOW },
    );
    daemon.registerAgent(runtime);
  });

  it("whoami returns the agent's public identity — never key material", async () => {
    const res = (await daemon.handleRequest(readRequest({ op: "whoami" }))) as ReadResponseJson;
    expect(res).toMatchObject({
      status: "ok",
      op: "whoami",
      agent: "funagent",
      permission: "active",
      publicKey: "PUB_K1_agentkey",
      chain: "XPR",
      network: "testnet",
      chainId: CHAIN_ID,
    });
    expect(JSON.stringify(res)).not.toContain("PVT");
  });

  it("query relays a whitelisted read and returns the result", async () => {
    const res = (await daemon.handleRequest(
      readRequest({ op: "query", method: "get_currency_balance", params: { code: "eosio.token", account: "funagent", symbol: "XPR" } }),
    )) as ReadResponseJson;
    expect(res).toMatchObject({ status: "ok", op: "query", method: "get_currency_balance", result: ["12.3456 XPR"] });
    expect(relay.calls[0]).toMatchObject({ method: "get_currency_balance" });
  });

  it("query surfaces a relay refusal (e.g. a non-whitelisted method) as an error, never a throw", async () => {
    const res = (await daemon.handleRequest(readRequest({ op: "query", method: "get_producers" }))) as ReadResponseJson;
    expect(res).toMatchObject({ status: "error", op: "query" });
    expect("error" in res && res.error).toMatch(/not permitted/);
  });

  it("a wrong token is rejected the same way as an unknown agent", async () => {
    const res = (await daemon.handleRequest(
      readRequest({ op: "whoami", token: "tok_wrongwrongwrongwrong" }),
    )) as ReadResponseJson;
    expect(res).toMatchObject({ status: "error", op: "whoami" });
    expect("error" in res && res.error).toMatch(/authenticated/);
  });

  it("an expired window is refused", async () => {
    const res = (await daemon.handleRequest(
      readRequest({ op: "whoami", expiresAt: new Date(NOW - 1000).toISOString() }),
    )) as ReadResponseJson;
    expect(res).toMatchObject({ status: "error", op: "whoami" });
  });

  it("query without a relay configured fails closed", async () => {
    const noRelay = new SignBoxDaemon(
      { socketPath: join(mkdtempSync(join(tmpdir(), "signbox-norelay-")), "signbox.sock") },
      { decode: decodeXprTransaction, signer: { sign: async () => ({ signature: "", transactionDigest: "" }) }, now: () => NOW },
    );
    noRelay.registerAgent({
      agent: "funagent", permission: "active", chain: CHAIN, policy: emptyPolicy("XPR", CHAIN_ID),
      policyVersion: 1, enabled: true, token: Buffer.from(TOKEN, "utf8"), key: KEY,
    });
    const res = (await noRelay.handleRequest(readRequest({ op: "query", method: "get_account" }))) as ReadResponseJson;
    expect(res).toMatchObject({ status: "error", op: "query" });
    expect("error" in res && res.error).toMatch(/relay is not available/);
  });
});
