import { describe, expect, it } from "vitest";
import {
  evaluatePolicy,
  collectProviderQueries,
  type EvaluationContext,
  type ProviderEvidenceMap,
} from "../src/core/policy/engine.js";
import { validatePolicy, type Policy } from "../src/core/policy/schema.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import { resolveProviders } from "../src/daemon/providerResolver.js";
import type { ChainReadRelay } from "../src/daemon/chainRelay.js";
import type { ChainContext, DecodedTransaction } from "../src/core/types.js";
import { xprDialect } from "../src/chains/xpr/dialect.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const CHAIN: ChainContext = { chain: "XPR", network: "testnet", chainId: CHAIN_ID };
const CTX: EvaluationContext = { agent: "funagent", agentPermission: "active", chainId: CHAIN_ID, policyVersion: 1, dialect: xprDialect };

/** Allow a transfer only if the recipient is in an on-chain whitelist row. */
const WHITELIST_POLICY: Policy = validatePolicy({
  schemaVersion: 1,
  default: "deny",
  chain: { name: "XPR", chainId: CHAIN_ID },
  rules: [
    {
      id: "allow-whitelisted",
      effect: "allow",
      match: { contract: "eosio.token", action: "transfer", "data.from": "$agent" },
      providers: [
        {
          provider: "xpr.rpc.tableRow",
          args: { contract: "whitelister", table: "lists", key: "$agent" },
          select: "allowed",
          op: "contains",
          value: "$data.to",
        },
      ],
    },
  ],
}, xprDialect);

function transfer(to: string): DecodedTransaction {
  return decodeXprTransaction(
    {
      actions: [
        {
          account: "eosio.token",
          name: "transfer",
          authorization: [{ actor: "funagent", permission: "active" }],
          data: { from: "funagent", to, quantity: "1.0000 XPR", memo: "" },
        },
      ],
    },
    CHAIN,
  );
}

/** Build an evidence map for the single query this policy/tx produces. */
function evidenceFor(tx: DecodedTransaction, value: ProviderEvidenceMap[string]): {
  key: string;
  evidence: ProviderEvidenceMap;
} {
  const queries = collectProviderQueries(tx, WHITELIST_POLICY, CTX);
  expect(queries).toHaveLength(1);
  return { key: queries[0]!.key, evidence: { [queries[0]!.key]: value } };
}

describe("policy providers — xpr.rpc.tableRow (§8.4)", () => {
  it("collects one query with args resolved from the transaction", () => {
    const [q] = collectProviderQueries(transfer("alice"), WHITELIST_POLICY, CTX);
    expect(q).toMatchObject({
      provider: "xpr.rpc.tableRow",
      args: { contract: "whitelister", scope: "whitelister", table: "lists", key: "funagent" },
    });
  });

  it("allows when the row's array CONTAINS the recipient", () => {
    const tx = transfer("alice");
    const { evidence } = evidenceFor(tx, { ok: true, found: true, row: { allowed: ["alice", "bob"] } });
    const { decision } = evaluatePolicy(tx, WHITELIST_POLICY, { ...CTX, evidence });
    expect(decision.effect).toBe("allow");
  });

  it("denies when the array does NOT contain the recipient", () => {
    const tx = transfer("mallory");
    const { evidence } = evidenceFor(tx, { ok: true, found: true, row: { allowed: ["alice", "bob"] } });
    const { decision } = evaluatePolicy(tx, WHITELIST_POLICY, { ...CTX, evidence });
    expect(decision).toMatchObject({ effect: "deny", code: "DEFAULT_DENY" });
  });

  it("denies when the whitelist row is absent (deterministic not-found)", () => {
    const tx = transfer("alice");
    const { evidence } = evidenceFor(tx, { ok: true, found: false, row: null });
    const { decision } = evaluatePolicy(tx, WHITELIST_POLICY, { ...CTX, evidence });
    expect(decision).toMatchObject({ effect: "deny", code: "DEFAULT_DENY" });
  });

  it("fails closed with PROVIDER_UNAVAILABLE when evidence could not be resolved", () => {
    const tx = transfer("alice");
    const { evidence } = evidenceFor(tx, { ok: false });
    const { decision } = evaluatePolicy(tx, WHITELIST_POLICY, { ...CTX, evidence });
    expect(decision).toMatchObject({ effect: "deny", code: "PROVIDER_UNAVAILABLE" });
  });

  it("fails closed when NO evidence is injected at all (provider never resolved)", () => {
    const tx = transfer("alice");
    const { decision } = evaluatePolicy(tx, WHITELIST_POLICY, CTX);
    expect(decision).toMatchObject({ effect: "deny", code: "PROVIDER_UNAVAILABLE" });
  });

  it("supports the `eq` operator on a scalar field", () => {
    const policy = validatePolicy({
      schemaVersion: 1,
      default: "deny",
      chain: { name: "XPR", chainId: CHAIN_ID },
      rules: [
        {
          id: "allow-if-tier-gold",
          effect: "allow",
          match: { contract: "eosio.token", action: "transfer", "data.from": "$agent" },
          providers: [
            {
              provider: "xpr.rpc.tableRow",
              args: { contract: "registry", table: "tiers", key: "$data.to" },
              select: "tier",
              op: "eq",
              value: "gold",
            },
          ],
        },
      ],
    }, xprDialect);
    const tx = transfer("alice");
    const queries = collectProviderQueries(tx, policy, CTX);
    const goldEvidence = { [queries[0]!.key]: { ok: true, found: true, row: { tier: "gold" } } } as ProviderEvidenceMap;
    expect(evaluatePolicy(tx, policy, { ...CTX, evidence: goldEvidence }).decision.effect).toBe("allow");
    const bronzeEvidence = { [queries[0]!.key]: { ok: true, found: true, row: { tier: "bronze" } } } as ProviderEvidenceMap;
    expect(evaluatePolicy(tx, policy, { ...CTX, evidence: bronzeEvidence }).decision).toMatchObject({ effect: "deny" });
  });
});

describe("provider resolver — normalization + fail closed", () => {
  const query = collectProviderQueries(transfer("alice"), WHITELIST_POLICY, CTX)[0]!;

  it("normalizes a found row", async () => {
    const relay: ChainReadRelay = { call: async () => ({ rows: [{ allowed: ["alice"] }], more: false }) };
    const evidence = await resolveProviders([query], relay, xprDialect);
    expect(evidence[query.key]).toMatchObject({ ok: true, found: true, row: { allowed: ["alice"] } });
  });

  it("normalizes an empty result to a deterministic not-found", async () => {
    const relay: ChainReadRelay = { call: async () => ({ rows: [], more: false }) };
    const evidence = await resolveProviders([query], relay, xprDialect);
    expect(evidence[query.key]).toMatchObject({ ok: true, found: false, row: null });
  });

  it("fails closed when the relay throws (e.g. timeout / unreachable)", async () => {
    const relay: ChainReadRelay = {
      call: async () => {
        throw new Error("unreachable");
      },
    };
    const evidence = await resolveProviders([query], relay, xprDialect);
    expect(evidence[query.key]).toEqual({ ok: false });
  });

  it("fails closed when no relay is available", async () => {
    const evidence = await resolveProviders([query], undefined, xprDialect);
    expect(evidence[query.key]).toEqual({ ok: false });
  });
});
