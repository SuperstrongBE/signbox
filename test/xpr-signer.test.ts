import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { Api, JsonRpc, JsSignatureProvider } from "@proton/js";
import { XprTransactionSigner, SigningError, pinChainId } from "../src/chains/xpr/adapter.js";
import { decodeXprTransaction } from "../src/chains/xpr/decode.js";
import type { ChainContext, KeyHandle } from "../src/core/types.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const CHAIN: ChainContext = { chain: "XPR", network: "testnet", chainId: CHAIN_ID };

/** Well-known throwaway test key (never fund it). */
const TEST_WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

const KEY: KeyHandle = {
  keyId: "k-test",
  publicKey: "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
  exportPolicy: "non-exportable",
  chain: CHAIN,
  agent: "superagent",
  permission: "xp2vr3",
};

/** Minimal eosio.token ABI — enough to serialize/deserialize `transfer`. */
const TOKEN_ABI = {
  version: "eosio::abi/1.1",
  types: [],
  structs: [
    {
      name: "transfer",
      base: "",
      fields: [
        { name: "from", type: "name" },
        { name: "to", type: "name" },
        { name: "quantity", type: "asset" },
        { name: "memo", type: "string" },
      ],
    },
  ],
  actions: [{ name: "transfer", type: "transfer", ricardian_contract: "" }],
  tables: [],
  ricardian_clauses: [],
  error_messages: [],
  abi_extensions: [],
  variants: [],
};

const FIXED_TAPOS = {
  expiration: "2026-07-30T00:00:00.000",
  ref_block_num: 12345,
  ref_block_prefix: 987654321,
};

function offlineApiFactory(wif: string): Api {
  const rpc = new JsonRpc(["http://127.0.0.1:1"]);
  // @proton/js calls rpc.get_info() unconditionally inside transact(); with
  // a provided transactionHeader its result is unused, so stub it to keep
  // the test fully offline and deterministic.
  (rpc as unknown as { get_info: () => Promise<unknown> }).get_info = async () => ({
    chain_id: CHAIN_ID,
  });
  const api = new Api({
    rpc,
    signatureProvider: new JsSignatureProvider([wif]) as unknown as NonNullable<
      ConstructorParameters<typeof Api>[0]["signatureProvider"]
    >,
    authorityProvider: { getRequiredKeys: async (args) => args.availableKeys },
  });
  (api as unknown as { cachedAbis: Map<string, unknown> }).cachedAbis.set("eosio.token", {
    rawAbi: new Uint8Array(0),
    abi: TOKEN_ABI,
  });
  return api;
}

function makeSigner(): XprTransactionSigner {
  return new XprTransactionSigner({
    endpoints: ["http://127.0.0.1:1"],
    chainId: CHAIN_ID,
    privateKeyProvider: async () => TEST_WIF,
    taposProvider: async () => FIXED_TAPOS,
    apiFactory: offlineApiFactory,
  });
}

const TRANSFER_JSON = {
  actions: [
    {
      account: "eosio.token",
      name: "transfer",
      authorization: [{ actor: "superagent", permission: "xp2vr3" }],
      data: { from: "superagent", to: "alice", quantity: "10.0000 XPR", memo: "tip" },
    },
  ],
};

describe("XprTransactionSigner (offline, deterministic)", () => {
  it("signs the exact validated JSON and returns a K1 signature", async () => {
    const tx = decodeXprTransaction(TRANSFER_JSON, CHAIN);
    const result = await makeSigner().sign(tx, KEY);
    expect(result.signature).toMatch(/^SIG_K1_/);
    expect(result.transactionDigest).toMatch(/^[0-9a-f]{64}$/);
    const signed = result.signedTransaction as { packedTransaction: string; signatures: string[] };
    expect(signed.packedTransaction).toMatch(/^[0-9a-f]+$/);
    expect(signed.signatures).toEqual([result.signature]);
  });

  it("is deterministic: same input, same TAPOS, same digest", async () => {
    const tx = decodeXprTransaction(TRANSFER_JSON, CHAIN);
    const a = await makeSigner().sign(tx, KEY);
    const b = await makeSigner().sign(tx, KEY);
    expect(a.transactionDigest).toBe(b.transactionDigest);
    expect((a.signedTransaction as { packedTransaction: string }).packedTransaction).toBe(
      (b.signedTransaction as { packedTransaction: string }).packedTransaction,
    );
  });

  it("computes the digest over chainId ‖ packed_trx ‖ zero32", async () => {
    const tx = decodeXprTransaction(TRANSFER_JSON, CHAIN);
    const result = await makeSigner().sign(tx, KEY);
    const packed = Buffer.from(
      (result.signedTransaction as { packedTransaction: string }).packedTransaction,
      "hex",
    );
    const expected = createHash("sha256")
      .update(Buffer.from(CHAIN_ID, "hex"))
      .update(packed)
      .update(Buffer.alloc(32))
      .digest("hex");
    expect(result.transactionDigest).toBe(expected);
  });

  it("the signed bytes round-trip to exactly the validated JSON (WYSIWYS)", async () => {
    const tx = decodeXprTransaction(TRANSFER_JSON, CHAIN);
    const result = await makeSigner().sign(tx, KEY);
    const api = offlineApiFactory(TEST_WIF);
    const packed = Buffer.from(
      (result.signedTransaction as { packedTransaction: string }).packedTransaction,
      "hex",
    );
    const decoded = await api.deserializeTransactionWithActions(packed);
    expect(decoded.actions).toHaveLength(1);
    expect(decoded.actions[0]).toMatchObject({
      account: "eosio.token",
      name: "transfer",
      data: { from: "superagent", to: "alice", quantity: "10.0000 XPR", memo: "tip" },
    });
    // The envelope is SignBox's, not the agent's: TAPOS came from the signer.
    expect(decoded.expiration).toBe(FIXED_TAPOS.expiration);
    expect(decoded.ref_block_num).toBe(FIXED_TAPOS.ref_block_num);
  });

  it("refuses when the round-trip diverges from the validated JSON", async () => {
    const signer = new XprTransactionSigner({
      endpoints: ["http://127.0.0.1:1"],
      chainId: CHAIN_ID,
      privateKeyProvider: async () => TEST_WIF,
      taposProvider: async () => FIXED_TAPOS,
      apiFactory: (wif) => {
        const api = offlineApiFactory(wif);
        const original = api.deserializeTransactionWithActions.bind(api);
        // Simulate an ABI/serialization divergence: the bytes decode to a
        // different recipient than the one that was validated.
        api.deserializeTransactionWithActions = async (raw) => {
          const decoded = await original(raw);
          (decoded.actions[0]!.data as Record<string, unknown>)["to"] = "mallory";
          return decoded;
        };
        return api;
      },
    });
    const tx = decodeXprTransaction(TRANSFER_JSON, CHAIN);
    await expect(signer.sign(tx, KEY)).rejects.toThrow(SigningError);
  });

  it("refuses a transaction without a validated source", async () => {
    const tx = decodeXprTransaction(TRANSFER_JSON, CHAIN);
    delete (tx as { source?: unknown }).source;
    await expect(makeSigner().sign(tx, KEY)).rejects.toThrow(SigningError);
  });

  it("refuses a key pinned to another chain (INV-013)", async () => {
    const tx = decodeXprTransaction(TRANSFER_JSON, CHAIN);
    const foreignKey: KeyHandle = {
      ...KEY,
      chain: { ...CHAIN, chainId: "b".repeat(64) },
    };
    await expect(makeSigner().sign(tx, foreignKey)).rejects.toThrow(SigningError);
  });

  it("refuses to sign when the RPC reports another chain id (INV-009, §17.4)", async () => {
    const rpc = new JsonRpc(["http://127.0.0.1:1"]);
    (rpc as unknown as { get_info: () => Promise<unknown> }).get_info = async () => ({
      chain_id: "b".repeat(64), // a lying or misconfigured endpoint
    });
    pinChainId(rpc, CHAIN_ID);
    await expect(rpc.get_info()).rejects.toThrow(SigningError);

    // And with the honest chain id, the pin is transparent.
    const honest = new JsonRpc(["http://127.0.0.1:1"]);
    (honest as unknown as { get_info: () => Promise<unknown> }).get_info = async () => ({
      chain_id: CHAIN_ID,
    });
    pinChainId(honest, CHAIN_ID);
    await expect(honest.get_info()).resolves.toMatchObject({ chain_id: CHAIN_ID });
  });

  it("caller mutations after decode cannot change what is signed (INV-014)", async () => {
    const input = structuredClone(TRANSFER_JSON);
    const tx = decodeXprTransaction(input, CHAIN);
    // The agent mutates its own object after validation…
    input.actions[0]!.data.to = "mallory";
    input.actions[0]!.data.quantity = "999999.0000 XPR";
    const result = await makeSigner().sign(tx, KEY);
    const api = offlineApiFactory(TEST_WIF);
    const decoded = await api.deserializeTransactionWithActions(
      Buffer.from(
        (result.signedTransaction as { packedTransaction: string }).packedTransaction,
        "hex",
      ),
    );
    // …and the signed bytes still carry the validated values.
    expect(decoded.actions[0]!.data).toMatchObject({ to: "alice", quantity: "10.0000 XPR" });
  });
});
