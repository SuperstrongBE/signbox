/**
 * Reads agent policy rows from the on-chain SignBox contract (spec §14.1 —
 * the contract is the source of truth).
 *
 * Uses @proton/js `get_table_rows`, which returns already-decoded JSON, so no
 * ABI is needed client-side. The chain id is pinned (INV-009) via the same
 * guard as the signer: a lying RPC that reports another chain refuses before
 * its rows are ever trusted.
 */

import { JsonRpc } from "@proton/js";
import { pinChainId } from "../chains/xpr/adapter.js";

/** One raw policy row, exactly as the contract stores it (spec §7.1). */
export interface PolicyRowRaw {
  agent: string;
  authority: string;
  agentperm: string;
  version: number;
  policyhash: string; // 64 lowercase hex
  policyjson: string; // canonical JCS
  enabled: boolean;
  updatedat: number;
}

/** Injectable seam so the cache can be tested without a live chain. */
export interface PolicyReader {
  read(agent: string): Promise<PolicyRowRaw | null>;
}

export interface ChainPolicyReaderOptions {
  endpoints: string[];
  chainId: string;
  /** Account hosting the SignBox contract (e.g. "signbox"). */
  contractAccount: string;
}

export class ChainPolicyReader implements PolicyReader {
  constructor(private readonly options: ChainPolicyReaderOptions) {}

  async read(agent: string): Promise<PolicyRowRaw | null> {
    const rpc = new JsonRpc(this.options.endpoints);
    pinChainId(rpc, this.options.chainId);

    const result = (await rpc.get_table_rows({
      code: this.options.contractAccount,
      scope: this.options.contractAccount,
      table: "policies",
      lower_bound: agent,
      upper_bound: agent,
      limit: 1,
      json: true,
    })) as { rows: unknown[] };

    const row = result.rows[0];
    if (row === undefined || row === null || typeof row !== "object") return null;
    const r = row as Record<string, unknown>;

    // Defensive: the RPC's name-bound handling must have returned OUR agent.
    if (r["agent"] !== agent) return null;

    if (
      typeof r["authority"] !== "string" ||
      typeof r["agentperm"] !== "string" ||
      typeof r["policyhash"] !== "string" ||
      typeof r["policyjson"] !== "string"
    ) {
      return null;
    }

    return {
      agent,
      authority: r["authority"],
      agentperm: r["agentperm"],
      version: Number(r["version"]),
      policyhash: r["policyhash"].toLowerCase(),
      policyjson: r["policyjson"],
      // AssemblyScript bool serializes as 0/1 or true/false depending on ABI.
      enabled: r["enabled"] === true || r["enabled"] === 1 || r["enabled"] === "1",
      updatedat: Number(r["updatedat"] ?? 0),
    };
  }
}
