/**
 * XPR read-only relay — strict allow-list of Antelope `/v1/chain/*` read
 * methods. See daemon/chainRelay.ts for the trust rationale (the relay can
 * never reach a state-changing endpoint, INV-011; chain id pinned, INV-009).
 */

import { JsonRpc } from "@proton/js";
import { pinChainId } from "./adapter.js";
import type { ChainReadRelay } from "../../daemon/chainRelay.js";

/** Read-only `/v1/chain/*` methods the agent may call. */
export const READ_ONLY_METHODS: ReadonlySet<string> = new Set([
  "get_account",
  "get_currency_balance",
  "get_currency_stats",
  "get_table_rows",
  "get_table_by_scope",
  "get_info",
  "get_block",
  "get_block_info",
  "get_abi",
  "get_raw_abi",
  "get_code",
  "get_producers",
  "get_accounts_by_authorizers",
]);

export interface XprChainReadRelayOptions {
  endpoints: string[];
  chainId: string;
}

export class XprChainReadRelay implements ChainReadRelay {
  constructor(private readonly options: XprChainReadRelayOptions) {}

  async call(method: string, params: unknown): Promise<unknown> {
    if (!READ_ONLY_METHODS.has(method)) {
      // Fail closed: the agent can never reach a state-changing endpoint here.
      throw new Error(`method "${method}" is not permitted by the read-only relay`);
    }
    const rpc = new JsonRpc(this.options.endpoints);
    pinChainId(rpc, this.options.chainId);
    const body = params !== null && typeof params === "object" ? params : {};
    return rpc.fetch(`/v1/chain/${method}`, body);
  }
}
