/**
 * Read-only chain relay (agent convenience — NOT part of the trust boundary).
 *
 * An agent talks only to the daemon socket; it has no RPC of its own. This
 * relay lets it read public on-chain data (its balance, an account, a table)
 * through the daemon's pinned endpoints — WITHOUT ever gaining a way to submit
 * a transaction. That is the whole point: the relay is a strict allow-list of
 * read methods. Anything that writes/computes state (push_transaction,
 * send_transaction, compute/read-only tx, …) is refused, so the policy gate can
 * never be bypassed through this door (INV-011).
 *
 * The chain id is pinned (INV-009): a get_info that reports another chain
 * throws before its data is trusted. The endpoints are operator config, not
 * agent-controlled, so the relay is not an SSRF surface.
 */

import { JsonRpc } from "@proton/js";
import { pinChainId } from "../chains/xpr/adapter.js";

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

export interface ChainReadRelay {
  /** Call a whitelisted read-only method; throws on a disallowed method. */
  call(method: string, params: unknown): Promise<unknown>;
}

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
