/**
 * Verified RPC access (#40, INV-009) — chain-id pinning that actually FIRES.
 *
 * `pinChainId` wraps get_info, but a code path that never calls get_info
 * (get_table_rows, get_abi, fetch…) never executed the verification: the pin
 * was decorative on exactly the security-critical reads (policy rows). This
 * wrapper closes that hole.
 *
 * Every JsonRpc method funnels through `fetch`, so `fetch` is the ONE choke
 * point guarded here: before any request other than the verification itself
 * (`/v1/chain/get_info` — recognized by path, deterministically, so there is
 * no reentrancy flag to race), a verification not older than `freshnessMs`
 * must have succeeded. The wrapped get_info:
 *  - refuses a mismatching chain id (a lying or cross-chain endpoint can
 *    never be failed-over into, INV-009);
 *  - refuses a stale head (`head_block_time` absent, unparsable, or older
 *    than `maxHeadLagMs`): a node frozen in the past must not feed policy
 *    state, TAPOS headers, or reads.
 *
 * Concurrent data calls share one in-flight verification promise. Residual
 * window: JsonRpc may fail over between the verification and the data call
 * inside one freshness window — bound documented in docs/endpoint-trust.md.
 */

import type { JsonRpc } from "@proton/js";
import { SigningError } from "./adapter.js";

export interface VerifiedRpcOptions {
  chainId: string;
  /** Re-verify at most this often before data calls. */
  freshnessMs?: number;
  /** Refuse heads older than this (stale/frozen node). */
  maxHeadLagMs?: number;
  /** Test seam. */
  now?: () => number;
}

const DEFAULT_FRESHNESS_MS = 30_000;
const DEFAULT_MAX_HEAD_LAG_MS = 120_000;
const VERIFY_PATH = "/v1/chain/get_info";

/**
 * Wrap a JsonRpc so its requests refuse unless a fresh, pinned get_info
 * verification succeeded. Returns the same instance, wrapped in place (the
 * style pinChainId established).
 */
export function verifiedRpc(rpc: JsonRpc, options: VerifiedRpcOptions): JsonRpc {
  const freshnessMs = options.freshnessMs ?? DEFAULT_FRESHNESS_MS;
  const maxHeadLagMs = options.maxHeadLagMs ?? DEFAULT_MAX_HEAD_LAG_MS;
  const now = options.now ?? Date.now;

  let verifiedAtMs: number | undefined;
  let inflight: Promise<void> | undefined;

  const originalGetInfo = rpc.get_info.bind(rpc);
  rpc.get_info = async () => {
    const info = await originalGetInfo();
    if (info.chain_id !== options.chainId) {
      throw new SigningError("RPC chain id does not match the pinned chain id");
    }
    const headTime = (info as { head_block_time?: string }).head_block_time;
    if (typeof headTime !== "string") {
      throw new SigningError("RPC get_info carries no head_block_time");
    }
    const headMs = Date.parse(`${headTime}Z`);
    if (!Number.isFinite(headMs) || now() - headMs > maxHeadLagMs) {
      throw new SigningError("RPC head is stale — refusing to trust this endpoint's state");
    }
    verifiedAtMs = now();
    return info;
  };

  const ensureVerified = (): Promise<void> => {
    if (verifiedAtMs !== undefined && now() - verifiedAtMs < freshnessMs) {
      return Promise.resolve();
    }
    if (inflight === undefined) {
      inflight = rpc
        .get_info()
        .then(() => undefined)
        .finally(() => {
          inflight = undefined;
        });
    }
    return inflight;
  };

  const originalFetch = rpc.fetch.bind(rpc);
  rpc.fetch = async (path: string, body: unknown) => {
    // The verification's own request must pass through (get_info funnels
    // here too); everything else waits for a fresh verification first. A
    // caller-issued get_info read is equally harmless: its RESULT is only
    // trusted through the wrapped, checking get_info above.
    if (path !== VERIFY_PATH) await ensureVerified();
    return originalFetch(path, body);
  };

  return rpc;
}
