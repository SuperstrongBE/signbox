/**
 * Policy-reader seam — how the policy cache reads agent policy rows from the
 * chain's policy registry (spec §14.1, the registry is the source of truth).
 *
 * Chain implementations live under src/chains/<chain>/ and are resolved
 * through the chain registry (issue #44). The injectable interface keeps the
 * cache testable without a live chain.
 */

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
