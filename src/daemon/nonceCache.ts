/**
 * Anti-replay nonce cache (spec §12.3, §15.7).
 *
 * A nonce is remembered until its request's expiry; presenting it twice
 * within that window is a replay. Fail closed: when the cache is full of
 * still-valid nonces, NEW requests are refused rather than evicting live
 * entries (an eviction would reopen the replay window).
 *
 * Nonces are namespaced PER AGENT, each agent getting its own capacity. A
 * single compromised agent flooding its own budget can therefore never
 * saturate the cache for the others (it would previously return "full" for
 * everyone — a cross-agent DoS on anti-replay).
 */

export class NonceCache {
  private readonly perAgent = new Map<string, Map<string, number>>();

  constructor(private readonly maxEntriesPerAgent = 100_000) {}

  /**
   * Register a nonce for a given agent. Returns:
   * - "ok"       — first sighting for this agent, registered;
   * - "replayed" — already seen for this agent and still within its window;
   * - "full"     — this agent's cache is saturated with live nonces (refuse).
   */
  register(agent: string, nonce: string, expiresAtMs: number, nowMs: number): "ok" | "replayed" | "full" {
    let entries = this.perAgent.get(agent);
    if (entries === undefined) {
      entries = new Map<string, number>();
      this.perAgent.set(agent, entries);
    }

    const existing = entries.get(nonce);
    if (existing !== undefined && existing > nowMs) {
      return "replayed";
    }
    if (entries.size >= this.maxEntriesPerAgent) {
      // Amortized cleanup: only sweep when saturated, so the hot path stays O(1).
      this.purge(entries, nowMs);
      if (entries.size >= this.maxEntriesPerAgent) {
        return "full";
      }
    }
    entries.set(nonce, expiresAtMs);
    return "ok";
  }

  private purge(entries: Map<string, number>, nowMs: number): void {
    for (const [nonce, expiry] of entries) {
      if (expiry <= nowMs) entries.delete(nonce);
    }
  }

  /** Live entry count for an agent (0 if unknown). Test/diagnostic aid. */
  sizeOf(agent: string): number {
    return this.perAgent.get(agent)?.size ?? 0;
  }
}
