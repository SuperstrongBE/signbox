/**
 * Anti-replay nonce cache (spec §12.3, §15.7).
 *
 * A nonce is remembered until its request's expiry; presenting it twice
 * within that window is a replay. Fail closed: when the cache is full of
 * still-valid nonces, NEW requests are refused rather than evicting live
 * entries (an eviction would reopen the replay window).
 */

export class NonceCache {
  private readonly entries = new Map<string, number>();

  constructor(private readonly maxEntries = 100_000) {}

  /**
   * Register a nonce. Returns:
   * - "ok"       — first sighting, registered;
   * - "replayed" — already seen and still within its validity window;
   * - "full"     — cache saturated with live nonces (caller must refuse).
   */
  register(nonce: string, expiresAtMs: number, nowMs: number): "ok" | "replayed" | "full" {
    const existing = this.entries.get(nonce);
    if (existing !== undefined && existing > nowMs) {
      return "replayed";
    }
    if (this.entries.size >= this.maxEntries) {
      // Amortized cleanup: only sweep when saturated, so the hot path stays O(1).
      this.purge(nowMs);
      if (this.entries.size >= this.maxEntries) {
        return "full";
      }
    }
    this.entries.set(nonce, expiresAtMs);
    return "ok";
  }

  private purge(nowMs: number): void {
    for (const [nonce, expiry] of this.entries) {
      if (expiry <= nowMs) this.entries.delete(nonce);
    }
  }

  get size(): number {
    return this.entries.size;
  }
}
