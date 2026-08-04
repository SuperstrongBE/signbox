import { describe, expect, it } from "vitest";
import { NonceCache } from "../src/daemon/nonceCache.js";

const EXPIRY = 60_000;
const NOW = 0;

describe("NonceCache — per-agent anti-replay (§15.7)", () => {
  it("registers a first-seen nonce and replays it within the window", () => {
    const cache = new NonceCache();
    expect(cache.register("agentA", "n1", EXPIRY, NOW)).toBe("ok");
    expect(cache.register("agentA", "n1", EXPIRY, NOW)).toBe("replayed");
  });

  it("scopes nonces per agent — the same nonce is fresh for a different agent", () => {
    const cache = new NonceCache();
    expect(cache.register("agentA", "shared", EXPIRY, NOW)).toBe("ok");
    // Same nonce string, different agent: must NOT be treated as a replay.
    expect(cache.register("agentB", "shared", EXPIRY, NOW)).toBe("ok");
  });

  it("one agent saturating its budget cannot DoS another agent", () => {
    const cache = new NonceCache(3); // tiny per-agent budget
    for (let i = 0; i < 3; i++) {
      expect(cache.register("noisy", `n${i}`, EXPIRY, NOW)).toBe("ok");
    }
    // The noisy agent is now full...
    expect(cache.register("noisy", "n-overflow", EXPIRY, NOW)).toBe("full");
    // ...but a different agent is entirely unaffected.
    expect(cache.register("victim", "v0", EXPIRY, NOW)).toBe("ok");
    expect(cache.sizeOf("victim")).toBe(1);
  });

  it("frees an agent's slots once its nonces expire", () => {
    const cache = new NonceCache(2);
    expect(cache.register("a", "n0", EXPIRY, NOW)).toBe("ok");
    expect(cache.register("a", "n1", EXPIRY, NOW)).toBe("ok");
    expect(cache.register("a", "n2", EXPIRY, NOW)).toBe("full");
    // After both entries expire, the sweep reclaims room on the next register.
    const later = EXPIRY + 1;
    expect(cache.register("a", "n2", later + EXPIRY, later)).toBe("ok");
  });
});
