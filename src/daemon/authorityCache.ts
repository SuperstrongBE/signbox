/**
 * On-chain key-authority cache (#39) — bounded-freshness verification that the
 * daemon's signing key is still authorized by the account's on-chain
 * permission. Ephemeral (in-memory): unlike quotas/policy it holds no value,
 * only a recent verification, so it never persists.
 *
 * Fail closed: a resolver that throws (network/parse) is cached as NOT
 * authorized for a short negative TTL — a lookup failure can never be read as
 * "authorized". A key/authority ROTATION is detected on the next re-resolve
 * after the positive TTL expires; that TTL is the rotation-detection bound and
 * is documented in docs/endpoint-trust.md.
 */

import type { KeyAuthorityResult } from "../chains/registry.js";

export type AuthorityResolver = (
  account: string,
  permission: string,
  expectedPublicKey: string,
) => Promise<KeyAuthorityResult>;

export interface AuthorityCacheOptions {
  /** How long a positive result is trusted before re-resolving (rotation bound). */
  freshnessMs?: number;
  /** How long a failure/negative is cached (avoids hammering on an outage). */
  negativeMs?: number;
  now?: () => number;
}

interface Entry {
  result: KeyAuthorityResult;
  verifiedAtMs: number;
}

const DEFAULT_FRESHNESS_MS = 30_000;
const DEFAULT_NEGATIVE_MS = 5_000;
/** Field separator for the composite cache key (never present in an id/key). */
const SEP = String.fromCharCode(0x1f); // ASCII unit separator

export class AuthorityCache {
  private readonly entries = new Map<string, Entry>();
  private readonly freshnessMs: number;
  private readonly negativeMs: number;
  private readonly now: () => number;

  constructor(
    private readonly resolve: AuthorityResolver,
    options: AuthorityCacheOptions = {},
  ) {
    this.freshnessMs = options.freshnessMs ?? DEFAULT_FRESHNESS_MS;
    this.negativeMs = options.negativeMs ?? DEFAULT_NEGATIVE_MS;
    this.now = options.now ?? Date.now;
  }

  /** Bind key by (account, permission, key). A resolver throw means not authorized. */
  async check(account: string, permission: string, expectedPublicKey: string): Promise<KeyAuthorityResult> {
    const cacheKey = [account, permission, expectedPublicKey].join(SEP);
    const now = this.now();
    const cached = this.entries.get(cacheKey);
    if (cached !== undefined) {
      const ttl = cached.result.authorized ? this.freshnessMs : this.negativeMs;
      if (now - cached.verifiedAtMs < ttl) return cached.result;
    }

    let result: KeyAuthorityResult;
    try {
      result = await this.resolve(account, permission, expectedPublicKey);
    } catch {
      result = { authorized: false, reason: "authority lookup failed" };
    }
    this.entries.set(cacheKey, { result, verifiedAtMs: now });
    return result;
  }

  /** Drop a cached binding (e.g. after an observed rotation). */
  invalidate(account: string, permission: string, expectedPublicKey: string): void {
    this.entries.delete([account, permission, expectedPublicKey].join(SEP));
  }
}
