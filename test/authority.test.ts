/**
 * On-chain key-authority resolution + cache (#39).
 *
 * The XPR resolver accepts ONLY the MVP shape — a dedicated threshold-1
 * permission holding exactly the daemon key, no accounts/waits — and refuses
 * anything else. The cache binds results with a freshness TTL (rotation
 * detection) and fails closed on a resolver throw.
 */

import { describe, expect, it } from "vitest";
import { JsonRpc, Numeric } from "@proton/js";
import { resolveXprKeyAuthority } from "../src/chains/xpr/authority.js";
import { AuthorityCache } from "../src/daemon/authorityCache.js";
import { generateK1KeyPair } from "../src/chains/xpr/keygen.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const HEAD = () => new Date(Date.now() - 500).toISOString().replace("Z", "");
const wiring = { endpoints: ["http://127.0.0.1:1"], chainId: CHAIN_ID };

/**
 * Stub JsonRpc.prototype.fetch so the resolver's internally-built rpc returns
 * a crafted get_account. Returns a restorer.
 */
function stubAccount(account: (name: string) => unknown): () => void {
  const proto = JsonRpc.prototype as unknown as Record<string, unknown>;
  const saved = proto["fetch"];
  proto["fetch"] = async (path: string, body: unknown) => {
    if (path === "/v1/chain/get_info") return { chain_id: CHAIN_ID, head_block_time: HEAD() };
    if (path === "/v1/chain/get_account") {
      return account((body as { account_name: string }).account_name);
    }
    return {};
  };
  return () => {
    proto["fetch"] = saved;
  };
}

function permission(name: string, auth: unknown) {
  return { permissions: [{ perm_name: name, required_auth: auth }] };
}

describe("resolveXprKeyAuthority — MVP authority shape", () => {
  it("authorizes a threshold-1 single-key permission holding the daemon key", async () => {
    const pair = await generateK1KeyPair();
    const restore = stubAccount(() =>
      permission("agentperm", { threshold: 1, keys: [{ key: pair.publicKey, weight: 1 }], accounts: [], waits: [] }),
    );
    try {
      const r = await resolveXprKeyAuthority(wiring, "funagent", "agentperm", pair.publicKey);
      expect(r.authorized).toBe(true);
    } finally {
      restore();
    }
  });

  it("matches across legacy EOS ↔ PUB_K1 encodings of the same key", async () => {
    const pair = await generateK1KeyPair();
    const legacy = Numeric.publicKeyToLegacyString(Numeric.stringToPublicKey(pair.publicKey));
    const restore = stubAccount(() =>
      permission("agentperm", { threshold: 1, keys: [{ key: legacy, weight: 1 }], accounts: [], waits: [] }),
    );
    try {
      const r = await resolveXprKeyAuthority(wiring, "funagent", "agentperm", pair.publicKey);
      expect(r.authorized).toBe(true); // encoding-independent
    } finally {
      restore();
    }
  });

  it("refuses a rotated key, a wrong permission, threshold>1, multi-key, and delegated auth", async () => {
    const ours = await generateK1KeyPair();
    const other = await generateK1KeyPair();
    const cases: [string, unknown][] = [
      ["rotated key", permission("agentperm", { threshold: 1, keys: [{ key: other.publicKey, weight: 1 }], accounts: [], waits: [] })],
      ["threshold 2", permission("agentperm", { threshold: 2, keys: [{ key: ours.publicKey, weight: 2 }], accounts: [], waits: [] })],
      ["two keys", permission("agentperm", { threshold: 1, keys: [{ key: ours.publicKey, weight: 1 }, { key: other.publicKey, weight: 1 }], accounts: [], waits: [] })],
      ["delegated account", permission("agentperm", { threshold: 1, keys: [{ key: ours.publicKey, weight: 1 }], accounts: [{ permission: { actor: "x", permission: "active" }, weight: 1 }], waits: [] })],
      ["a wait", permission("agentperm", { threshold: 1, keys: [{ key: ours.publicKey, weight: 1 }], accounts: [], waits: [{ wait_sec: 60, weight: 1 }] })],
      ["missing permission", permission("owner", { threshold: 1, keys: [{ key: ours.publicKey, weight: 1 }], accounts: [], waits: [] })],
    ];
    for (const [label, account] of cases) {
      const restore = stubAccount(() => account);
      try {
        const r = await resolveXprKeyAuthority(wiring, "funagent", "agentperm", ours.publicKey);
        expect(r.authorized, label).toBe(false);
      } finally {
        restore();
      }
    }
  });

  it("refuses (never throws) when the endpoint is unreachable", async () => {
    const pair = await generateK1KeyPair();
    // No stub → real fetch against 127.0.0.1:1 fails; resolver rejects, the
    // cache turns that into `authorized:false`.
    const cache = new AuthorityCache((a, p, k) => resolveXprKeyAuthority(wiring, a, p, k));
    const r = await cache.check("funagent", "agentperm", pair.publicKey);
    expect(r.authorized).toBe(false);
  });
});

describe("AuthorityCache — freshness + rotation", () => {
  it("caches a positive result and re-resolves only after the freshness window", async () => {
    let nowMs = 1_000_000;
    let authorized = true;
    let calls = 0;
    const cache = new AuthorityCache(
      async () => {
        calls += 1;
        return { authorized };
      },
      { freshnessMs: 30_000, now: () => nowMs },
    );
    expect((await cache.check("a", "p", "k")).authorized).toBe(true);
    expect((await cache.check("a", "p", "k")).authorized).toBe(true);
    expect(calls).toBe(1); // within the window: one resolution

    // A rotation happens on-chain; the cache keeps trusting until the TTL.
    authorized = false;
    nowMs += 29_000;
    expect((await cache.check("a", "p", "k")).authorized).toBe(true);
    expect(calls).toBe(1);

    // Past the window: re-resolve picks up the rotation → refused.
    nowMs += 2_000;
    expect((await cache.check("a", "p", "k")).authorized).toBe(false);
    expect(calls).toBe(2);
  });

  it("caches a failure briefly (negative TTL) and does not hammer", async () => {
    let nowMs = 0;
    let calls = 0;
    const cache = new AuthorityCache(
      async () => {
        calls += 1;
        throw new Error("outage");
      },
      { negativeMs: 5_000, now: () => nowMs },
    );
    expect((await cache.check("a", "p", "k")).authorized).toBe(false);
    nowMs += 3_000;
    expect((await cache.check("a", "p", "k")).authorized).toBe(false);
    expect(calls).toBe(1); // negative cached
    nowMs += 3_000;
    expect((await cache.check("a", "p", "k")).authorized).toBe(false);
    expect(calls).toBe(2); // negative expired → retried
  });
});
