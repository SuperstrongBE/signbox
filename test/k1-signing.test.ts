/**
 * K1 signing parity (#46) — the keystore's noble-based crypto judged by
 * @proton/js itself: derivations must match the SDK's, and every ground
 * canonical signature must verify AND recover through the SDK's own
 * Signature/PublicKey classes.
 */

import { describe, expect, it } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import protonPkg from "@proton/js";
import {
  derivePublicKeyK1,
  derivePublicKeyLegacy,
  signDigestK1Canonical,
  wifToPrivateKey,
} from "../src/keystore/k1.js";
import { generateK1KeyPair } from "../src/chains/xpr/keygen.js";

const { Key, Numeric } = protonPkg as unknown as {
  Key: {
    PrivateKey: { fromString(s: string): { getPublicKey(): { toString(): string } } };
    Signature: {
      fromString(s: string): {
        verify(digest: Buffer, pub: unknown, shouldHash: boolean): boolean;
        recover(digest: Buffer, shouldHash: boolean): { toString(): string };
      };
    };
    PublicKey: { fromString(s: string): unknown };
  };
  Numeric: {
    KeyType: { k1: number };
    signatureToString(sig: { type: number; data: Uint8Array }): string;
  };
};

/** Well-known throwaway test key (never fund it). */
const TEST_WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3";

function toSigK1(recovered: Uint8Array): string {
  const sigData = new Uint8Array(65);
  sigData[0] = 27 + 4 + recovered[0]!;
  sigData.set(recovered.subarray(1), 1);
  return Numeric.signatureToString({ type: Numeric.KeyType.k1, data: sigData });
}

describe("k1 primitives — parity with @proton/js", () => {
  it("derives the same PUB_K1 as the SDK, from the WIF", () => {
    const priv = wifToPrivateKey(TEST_WIF);
    const derived = derivePublicKeyK1(priv);
    const sdk = Key.PrivateKey.fromString(TEST_WIF).getPublicKey().toString();
    expect(derived).toBe(sdk);
    priv.fill(0);
  });

  it("derives matching keys for freshly generated pairs", async () => {
    for (let i = 0; i < 5; i++) {
      const pair = await generateK1KeyPair();
      const priv = wifToPrivateKey(pair.wif);
      expect(derivePublicKeyK1(priv)).toBe(pair.publicKey);
      priv.fill(0);
    }
  });

  it("every canonical signature verifies AND recovers through the SDK", () => {
    const priv = wifToPrivateKey(TEST_WIF);
    const pub = derivePublicKeyK1(priv);
    const pubObj = Key.PublicKey.fromString(pub);
    for (let i = 0; i < 50; i++) {
      const digest = createHash("sha256").update(randomBytes(64)).digest();
      const recovered = signDigestK1Canonical(priv, digest);
      // Canonicality bits (Antelope rule) on r and s:
      expect(recovered[1]! & 0x80).toBe(0);
      expect(recovered[33]! & 0x80).toBe(0);
      const sigStr = toSigK1(recovered);
      expect(sigStr).toMatch(/^SIG_K1_/);
      const sig = Key.Signature.fromString(sigStr);
      expect(sig.verify(digest, pubObj, false)).toBe(true);
      expect(sig.recover(digest, false).toString()).toBe(pub);
    }
    priv.fill(0);
  });

  it("rejects malformed WIFs and non-32-byte digests", () => {
    expect(() => wifToPrivateKey("not-a-wif")).toThrowError(
      expect.objectContaining({ code: "BAD_FORMAT" }),
    );
    // Valid base58 but wrong payload (checksum/version cannot both hold).
    expect(() => wifToPrivateKey("111111111111111111111111111111111111")).toThrowError(
      expect.objectContaining({ code: "BAD_FORMAT" }),
    );
    const priv = wifToPrivateKey(TEST_WIF);
    expect(() => signDigestK1Canonical(priv, new Uint8Array(31))).toThrowError(
      expect.objectContaining({ code: "BAD_FORMAT" }),
    );
    priv.fill(0);
  });

  it("legacy EOS encoding derives correctly (old keystores)", () => {
    const priv = wifToPrivateKey(TEST_WIF);
    // The canonical test key's well-known legacy encoding.
    expect(derivePublicKeyLegacy(priv)).toBe(
      "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV",
    );
    priv.fill(0);
  });
});
