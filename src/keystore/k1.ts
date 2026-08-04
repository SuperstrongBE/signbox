/**
 * K1 (secp256k1) primitives for the encrypted-file backend's STORAGE formats.
 *
 * Existing keystore files hold the secret as a WIF string and declare the
 * public key as a "PUB_K1_…" (or legacy "EOS…") string — so decoding those
 * formats is the backend's own business (they are its on-disk vocabulary),
 * while chain-side SIGNATURE formatting stays in src/chains/*.
 *
 * Signing follows the Antelope-family canonical rule: grind deterministic
 * RFC6979 signatures (varying extraEntropy) until both r and s clear the
 * canonicality bits. Verified against @proton/js's own Signature.verify /
 * recover (see test/k1-signing.test.ts).
 */

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { base58 } from "@scure/base";
import { createHash } from "node:crypto";
import { KeystoreError } from "../core/errors.js";

function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

/**
 * Decode a stored K1 secret to its 32-byte scalar. Supports both formats
 * SignBox keystores hold: the modern "PVT_K1_…" string (what keygen writes)
 * and the legacy base58check WIF ("5…"). Caller wipes the returned buffer.
 */
export function wifToPrivateKey(wif: string): Buffer {
  let decoded: Uint8Array;
  if (wif.startsWith("PVT_K1_")) {
    try {
      decoded = base58.decode(wif.slice("PVT_K1_".length));
    } catch {
      throw new KeystoreError("BAD_FORMAT", "stored secret is not valid base58");
    }
    if (decoded.length !== 36) {
      throw new KeystoreError("BAD_FORMAT", "stored secret is not a K1 private key");
    }
    const data = decoded.slice(0, 32);
    if (!Buffer.from(decoded.slice(32)).equals(k1Checksum(data, "K1"))) {
      throw new KeystoreError("BAD_FORMAT", "stored secret failed its K1 checksum");
    }
    return Buffer.from(data);
  }
  try {
    decoded = base58.decode(wif);
  } catch {
    throw new KeystoreError("BAD_FORMAT", "stored secret is not valid base58");
  }
  if (decoded.length !== 37 || decoded[0] !== 0x80) {
    throw new KeystoreError("BAD_FORMAT", "stored secret is not a K1 WIF");
  }
  const payload = decoded.slice(0, 33);
  const checksum = decoded.slice(33);
  const expected = sha256(sha256(payload)).subarray(0, 4);
  if (!Buffer.from(checksum).equals(expected)) {
    throw new KeystoreError("BAD_FORMAT", "stored secret failed its WIF checksum");
  }
  return Buffer.from(payload.subarray(1));
}

function k1Checksum(data: Uint8Array, suffix: string): Buffer {
  return Buffer.from(
    ripemd160(Buffer.concat([Buffer.from(data), Buffer.from(suffix, "utf8")])),
  ).subarray(0, 4);
}

/** Derive the compressed public key and encode it as a "PUB_K1_…" string. */
export function derivePublicKeyK1(privateKey: Uint8Array): string {
  const pub = secp256k1.getPublicKey(privateKey, true);
  return "PUB_K1_" + base58.encode(Buffer.concat([Buffer.from(pub), k1Checksum(pub, "K1")]));
}

/** Derive the legacy "EOS…" encoding of the same compressed public key. */
export function derivePublicKeyLegacy(privateKey: Uint8Array): string {
  const pub = secp256k1.getPublicKey(privateKey, true);
  const checksum = Buffer.from(ripemd160(Buffer.from(pub))).subarray(0, 4);
  return "EOS" + base58.encode(Buffer.concat([Buffer.from(pub), checksum]));
}

/** Antelope canonicality over a 65-byte [header, r32, s32] layout. */
function isCanonical(sigData: Uint8Array): boolean {
  return (
    !(sigData[1]! & 0x80) &&
    !(sigData[1] === 0 && !(sigData[2]! & 0x80)) &&
    !(sigData[33]! & 0x80) &&
    !(sigData[33] === 0 && !(sigData[34]! & 0x80))
  );
}

const MAX_GRIND_ATTEMPTS = 100;

/**
 * Sign a 32-byte digest, grinding until Antelope-canonical. Returns 65 bytes:
 * `[recoveryId (0-3), r (32), s (32)]` — chain-neutral layout; the chain side
 * adds its own header/encoding.
 */
export function signDigestK1Canonical(privateKey: Uint8Array, digest: Uint8Array): Uint8Array {
  if (digest.length !== 32) {
    throw new KeystoreError("BAD_FORMAT", "digest must be exactly 32 bytes");
  }
  for (let attempt = 0; attempt <= MAX_GRIND_ATTEMPTS; attempt++) {
    const recovered = secp256k1.sign(digest, privateKey, {
      lowS: true,
      prehash: false,
      format: "recovered", // [recid, r, s]
      ...(attempt > 0
        ? { extraEntropy: sha256(Buffer.concat([Buffer.from(digest), Buffer.from([attempt])])) }
        : {}),
    });
    // Canonicality is defined over the header+r+s layout; recid slot stands
    // in for the header here (only bytes 1..64 are inspected).
    if (isCanonical(recovered)) return recovered;
  }
  // Astronomically unlikely (each attempt passes with p≈1/4); fail closed.
  throw new KeystoreError("BAD_FORMAT", "could not produce a canonical signature");
}
