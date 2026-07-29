/**
 * K1 (secp256k1) key generation for agent onboarding (spec §10.2 step 4).
 *
 * The private key is generated locally from CSPRNG bytes, validated against
 * the curve order, and immediately encoded to WIF for the keystore. The WIF
 * is returned to the CALLER (key generate command / onboarding flow), which
 * encrypts it at rest and never prints it (INV-002).
 */

import { randomBytes } from "node:crypto";
import { JsSignatureProvider, Numeric } from "@proton/js";
import { SignBoxError } from "../../core/errors.js";

/** secp256k1 group order. */
const CURVE_ORDER = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
);

export interface GeneratedKeyPair {
  /** Private key in WIF form. Encrypt it at rest, never log it. */
  wif: string;
  publicKey: string;
}

function isValidScalar(candidate: Buffer): boolean {
  const value = BigInt(`0x${candidate.toString("hex")}`);
  return value > 0n && value < CURVE_ORDER;
}

export async function generateK1KeyPair(): Promise<GeneratedKeyPair> {
  let candidate = randomBytes(32);
  // Rejection sampling: astronomically unlikely to loop, but correctness
  // beats an out-of-range scalar.
  while (!isValidScalar(candidate)) {
    candidate = randomBytes(32);
  }
  const wif = Numeric.privateKeyToString({
    type: Numeric.KeyType.k1,
    data: new Uint8Array(candidate),
  });
  candidate.fill(0);

  const provider = new JsSignatureProvider([wif]);
  const available = await provider.getAvailableKeys();
  const publicKey = available[0];
  if (publicKey === undefined) {
    throw new SignBoxError("key generation failed to derive a public key");
  }
  return { wif, publicKey };
}
