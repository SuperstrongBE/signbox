/**
 * Keystore backend seam (issue #46, spec §6.3 / §9.1).
 *
 * A backend OWNS key material: callers identify keys by id and ask the
 * backend to act — the private key itself is never part of the interface.
 * `signDigest` is the signing boundary (spec §6.3): backends where the key
 * physically cannot leave (Vault transit, KMS, HSM) implement it natively;
 * the local encrypted-file backend implements it so that even locally the
 * key stops crossing module boundaries.
 *
 * Staging note: `signDigest` and `verifyKeyBinding` are implemented together
 * with the chain-side signature-provider swap (#46 phase A, task "XPR
 * SignatureProvider over signDigest") — landing the raw-curve crypto and its
 * consumer in one reviewable change. Until then the encrypted-file backend
 * refuses them with KeystoreError("UNSUPPORTED").
 */

import type { KeystoreMetadata } from "./encryptedFile.js";

/** Signature schemes a backend may support (per key). */
export type SignatureScheme = "secp256k1" | "ed25519";

/**
 * How a backend authenticates before it can operate. Today: an interactive
 * passphrase (encrypted-file). Future backends add their own variants (Vault
 * token, cloud credential chain) — spec §9.4.
 */
export interface PassphraseUnlock {
  kind: "passphrase";
  /**
   * Prompt for one keystore's passphrase. `attempt` starts at 1 and bumps on
   * a wrong-passphrase retry; the backend caps attempts. The backend wipes
   * the returned buffer.
   */
  passphraseFor: (keystoreLabel: string, attempt: number) => Promise<Buffer>;
}

export type UnlockContext = PassphraseUnlock;

export interface KeystoreBackend {
  readonly kind: "encrypted-file" | "vault-transit" | "aws-kms" | "os-keychain";

  /**
   * Public metadata of every key this backend holds — readable WITHOUT
   * unlocking (encrypted-file metadata is cleartext, AAD-bound).
   */
  listKeys(): KeystoreMetadata[];

  /** Public metadata for one key id, or undefined. Never requires unlock. */
  readMetadata(keyId: string): KeystoreMetadata | undefined;

  /**
   * Authenticate and load every key this backend holds. Refuses duplicate
   * key ids. Idempotent unlocks are not required — call once at startup.
   */
  unlock(ctx: UnlockContext): Promise<KeystoreMetadata[]>;

  /**
   * Sign a digest with an unlocked key. The private key never crosses this
   * boundary in either direction (INV-002, extended).
   */
  signDigest(keyId: string, digest: Uint8Array, scheme: SignatureScheme): Promise<Uint8Array>;

  /**
   * Verify — inside the backend, no export — that the held private key
   * derives the declared public key (#39 identity binding).
   */
  verifyKeyBinding(keyId: string): Promise<boolean>;

  /** Zeroize all in-process key material. Safe to call more than once. */
  wipe(): void;
}
