/**
 * Encrypted-file key backend (spec §9.1 Backend A).
 *
 * - key derived from a passphrase with Argon2id (libsodium crypto_pwhash);
 * - authenticated encryption with XChaCha20-Poly1305-ietf;
 * - the canonical JSON of the header is bound as additional data: tampering
 *   with ANY metadata field (export policy, chain, agent…) breaks decryption;
 * - secret material only ever lives in sodium secure buffers (mlocked,
 *   zeroed on free);
 * - 0600 file permissions, enforced at creation and verified at open;
 * - temporary container + atomic promotion (spec §10.3).
 *
 * "Non-exportable" here is a software guarantee only (spec §9.3): no SignBox
 * API returns the secret, nothing more against a root attacker.
 */

import sodium from "sodium-native";
import { readFileSync, writeFileSync, statSync, linkSync, unlinkSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { KeystoreError } from "../core/errors.js";
import { canonicalize } from "../core/canonical/jcs.js";
import type { ChainContext, ExportPolicy } from "../core/types.js";

export interface KeystoreMetadata {
  publicKey: string;
  exportPolicy: ExportPolicy;
  chain: ChainContext;
  agent: string;
  permission: string;
  createdAt: string;
}

interface KeystoreFileV1 {
  version: 1;
  kind: "encrypted-file";
  kdf: {
    algorithm: "argon2id13";
    opslimit: number;
    memlimit: number;
    salt: string; // base64
  };
  cipher: {
    algorithm: "xchacha20poly1305-ietf";
    nonce: string; // base64
  };
  meta: KeystoreMetadata;
  ciphertext: string; // base64
}

function additionalData(file: Omit<KeystoreFileV1, "ciphertext">): Buffer {
  return Buffer.from(canonicalize(file), "utf8");
}

function deriveKey(
  passphrase: Buffer,
  salt: Buffer,
  opslimit: number,
  memlimit: number,
): Buffer {
  const key = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  sodium.crypto_pwhash(
    key,
    passphrase,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  return key;
}

/**
 * Create a keystore file. Fails if the path already exists (promotion from a
 * temporary container is the only supported replacement flow — §10.3).
 * The caller keeps ownership of `secret` and `passphrase` and must wipe them.
 */
export function createKeystoreFile(
  filePath: string,
  secret: Buffer,
  passphrase: Buffer,
  meta: KeystoreMetadata,
): void {
  const salt = Buffer.alloc(sodium.crypto_pwhash_SALTBYTES);
  sodium.randombytes_buf(salt);
  const nonce = Buffer.alloc(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  sodium.randombytes_buf(nonce);

  const opslimit = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  const memlimit = sodium.crypto_pwhash_MEMLIMIT_MODERATE;

  const header: Omit<KeystoreFileV1, "ciphertext"> = {
    version: 1,
    kind: "encrypted-file",
    kdf: {
      algorithm: "argon2id13",
      opslimit,
      memlimit,
      salt: salt.toString("base64"),
    },
    cipher: {
      algorithm: "xchacha20poly1305-ietf",
      nonce: nonce.toString("base64"),
    },
    meta,
  };

  const key = deriveKey(passphrase, salt, opslimit, memlimit);
  try {
    const ciphertext = Buffer.alloc(
      secret.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES,
    );
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext,
      secret,
      additionalData(header),
      null,
      nonce,
      key,
    );
    const file: KeystoreFileV1 = { ...header, ciphertext: ciphertext.toString("base64") };
    try {
      // Ensure the keystore directory exists (zero-config first run creates
      // ~/.signbox/keystores/ on demand).
      mkdirSync(dirname(filePath), { recursive: true });
      writeFileSync(filePath, JSON.stringify(file, null, 2) + "\n", {
        mode: 0o600,
        flag: "wx",
      });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new KeystoreError("FILE_EXISTS", `keystore already exists: ${filePath}`);
      }
      throw error;
    }
  } finally {
    sodium.sodium_memzero(key);
  }
}

export interface OpenedKeystore {
  /** Sodium secure buffer (mlocked). Caller MUST wipe with wipeSecret(). */
  secret: Buffer;
  meta: KeystoreMetadata;
}

/**
 * Open a keystore file. Throws KeystoreError("DECRYPT_FAILED") on a wrong
 * passphrase or ANY tampering (ciphertext or metadata), without revealing
 * which. Refuses files with group/other permission bits.
 */
export function openKeystoreFile(filePath: string, passphrase: Buffer): OpenedKeystore {
  let raw: string;
  try {
    const mode = statSync(filePath).mode;
    if ((mode & 0o077) !== 0) {
      throw new KeystoreError(
        "PERMISSIONS",
        `keystore file must not be group/other accessible: ${filePath}`,
      );
    }
    raw = readFileSync(filePath, "utf8");
  } catch (error) {
    if (error instanceof KeystoreError) throw error;
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new KeystoreError("FILE_NOT_FOUND", `keystore not found: ${filePath}`);
    }
    throw error;
  }

  let file: KeystoreFileV1;
  try {
    file = JSON.parse(raw) as KeystoreFileV1;
  } catch {
    throw new KeystoreError("BAD_FORMAT", "keystore file is not valid JSON");
  }
  if (file.version !== 1 || file.kind !== "encrypted-file") {
    throw new KeystoreError("UNSUPPORTED_VERSION", "unsupported keystore version or kind");
  }
  if (file.kdf?.algorithm !== "argon2id13" || file.cipher?.algorithm !== "xchacha20poly1305-ietf") {
    throw new KeystoreError("UNSUPPORTED_VERSION", "unsupported keystore algorithms");
  }

  const { ciphertext: ciphertextB64, ...header } = file;
  const salt = Buffer.from(file.kdf.salt, "base64");
  const nonce = Buffer.from(file.cipher.nonce, "base64");
  const ciphertext = Buffer.from(ciphertextB64, "base64");
  if (
    salt.length !== sodium.crypto_pwhash_SALTBYTES ||
    nonce.length !== sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES ||
    ciphertext.length <= sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
  ) {
    throw new KeystoreError("BAD_FORMAT", "keystore file has malformed cryptographic fields");
  }

  const key = deriveKey(passphrase, salt, file.kdf.opslimit, file.kdf.memlimit);
  try {
    const secret = sodium.sodium_malloc(
      ciphertext.length - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES,
    );
    try {
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        secret,
        null,
        ciphertext,
        additionalData(header),
        nonce,
        key,
      );
    } catch {
      sodium.sodium_memzero(secret);
      throw new KeystoreError(
        "DECRYPT_FAILED",
        "keystore decryption failed (wrong passphrase or tampered file)",
      );
    }
    return { secret, meta: file.meta };
  } finally {
    sodium.sodium_memzero(key);
  }
}

/**
 * Read a keystore's public metadata WITHOUT the passphrase. The metadata
 * (agent, permission, public key, chain) is stored in the file header in
 * cleartext — the secret is not touched. Used to list agents (INV-002: this
 * never exposes anything secret).
 */
export function readKeystoreMetadata(filePath: string): KeystoreMetadata {
  let file: KeystoreFileV1;
  try {
    file = JSON.parse(readFileSync(filePath, "utf8")) as KeystoreFileV1;
  } catch {
    throw new KeystoreError("BAD_FORMAT", `cannot read keystore metadata: ${filePath}`);
  }
  if (file.version !== 1 || file.meta === undefined || typeof file.meta.agent !== "string") {
    throw new KeystoreError("BAD_FORMAT", `keystore has no readable metadata: ${filePath}`);
  }
  return file.meta;
}

export function wipeSecret(secret: Buffer): void {
  sodium.sodium_memzero(secret);
}

/**
 * Atomically promote a temporary container to its final path (§10.3).
 * Fails if the final path already exists — a promotion never overwrites.
 */
export function promoteKeystoreFile(tempPath: string, finalPath: string): void {
  try {
    linkSync(tempPath, finalPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new KeystoreError("FILE_EXISTS", `keystore already exists: ${finalPath}`);
    }
    throw error;
  }
  unlinkSync(tempPath);
}

/** Destroy a (temporary) container, e.g. on session timeout or failed ESR. */
export function destroyKeystoreFile(filePath: string): void {
  try {
    unlinkSync(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}
