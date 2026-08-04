/**
 * Encrypted-file KeystoreBackend (issue #46) — wraps the container functions
 * of encryptedFile.ts behind the backend seam. The file format is untouched:
 * every existing `*.keystore.json` loads unchanged (migration-free).
 *
 * Discovery is directory-based: every `*.keystore.json` under `keystoreDir`
 * is one key, its agent name being the key id (as before, one keystore per
 * agent). Unlock prompts per file with bounded wrong-passphrase retries —
 * the exact behavior the daemon runner used to implement inline.
 */

import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { KeystoreError } from "../core/errors.js";
import {
  openKeystoreFile,
  readKeystoreMetadata,
  wipeSecret,
  type KeystoreMetadata,
} from "./encryptedFile.js";
import {
  derivePublicKeyK1,
  derivePublicKeyLegacy,
  signDigestK1Canonical,
  wifToPrivateKey,
} from "./k1.js";
import type { KeystoreBackend, SignatureScheme, UnlockContext } from "./backend.js";

/** Discover keystore files (`*.keystore.json`) in a keystore directory. */
export function discoverKeystoreFiles(keystoreDir: string): string[] {
  if (!existsSync(keystoreDir)) return [];
  return readdirSync(keystoreDir)
    .filter((name) => name.endsWith(".keystore.json"))
    .sort()
    .map((name) => join(keystoreDir, name));
}

const MAX_PASSPHRASE_ATTEMPTS = 3;

export class EncryptedFileKeystore implements KeystoreBackend {
  readonly kind = "encrypted-file" as const;

  /** keyId (agent name) → mlocked secret buffer. Populated by unlock(). */
  private readonly secrets = new Map<string, Buffer>();

  constructor(private readonly keystoreDir: string) {}

  listKeys(): KeystoreMetadata[] {
    return discoverKeystoreFiles(this.keystoreDir).map((path) => readKeystoreMetadata(path));
  }

  readMetadata(keyId: string): KeystoreMetadata | undefined {
    return this.listKeys().find((meta) => meta.agent === keyId);
  }

  async unlock(ctx: UnlockContext): Promise<KeystoreMetadata[]> {
    const unlocked: KeystoreMetadata[] = [];
    for (const keystorePath of discoverKeystoreFiles(this.keystoreDir)) {
      const label = keystorePath.split("/").pop() ?? keystorePath;
      // A wrong passphrase is a typo, not a fatal error — retry a few times
      // before giving up, so one fumble doesn't abort a multi-keystore start.
      let opened: ReturnType<typeof openKeystoreFile> | undefined;
      for (let attempt = 1; opened === undefined; attempt++) {
        const passphrase = await ctx.passphraseFor(label, attempt);
        try {
          opened = openKeystoreFile(keystorePath, passphrase);
        } catch (error) {
          if (
            error instanceof KeystoreError &&
            error.code === "DECRYPT_FAILED" &&
            attempt < MAX_PASSPHRASE_ATTEMPTS
          ) {
            continue; // re-prompt
          }
          this.wipe();
          throw error;
        } finally {
          passphrase.fill(0);
        }
      }

      if (this.secrets.has(opened.meta.agent)) {
        wipeSecret(opened.secret);
        this.wipe();
        throw new KeystoreError(
          "BAD_FORMAT",
          `duplicate keystore for agent "${opened.meta.agent}"`,
        );
      }
      this.secrets.set(opened.meta.agent, opened.secret);
      unlocked.push(opened.meta);
    }
    return unlocked;
  }

  /** The unlocked WIF for keyId, decoded to its scalar. Caller wipes it. */
  private privateKeyOf(keyId: string): Buffer {
    const secret = this.secrets.get(keyId);
    if (secret === undefined) {
      throw new KeystoreError("FILE_NOT_FOUND", `no unlocked key for: ${keyId}`);
    }
    return wifToPrivateKey(secret.toString("utf8"));
  }

  async signDigest(keyId: string, digest: Uint8Array, scheme: SignatureScheme): Promise<Uint8Array> {
    if (scheme !== "secp256k1-canonical" && scheme !== "secp256k1") {
      throw new KeystoreError(
        "UNSUPPORTED",
        `encrypted-file keys are K1 WIFs — scheme "${scheme}" is not available`,
      );
    }
    const privateKey = this.privateKeyOf(keyId);
    try {
      // Both supported schemes produce the [recid, r, s] layout; the
      // canonical variant additionally grinds for Antelope canonicality.
      return signDigestK1Canonical(privateKey, digest);
    } finally {
      privateKey.fill(0);
    }
  }

  async verifyKeyBinding(keyId: string): Promise<boolean> {
    const meta = this.readMetadata(keyId);
    if (meta === undefined) return false;
    const privateKey = this.privateKeyOf(keyId);
    try {
      const declared = meta.publicKey;
      const derived = declared.startsWith("EOS")
        ? derivePublicKeyLegacy(privateKey)
        : derivePublicKeyK1(privateKey);
      return derived === declared;
    } finally {
      privateKey.fill(0);
    }
  }

  wipe(): void {
    for (const secret of this.secrets.values()) wipeSecret(secret);
    this.secrets.clear();
  }
}
