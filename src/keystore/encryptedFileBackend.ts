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

  async signDigest(_keyId: string, _digest: Uint8Array, _scheme: SignatureScheme): Promise<Uint8Array> {
    throw new KeystoreError(
      "UNSUPPORTED",
      "signDigest lands with the signature-provider swap (#46) — use the scoped secret access until then",
    );
  }

  async verifyKeyBinding(_keyId: string): Promise<boolean> {
    throw new KeystoreError(
      "UNSUPPORTED",
      "verifyKeyBinding lands with the signature-provider swap (#46)",
    );
  }

  /**
   * TRANSITIONAL (#46): scoped access to an unlocked secret, for the current
   * WIF-based signer path. The callback's return value may derive from the
   * secret but the buffer itself must not escape. Removed when the XPR
   * SignatureProvider moves onto signDigest — after that, nothing outside
   * this module can touch key material.
   */
  withSecret<T>(keyId: string, use: (secret: Buffer) => T): T {
    const secret = this.secrets.get(keyId);
    if (secret === undefined) {
      throw new KeystoreError("FILE_NOT_FOUND", `no unlocked key for: ${keyId}`);
    }
    return use(secret);
  }

  wipe(): void {
    for (const secret of this.secrets.values()) wipeSecret(secret);
    this.secrets.clear();
  }
}
