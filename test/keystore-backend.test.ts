/**
 * EncryptedFileKeystore backend (#46) — lifecycle behavior that used to live
 * inline in the daemon runner: discovery, bounded passphrase retries,
 * duplicate refusal, metadata-without-unlock, scoped secret access, wipe.
 */

import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeystoreFile, type KeystoreMetadata } from "../src/keystore/encryptedFile.js";
import { EncryptedFileKeystore } from "../src/keystore/encryptedFileBackend.js";

const PASSPHRASE = "correct horse battery staple";

function meta(agent: string): KeystoreMetadata {
  return {
    publicKey: `PUB_K1_${agent}`,
    exportPolicy: "non-exportable",
    chain: { chain: "XPR", network: "testnet", chainId: "a".repeat(64) },
    agent,
    permission: "active",
    createdAt: "2026-08-04T00:00:00.000Z",
  };
}

function makeDir(agents: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "signbox-backend-"));
  for (const agent of agents) {
    createKeystoreFile(
      join(dir, `${agent}.keystore.json`),
      Buffer.from(`secret-of-${agent}`),
      Buffer.from(PASSPHRASE),
      meta(agent),
    );
  }
  return dir;
}

const passphraseCtx = { kind: "passphrase" as const, passphraseFor: async () => Buffer.from(PASSPHRASE) };

describe("EncryptedFileKeystore", () => {
  it("lists public metadata without unlocking", () => {
    const backend = new EncryptedFileKeystore(makeDir(["aagent", "bagent"]));
    const keys = backend.listKeys();
    expect(keys.map((k) => k.agent)).toEqual(["aagent", "bagent"]);
    expect(backend.readMetadata("bagent")?.publicKey).toBe("PUB_K1_bagent");
    expect(backend.readMetadata("nobody")).toBeUndefined();
  });

  it("unlocks every keystore and scopes secret access by key id", async () => {
    const backend = new EncryptedFileKeystore(makeDir(["aagent", "bagent"]));
    const unlocked = await backend.unlock(passphraseCtx);
    expect(unlocked.map((k) => k.agent)).toEqual(["aagent", "bagent"]);
    const value = backend.withSecret("bagent", (secret) => secret.toString("utf8"));
    expect(value).toBe("secret-of-bagent");
    expect(() => backend.withSecret("nobody", () => 0)).toThrowError(
      expect.objectContaining({ code: "FILE_NOT_FOUND" }),
    );
  });

  it("re-prompts on a wrong passphrase and caps the attempts", async () => {
    const backend = new EncryptedFileKeystore(makeDir(["aagent"]));
    const attempts: number[] = [];
    await expect(
      backend.unlock({
        kind: "passphrase",
        passphraseFor: async (_label, attempt) => {
          attempts.push(attempt);
          return Buffer.from("always wrong");
        },
      }),
    ).rejects.toThrowError(expect.objectContaining({ code: "DECRYPT_FAILED" }));
    expect(attempts).toEqual([1, 2, 3]); // bounded retries, then fatal
  });

  it("recovers when a retry provides the right passphrase", async () => {
    const backend = new EncryptedFileKeystore(makeDir(["aagent"]));
    const unlocked = await backend.unlock({
      kind: "passphrase",
      passphraseFor: async (_label, attempt) =>
        Buffer.from(attempt < 3 ? "typo" : PASSPHRASE),
    });
    expect(unlocked.map((k) => k.agent)).toEqual(["aagent"]);
  });

  it("wipes all secrets (idempotent)", async () => {
    const backend = new EncryptedFileKeystore(makeDir(["aagent"]));
    await backend.unlock(passphraseCtx);
    backend.wipe();
    backend.wipe();
    expect(() => backend.withSecret("aagent", () => 0)).toThrowError(
      expect.objectContaining({ code: "FILE_NOT_FOUND" }),
    );
  });

  it("stages signDigest / verifyKeyBinding as UNSUPPORTED until the provider swap", async () => {
    const backend = new EncryptedFileKeystore(makeDir(["aagent"]));
    await backend.unlock(passphraseCtx);
    await expect(backend.signDigest("aagent", new Uint8Array(32), "secp256k1")).rejects.toThrowError(
      expect.objectContaining({ code: "UNSUPPORTED" }),
    );
    await expect(backend.verifyKeyBinding("aagent")).rejects.toThrowError(
      expect.objectContaining({ code: "UNSUPPORTED" }),
    );
  });

  it("returns no keys for a missing directory", () => {
    const backend = new EncryptedFileKeystore(join(tmpdir(), "signbox-backend-missing", "nope"));
    expect(backend.listKeys()).toEqual([]);
  });
});
