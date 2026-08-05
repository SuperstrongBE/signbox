/**
 * EncryptedFileKeystore backend (#46) — lifecycle (discovery, bounded
 * passphrase retries, duplicate refusal, metadata-without-unlock, wipe) and
 * the signing boundary: signDigest / verifyKeyBinding, with the private key
 * never crossing the interface.
 */

import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createKeystoreFile, type KeystoreMetadata } from "../src/keystore/encryptedFile.js";
import { EncryptedFileKeystore } from "../src/keystore/encryptedFileBackend.js";
import { generateK1KeyPair } from "../src/chains/xpr/keygen.js";

const PASSPHRASE = "correct horse battery staple";

function meta(agent: string, publicKey: string): KeystoreMetadata {
  return {
    publicKey,
    exportPolicy: "non-exportable",
    chain: { chain: "XPR", network: "testnet", chainId: "a".repeat(64) },
    agent,
    permission: "active",
    createdAt: "2026-08-04T00:00:00.000Z",
  };
}

/** Build a keystore dir with REAL K1 keys, one per agent. */
async function makeDir(agents: string[]): Promise<{ dir: string; pubs: Map<string, string> }> {
  const dir = mkdtempSync(join(tmpdir(), "signbox-backend-"));
  const pubs = new Map<string, string>();
  for (const agent of agents) {
    const pair = await generateK1KeyPair();
    pubs.set(agent, pair.publicKey);
    createKeystoreFile(
      join(dir, `${agent}.keystore.json`),
      Buffer.from(pair.wif, "utf8"),
      Buffer.from(PASSPHRASE),
      meta(agent, pair.publicKey),
    );
  }
  return { dir, pubs };
}

const passphraseCtx = { kind: "passphrase" as const, passphraseFor: async () => Buffer.from(PASSPHRASE) };

describe("EncryptedFileKeystore", () => {
  it("lists public metadata without unlocking", async () => {
    const { dir, pubs } = await makeDir(["aagent", "bagent"]);
    const backend = new EncryptedFileKeystore(dir);
    expect(backend.listKeys().map((k) => k.agent)).toEqual(["aagent", "bagent"]);
    expect(backend.readMetadata("bagent")?.publicKey).toBe(pubs.get("bagent"));
    expect(backend.readMetadata("nobody")).toBeUndefined();
  });

  it("re-prompts on a wrong passphrase and caps the attempts", async () => {
    const { dir } = await makeDir(["aagent"]);
    const backend = new EncryptedFileKeystore(dir);
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
    const { dir } = await makeDir(["aagent"]);
    const backend = new EncryptedFileKeystore(dir);
    const unlocked = await backend.unlock({
      kind: "passphrase",
      passphraseFor: async (_label, attempt) => Buffer.from(attempt < 3 ? "typo" : PASSPHRASE),
    });
    expect(unlocked.map((k) => k.agent)).toEqual(["aagent"]);
  });

  it("signs a digest without exposing the key, verifiable against the declared pubkey", async () => {
    const { dir } = await makeDir(["aagent"]);
    const backend = new EncryptedFileKeystore(dir);
    await backend.unlock(passphraseCtx);
    const digest = new Uint8Array(32).fill(7);
    const sig = await backend.signDigest("aagent", digest, "secp256k1-canonical");
    expect(sig.length).toBe(65); // [recoveryId, r, s]
    expect(sig[0]).toBeGreaterThanOrEqual(0);
    expect(sig[0]).toBeLessThanOrEqual(3);
    // The binding check proves the signing key IS the declared one.
    await expect(backend.verifyKeyBinding("aagent")).resolves.toBe(true);
  });

  it("refuses signing for a locked/unknown key and unsupported schemes", async () => {
    const { dir } = await makeDir(["aagent"]);
    const backend = new EncryptedFileKeystore(dir);
    const digest = new Uint8Array(32);
    // Not unlocked yet → no key material available.
    await expect(backend.signDigest("aagent", digest, "secp256k1-canonical")).rejects.toThrowError(
      expect.objectContaining({ code: "FILE_NOT_FOUND" }),
    );
    await backend.unlock(passphraseCtx);
    await expect(backend.signDigest("nobody", digest, "secp256k1-canonical")).rejects.toThrowError(
      expect.objectContaining({ code: "FILE_NOT_FOUND" }),
    );
    // The file stores a K1 WIF — ed25519 cannot be served from it.
    await expect(backend.signDigest("aagent", digest, "ed25519")).rejects.toThrowError(
      expect.objectContaining({ code: "UNSUPPORTED" }),
    );
  });

  it("verifyKeyBinding fails when the declared public key does not match (#39)", async () => {
    const { dir } = await makeDir(["aagent"]);
    // Rebuild the keystore with a DIFFERENT declared pubkey (fresh dir, since
    // metadata is AAD-bound and cannot be tampered in place).
    const other = await generateK1KeyPair();
    const dir2 = mkdtempSync(join(tmpdir(), "signbox-backend-"));
    const pair = await generateK1KeyPair();
    createKeystoreFile(
      join(dir2, "bagent.keystore.json"),
      Buffer.from(pair.wif, "utf8"),
      Buffer.from(PASSPHRASE),
      meta("bagent", other.publicKey), // declares someone else's key
    );
    const backend = new EncryptedFileKeystore(dir2);
    await backend.unlock(passphraseCtx);
    await expect(backend.verifyKeyBinding("bagent")).resolves.toBe(false);
    // Control: the honest dir still verifies.
    const honest = new EncryptedFileKeystore(dir);
    await honest.unlock(passphraseCtx);
    await expect(honest.verifyKeyBinding("aagent")).resolves.toBe(true);
  });

  it("wipes all secrets (idempotent)", async () => {
    const { dir } = await makeDir(["aagent"]);
    const backend = new EncryptedFileKeystore(dir);
    await backend.unlock(passphraseCtx);
    backend.wipe();
    backend.wipe();
    await expect(backend.signDigest("aagent", new Uint8Array(32), "secp256k1-canonical")).rejects.toThrowError(
      expect.objectContaining({ code: "FILE_NOT_FOUND" }),
    );
  });

  it("returns no keys for a missing directory", () => {
    const backend = new EncryptedFileKeystore(join(tmpdir(), "signbox-backend-missing", "nope"));
    expect(backend.listKeys()).toEqual([]);
  });
});
