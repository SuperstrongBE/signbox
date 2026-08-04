import { describe, expect, it } from "vitest";
import sodium from "sodium-native";
import { chmodSync, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createKeystoreFile,
  destroyKeystoreFile,
  openKeystoreFile,
  promoteKeystoreFile,
  wipeSecret,
  type KeystoreMetadata,
} from "../src/keystore/encryptedFile.js";
import { KeystoreError } from "../src/core/errors.js";

const META: KeystoreMetadata = {
  publicKey: "PUB_K1_placeholder",
  exportPolicy: "non-exportable",
  chain: { chain: "XPR", network: "testnet", chainId: "a".repeat(64) },
  agent: "superagent",
  permission: "xp2vr3",
  createdAt: "2026-07-29T00:00:00.000Z",
};

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "signbox-keystore-"));
}

function makeKeystore(dir: string): { path: string; secret: Buffer; passphrase: Buffer } {
  const path = join(dir, "agent.keystore.json");
  const secret = Buffer.from("super-secret-private-key-material-0123456789");
  const passphrase = Buffer.from("correct horse battery staple");
  createKeystoreFile(path, secret, passphrase, META);
  return { path, secret, passphrase };
}

describe("encrypted-file keystore", () => {
  it("round-trips the secret and metadata", () => {
    const dir = tempDir();
    const { path, secret, passphrase } = makeKeystore(dir);
    const opened = openKeystoreFile(path, passphrase);
    expect(Buffer.compare(opened.secret, secret)).toBe(0);
    expect(opened.meta).toEqual(META);
    wipeSecret(opened.secret);
  });

  it("creates the file with 0600 permissions", () => {
    const dir = tempDir();
    const { path } = makeKeystore(dir);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("never writes the secret in cleartext (INV-002)", () => {
    const dir = tempDir();
    const { path } = makeKeystore(dir);
    const raw = readFileSync(path, "utf8");
    expect(raw).not.toContain("super-secret");
    expect(raw).not.toContain(Buffer.from("super-secret-private-key-material-0123456789").toString("base64"));
  });

  it("fails with DECRYPT_FAILED on a wrong passphrase", () => {
    const dir = tempDir();
    const { path } = makeKeystore(dir);
    expect(() => openKeystoreFile(path, Buffer.from("wrong passphrase"))).toThrowError(
      expect.objectContaining({ code: "DECRYPT_FAILED" }),
    );
  });

  it("fails on ciphertext tampering", () => {
    const dir = tempDir();
    const { path, passphrase } = makeKeystore(dir);
    const file = JSON.parse(readFileSync(path, "utf8"));
    const bytes = Buffer.from(file.ciphertext, "base64");
    bytes[0] = bytes[0]! ^ 0xff;
    file.ciphertext = bytes.toString("base64");
    writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
    expect(() => openKeystoreFile(path, passphrase)).toThrowError(
      expect.objectContaining({ code: "DECRYPT_FAILED" }),
    );
  });

  it("fails when metadata is tampered with (AD binding)", () => {
    const dir = tempDir();
    const { path, passphrase } = makeKeystore(dir);
    const file = JSON.parse(readFileSync(path, "utf8"));
    // Attacker tries to flip the export policy on disk.
    file.meta.exportPolicy = "encrypted-backup-only";
    writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
    expect(() => openKeystoreFile(path, passphrase)).toThrowError(
      expect.objectContaining({ code: "DECRYPT_FAILED" }),
    );
  });

  it("refuses to overwrite an existing keystore", () => {
    const dir = tempDir();
    const { path, secret, passphrase } = makeKeystore(dir);
    expect(() => createKeystoreFile(path, secret, passphrase, META)).toThrowError(
      expect.objectContaining({ code: "FILE_EXISTS" }),
    );
  });

  it("refuses group/other-readable files", () => {
    const dir = tempDir();
    const { path, passphrase } = makeKeystore(dir);
    chmodSync(path, 0o644);
    expect(() => openKeystoreFile(path, passphrase)).toThrowError(
      expect.objectContaining({ code: "PERMISSIONS" }),
    );
  });

  it("promotes a temporary container atomically and never overwrites (§10.3)", () => {
    const dir = tempDir();
    const tempPath = join(dir, "agent.keystore.tmp");
    const finalPath = join(dir, "agent.keystore.json");
    const secret = Buffer.from("s3cret");
    const passphrase = Buffer.from("pass");
    createKeystoreFile(tempPath, secret, passphrase, META);
    promoteKeystoreFile(tempPath, finalPath);
    expect(existsSync(tempPath)).toBe(false);
    const opened = openKeystoreFile(finalPath, passphrase);
    expect(Buffer.compare(opened.secret, secret)).toBe(0);
    wipeSecret(opened.secret);

    // A second promotion targeting the same final path must fail.
    createKeystoreFile(tempPath, secret, passphrase, META);
    expect(() => promoteKeystoreFile(tempPath, finalPath)).toThrowError(
      expect.objectContaining({ code: "FILE_EXISTS" }),
    );
  });

  it("destroys a temporary container idempotently", () => {
    const dir = tempDir();
    const { path } = makeKeystore(dir);
    destroyKeystoreFile(path);
    expect(existsSync(path)).toBe(false);
    destroyKeystoreFile(path); // no throw on already-gone
  });

  it("rejects a keystore with an out-of-range memlimit before deriving (OOM guard)", () => {
    const dir = tempDir();
    const { path, passphrase } = makeKeystore(dir);
    const file = JSON.parse(readFileSync(path, "utf8"));
    // A hostile memlimit (~4 TB) would OOM the daemon at crypto_pwhash — which
    // runs BEFORE the passphrase/AD is ever checked. The bounds check must fire
    // first with BAD_FORMAT, never attempting the allocation.
    file.kdf.memlimit = 4_398_046_510_080;
    writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
    expect(() => openKeystoreFile(path, passphrase)).toThrowError(
      expect.objectContaining({ code: "BAD_FORMAT" }),
    );
  });

  it("rejects a keystore with an out-of-range opslimit", () => {
    const dir = tempDir();
    const { path, passphrase } = makeKeystore(dir);
    const file = JSON.parse(readFileSync(path, "utf8"));
    file.kdf.opslimit = 9999;
    writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
    expect(() => openKeystoreFile(path, passphrase)).toThrowError(
      expect.objectContaining({ code: "BAD_FORMAT" }),
    );
  });

  it("caps the accepted memlimit at MODERATE — the strongest preset SignBox writes (#62)", () => {
    const dir = tempDir();
    const { path, passphrase } = makeKeystore(dir);
    const file = JSON.parse(readFileSync(path, "utf8"));
    // At exactly the ceiling (what createKeystoreFile writes) the bounds check
    // passes — the failure that follows is the AAD/passphrase gate, proving
    // crypto_pwhash WAS attempted. One byte above, BAD_FORMAT fires first and
    // the (up to 1 GiB under the old SENSITIVE bound) allocation never happens.
    expect(file.kdf.memlimit).toBe(sodium.crypto_pwhash_MEMLIMIT_MODERATE);
    file.kdf.memlimit = sodium.crypto_pwhash_MEMLIMIT_MODERATE + 1;
    writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
    expect(() => openKeystoreFile(path, passphrase)).toThrowError(
      expect.objectContaining({ code: "BAD_FORMAT" }),
    );
  });

  it("caps the accepted opslimit at MODERATE (#62)", () => {
    const dir = tempDir();
    const { path, passphrase } = makeKeystore(dir);
    const file = JSON.parse(readFileSync(path, "utf8"));
    expect(file.kdf.opslimit).toBe(sodium.crypto_pwhash_OPSLIMIT_MODERATE);
    file.kdf.opslimit = sodium.crypto_pwhash_OPSLIMIT_MODERATE + 1;
    writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
    expect(() => openKeystoreFile(path, passphrase)).toThrowError(
      expect.objectContaining({ code: "BAD_FORMAT" }),
    );
  });

  it("keystores written by createKeystoreFile load under the ceiling (compatibility)", () => {
    const dir = tempDir();
    const { path, passphrase, secret } = makeKeystore(dir);
    const opened = openKeystoreFile(path, passphrase);
    expect(Buffer.compare(opened.secret, secret)).toBe(0);
    wipeSecret(opened.secret);
  });

  it("rejects non-integer / non-numeric KDF parameters", () => {
    const dir = tempDir();
    const { path, passphrase } = makeKeystore(dir);
    const file = JSON.parse(readFileSync(path, "utf8"));
    file.kdf.memlimit = "268435456";
    writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
    expect(() => openKeystoreFile(path, passphrase)).toThrowError(
      expect.objectContaining({ code: "BAD_FORMAT" }),
    );
  });

  it("rejects unsupported versions", () => {
    const dir = tempDir();
    const { path, passphrase } = makeKeystore(dir);
    const file = JSON.parse(readFileSync(path, "utf8"));
    file.version = 2;
    writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
    expect(() => openKeystoreFile(path, passphrase)).toThrow(KeystoreError);
  });
});
