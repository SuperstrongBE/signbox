/**
 * Startup identity gate (#39) — a keystore whose PRIVATE key does not derive
 * the PUBLIC key its own metadata declares must prevent the daemon from
 * starting. The check is in-backend (no key export) via verifyKeyBinding.
 */

import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startDaemonFromConfig } from "../src/cli/daemonRunner.js";
import { createKeystoreFile } from "../src/keystore/encryptedFile.js";
import { generateK1KeyPair } from "../src/chains/xpr/keygen.js";
import type { SignBoxConfig } from "../src/cli/config.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const PASSPHRASE = "correct horse battery staple";

/** Store `wif` but DECLARE `declaredPublicKey` — the two may disagree. */
function configWith(wif: string, declaredPublicKey: string): SignBoxConfig {
  const dir = mkdtempSync(join(tmpdir(), "signbox-startup-"));
  const keystoreDir = join(dir, "keystores");
  mkdirSync(keystoreDir, { recursive: true });
  const secret = Buffer.from(wif, "utf8");
  createKeystoreFile(join(keystoreDir, "superagent.keystore.json"), secret, Buffer.from(PASSPHRASE), {
    publicKey: declaredPublicKey,
    exportPolicy: "non-exportable",
    chain: { chain: "XPR", network: "testnet", chainId: CHAIN_ID },
    agent: "superagent",
    permission: "xp2vr3",
    createdAt: "2026-08-06T00:00:00.000Z",
  });
  secret.fill(0);
  return {
    chain: "XPR",
    network: "testnet",
    chainId: CHAIN_ID,
    endpoints: ["http://127.0.0.1:1"],
    signboxContract: "signbox",
    baseDir: dir,
    keystoreDir,
    tokenDir: join(dir, "tokens"),
    socketPath: join(dir, "signbox.sock"),
    adminSocketPath: join(dir, "signbox.admin.sock"),
    stateDbPath: join(dir, "state.db"),
  };
}

const overrides = {
  signer: { sign: async () => ({ signature: "x", transactionDigest: "d".repeat(64) }) },
  resolveKeyAuthority: async () => ({ authorized: true as const }),
};

describe("daemon startup — key binding (#39)", () => {
  it("refuses to start when the declared public key ≠ the private key", async () => {
    const stored = await generateK1KeyPair();
    const other = await generateK1KeyPair();
    const config = configWith(stored.wif, other.publicKey); // declares a foreign key
    await expect(
      startDaemonFromConfig(config, async () => Buffer.from(PASSPHRASE), overrides),
    ).rejects.toThrow(/key binding/);
  });

  it("starts when the keystore's key binding is consistent", async () => {
    const pair = await generateK1KeyPair();
    const config = configWith(pair.wif, pair.publicKey); // declares its own key
    const running = await startDaemonFromConfig(config, async () => Buffer.from(PASSPHRASE), overrides);
    try {
      expect(running.agents).toEqual(["superagent"]);
    } finally {
      await running.shutdown();
    }
  });
});
