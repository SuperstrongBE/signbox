import { beforeEach, afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JsSignatureProvider } from "@proton/js";
import { generateK1KeyPair } from "../src/chains/xpr/keygen.js";
import { loadConfig } from "../src/cli/config.js";
import { adminCommand, readToken, signViaDaemon } from "../src/cli/client.js";
import { startDaemonFromConfig } from "../src/cli/daemonRunner.js";
import { openKeystoreFile, createKeystoreFile, wipeSecret } from "../src/keystore/encryptedFile.js";
import type { RunningDaemon } from "../src/cli/daemonRunner.js";
import type { SignBoxConfig } from "../src/cli/config.js";
import type {
  DecodedTransaction,
  KeyHandle,
  SignedTransactionResult,
  TransactionSigner,
} from "../src/core/types.js";

const TESTNET_CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";

describe("key generation", () => {
  it("produces a valid K1 pair accepted by the signature provider", async () => {
    const pair = await generateK1KeyPair();
    expect(pair.wif).toMatch(/^PVT_K1_/);
    expect(pair.publicKey).toMatch(/^PUB_K1_/);
    const provider = new JsSignatureProvider([pair.wif]);
    await expect(provider.getAvailableKeys()).resolves.toEqual([pair.publicKey]);
  });

  it("produces distinct keys", async () => {
    const a = await generateK1KeyPair();
    const b = await generateK1KeyPair();
    expect(a.wif).not.toBe(b.wif);
    expect(a.publicKey).not.toBe(b.publicKey);
  });
});

describe("config loader", () => {
  function writeConfig(dir: string, config: unknown): string {
    const path = join(dir, "config.json");
    writeFileSync(path, JSON.stringify(config));
    return path;
  }

  it("loads a valid config and resolves the pinned chain id", () => {
    const dir = mkdtempSync(join(tmpdir(), "signbox-config-"));
    const path = writeConfig(dir, {
      chain: "XPR",
      network: "testnet",
      socketPath: join(dir, "signbox.sock"),
      agents: [],
    });
    const config = loadConfig(path);
    expect(config.chainId).toBe(TESTNET_CHAIN_ID);
    expect(config.endpoints.length).toBeGreaterThan(0);
    expect(config.adminSocketPath).toBe(join(dir, "signbox.sock.admin"));
  });

  it("rejects unknown fields — a typoed security option never silently passes", () => {
    const dir = mkdtempSync(join(tmpdir(), "signbox-config-"));
    const path = writeConfig(dir, {
      chain: "XPR",
      network: "testnet",
      socketPath: join(dir, "s.sock"),
      agents: [],
      allowUnsafeSigning: true,
    });
    expect(() => loadConfig(path)).toThrow();
  });

  it("rejects an unknown network without an explicit chainId", () => {
    const dir = mkdtempSync(join(tmpdir(), "signbox-config-"));
    const path = writeConfig(dir, {
      chain: "XPR",
      network: "otherenet",
      socketPath: join(dir, "s.sock"),
      agents: [],
    });
    expect(() => loadConfig(path)).toThrow();
  });

  it("accepts an unknown network when chainId and endpoints are explicit", () => {
    const dir = mkdtempSync(join(tmpdir(), "signbox-config-"));
    const path = writeConfig(dir, {
      chain: "XPR",
      network: "localnet",
      chainId: "c".repeat(64),
      endpoints: ["http://127.0.0.1:8888"],
      socketPath: join(dir, "s.sock"),
      agents: [],
    });
    expect(loadConfig(path).chainId).toBe("c".repeat(64));
  });
});

describe("daemon assembled from config (integration)", () => {
  let dir: string;
  let running: RunningDaemon | undefined;
  let config: SignBoxConfig;
  const PASSPHRASE = "test passphrase";

  class FakeSigner implements TransactionSigner {
    async sign(_tx: DecodedTransaction, _key: KeyHandle): Promise<SignedTransactionResult> {
      return { signature: "SIG_K1_fake", transactionDigest: "e".repeat(64) };
    }
  }

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "signbox-cli-"));
    const pair = await generateK1KeyPair();
    const keystorePath = join(dir, "agent.keystore.json");
    const secret = Buffer.from(pair.wif, "utf8");
    createKeystoreFile(keystorePath, secret, Buffer.from(PASSPHRASE), {
      publicKey: pair.publicKey,
      exportPolicy: "non-exportable",
      chain: { chain: "XPR", network: "testnet", chainId: TESTNET_CHAIN_ID },
      agent: "superagent",
      permission: "xp2vr3",
      createdAt: "2026-07-30T00:00:00.000Z",
    });
    secret.fill(0);

    const policyPath = join(dir, "policy.json");
    writeFileSync(
      policyPath,
      JSON.stringify({
        schemaVersion: 1,
        default: "deny",
        chain: { name: "XPR", chainId: TESTNET_CHAIN_ID },
        rules: [
          {
            id: "allow-tips",
            effect: "allow",
            match: { contract: "eosio.token", action: "transfer", "data.from": "$agent" },
          },
        ],
      }),
    );

    config = {
      chain: "XPR",
      network: "testnet",
      chainId: TESTNET_CHAIN_ID,
      endpoints: ["http://127.0.0.1:1"],
      socketPath: join(dir, "signbox.sock"),
      adminSocketPath: join(dir, "signbox.sock.admin"),
      agents: [
        {
          agent: "superagent",
          permission: "xp2vr3",
          keystorePath,
          policyPath,
          policyVersion: 3,
          tokenPath: join(dir, "superagent.token"),
        },
      ],
    };

    running = await startDaemonFromConfig(config, async () => Buffer.from(PASSPHRASE));
    // The network signer is replaced by a fake for the integration test.
    (running.daemon as unknown as { deps: { signer: TransactionSigner } }).deps.signer =
      new FakeSigner();
  });

  afterEach(async () => {
    await running?.shutdown();
    running = undefined;
  });

  function transfer(): unknown {
    return {
      actions: [
        {
          account: "eosio.token",
          name: "transfer",
          authorization: [{ actor: "superagent", permission: "xp2vr3" }],
          data: { from: "superagent", to: "alice", quantity: "1.0000 XPR", memo: "" },
        },
      ],
    };
  }

  it("writes a 0600 token file usable by the sign client", async () => {
    const tokenPath = config.agents[0]!.tokenPath;
    expect(statSync(tokenPath).mode & 0o777).toBe(0o600);
    const response = await signViaDaemon({
      socketPath: config.socketPath,
      agent: "superagent",
      context: { chain: "XPR", network: "testnet", chainId: TESTNET_CHAIN_ID },
      transaction: transfer(),
      token: readToken(tokenPath),
    });
    expect(response).toMatchObject({ status: "signed", policyVersion: 3 });
  });

  it("admin socket: status, kill-switch, re-enable (§14.6)", async () => {
    const admin = config.adminSocketPath;
    expect(statSync(admin).mode & 0o777).toBe(0o600);

    const status = await adminCommand(admin, { command: "status" });
    expect(status).toMatchObject({
      ok: true,
      agents: [{ agent: "superagent", enabled: true, policyVersion: 3 }],
    });

    expect(await adminCommand(admin, { command: "disable", agent: "superagent" })).toEqual({
      ok: true,
    });
    const denied = await signViaDaemon({
      socketPath: config.socketPath,
      agent: "superagent",
      context: { chain: "XPR", network: "testnet", chainId: TESTNET_CHAIN_ID },
      transaction: transfer(),
      token: readToken(config.agents[0]!.tokenPath),
    });
    expect(denied).toMatchObject({ status: "denied", code: "AGENT_DISABLED" });

    expect(await adminCommand(admin, { command: "enable", agent: "superagent" })).toEqual({
      ok: true,
    });
    expect(await adminCommand(admin, { command: "disable", agent: "ghost" })).toMatchObject({
      ok: false,
    });
  });

  it("refuses to assemble when the keystore belongs to another agent", async () => {
    await running?.shutdown();
    running = undefined;
    const badConfig = {
      ...config,
      socketPath: join(dir, "signbox2.sock"),
      adminSocketPath: join(dir, "signbox2.sock.admin"),
      agents: [{ ...config.agents[0]!, agent: "mallory.agent".slice(0, 12) }],
    };
    // "mallory.agen" (12 chars) ≠ keystore meta agent "superagent"
    await expect(
      startDaemonFromConfig(badConfig, async () => Buffer.from(PASSPHRASE)),
    ).rejects.toThrow(/belongs to agent/);
  });

  it("keystore round-trips through the runner's unlock path", () => {
    const opened = openKeystoreFile(config.agents[0]!.keystorePath, Buffer.from(PASSPHRASE));
    expect(opened.meta.agent).toBe("superagent");
    expect(readFileSync(config.agents[0]!.keystorePath, "utf8")).not.toContain("PVT_K1");
    wipeSecret(opened.secret);
  });
});
