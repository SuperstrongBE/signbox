import { beforeEach, afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { JsSignatureProvider } from "@proton/js";
import { generateK1KeyPair } from "../src/chains/xpr/keygen.js";
import { loadConfig } from "../src/cli/config.js";
import { adminCommand, readToken, signViaDaemon } from "../src/cli/client.js";
import { startDaemonFromConfig } from "../src/cli/daemonRunner.js";
import { createKeystoreFile } from "../src/keystore/encryptedFile.js";
import { canonicalize } from "../src/core/canonical/jcs.js";
import type { RunningDaemon } from "../src/cli/daemonRunner.js";
import type { SignBoxConfig } from "../src/cli/config.js";
import type { PolicyReader, PolicyRowRaw } from "../src/daemon/chainPolicyReader.js";
import type {
  DecodedTransaction,
  KeyHandle,
  SignedTransactionResult,
  TransactionSigner,
} from "../src/core/types.js";

const TESTNET_CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const NOW = Date.parse("2026-07-30T12:00:00.000Z");

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

describe("config loader — zero-config", () => {
  it("defaults everything under ~/.signbox when no file exists", () => {
    const config = loadConfig(join(mkdtempSync(join(tmpdir(), "signbox-cfg-")), "absent.json"));
    expect(config.network).toBe("testnet");
    expect(config.signboxContract).toBe("signbox");
    expect(config.chainId).toBe(TESTNET_CHAIN_ID);
    expect(config.keystoreDir).toMatch(/\.signbox\/keystores$/);
    expect(config.socketPath).toMatch(/\.signbox\/signbox\.sock$/);
    expect(config.stateDbPath).toMatch(/\.signbox\/state\.db$/);
  });

  it("reads deployment settings from an optional file", () => {
    const dir = mkdtempSync(join(tmpdir(), "signbox-cfg-"));
    const path = join(dir, "config.json");
    writeFileSync(
      path,
      JSON.stringify({ network: "mainnet", signboxContract: "signbox", baseDir: dir }),
    );
    const config = loadConfig(path);
    expect(config.network).toBe("mainnet");
    expect(config.keystoreDir).toBe(join(dir, "keystores"));
  });

  it("rejects unknown fields — a typoed security option never silently passes", () => {
    const dir = mkdtempSync(join(tmpdir(), "signbox-cfg-"));
    const path = join(dir, "config.json");
    writeFileSync(path, JSON.stringify({ network: "testnet", allowUnsafeSigning: true }));
    expect(() => loadConfig(path)).toThrow();
  });

  it("rejects an unknown network without an explicit chainId", () => {
    const dir = mkdtempSync(join(tmpdir(), "signbox-cfg-"));
    const path = join(dir, "config.json");
    writeFileSync(path, JSON.stringify({ network: "otherenet" }));
    expect(() => loadConfig(path)).toThrow();
  });

  it("applies CLI overrides over the file and defaults", () => {
    const config = loadConfig("/nonexistent/config.json", { network: "mainnet", signboxContract: "sbx" });
    expect(config.network).toBe("mainnet");
    expect(config.signboxContract).toBe("sbx");
  });
});

describe("daemon assembled from keystores (zero-config integration)", () => {
  let dir: string;
  let running: RunningDaemon | undefined;
  let config: SignBoxConfig;
  const PASSPHRASE = "test passphrase";

  class FakeSigner implements TransactionSigner {
    async sign(_tx: DecodedTransaction, _key: KeyHandle): Promise<SignedTransactionResult> {
      return { signature: "SIG_K1_fake", transactionDigest: "e".repeat(64) };
    }
  }

  /** A fake on-chain reader returning a canonical policy that allows transfers. */
  class FakeReader implements PolicyReader {
    row: PolicyRowRaw | null;
    constructor(agent: string) {
      const canonical = canonicalize({
        schemaVersion: 1,
        default: "deny",
        chain: { name: "XPR", chainId: TESTNET_CHAIN_ID },
        rules: [
          {
            id: "allow-transfer",
            effect: "allow",
            match: { contract: "eosio.token", action: "transfer", "data.from": "$agent" },
          },
        ],
      });
      this.row = {
        agent,
        authority: "superdev",
        agentperm: "xp2vr3",
        version: 3,
        policyhash: createHash("sha256").update(Buffer.from(canonical, "utf8")).digest("hex"),
        policyjson: canonical,
        enabled: true,
        updatedat: NOW,
      };
    }
    async read(agent: string): Promise<PolicyRowRaw | null> {
      return this.row !== null && this.row.agent === agent ? this.row : null;
    }
  }

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "signbox-cli-"));
    const keystoreDir = join(dir, "keystores");
    mkdirSync(keystoreDir, { recursive: true });

    // Drop a keystore in the directory — the daemon discovers it (no config list).
    const pair = await generateK1KeyPair();
    const secret = Buffer.from(pair.wif, "utf8");
    createKeystoreFile(join(keystoreDir, "superagent.keystore.json"), secret, Buffer.from(PASSPHRASE), {
      publicKey: pair.publicKey,
      exportPolicy: "non-exportable",
      chain: { chain: "XPR", network: "testnet", chainId: TESTNET_CHAIN_ID },
      agent: "superagent",
      permission: "xp2vr3",
      createdAt: "2026-07-30T00:00:00.000Z",
    });
    secret.fill(0);

    config = {
      chain: "XPR",
      network: "testnet",
      chainId: TESTNET_CHAIN_ID,
      endpoints: ["http://127.0.0.1:1"],
      signboxContract: "signbox",
      baseDir: dir,
      keystoreDir,
      tokenDir: join(dir, "tokens"),
      socketPath: join(dir, "signbox.sock"),
      adminSocketPath: join(dir, "signbox.admin.sock"),
      stateDbPath: join(dir, "state.db"),
    };

    running = await startDaemonFromConfig(config, async () => Buffer.from(PASSPHRASE), {
      signer: new FakeSigner(),
      policyReader: new FakeReader("superagent"),
      // Offline: the on-chain authority is simulated as binding the daemon key.
      resolveKeyAuthority: async () => ({ authorized: true }),
    });
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

  it("discovers the agent from its keystore and serves it", () => {
    expect(running!.agents).toEqual(["superagent"]);
  });

  it("writes a 0600 token file and signs on the ON-CHAIN policy", async () => {
    const tokenPath = join(config.tokenDir, "superagent.token");
    expect(statSync(tokenPath).mode & 0o777).toBe(0o600);
    const response = await signViaDaemon({
      socketPath: config.socketPath,
      agent: "superagent",
      context: { chain: "XPR", network: "testnet", chainId: TESTNET_CHAIN_ID },
      transaction: transfer(),
      token: readToken(tokenPath),
    });
    // The registered placeholder denies all; only the cached on-chain policy
    // (version 3, from the fake reader) allows this transfer.
    expect(response).toMatchObject({ status: "signed", policyVersion: 3 });
  });

  it("admin socket: status and kill-switch (§14.6)", async () => {
    const admin = config.adminSocketPath;
    expect(statSync(admin).mode & 0o777).toBe(0o600);
    expect(await adminCommand(admin, { command: "status" })).toMatchObject({
      ok: true,
      agents: [{ agent: "superagent", enabled: true }],
    });
    expect(await adminCommand(admin, { command: "disable", agent: "superagent" })).toEqual({ ok: true });
    const denied = await signViaDaemon({
      socketPath: config.socketPath,
      agent: "superagent",
      context: { chain: "XPR", network: "testnet", chainId: TESTNET_CHAIN_ID },
      transaction: transfer(),
      token: readToken(join(config.tokenDir, "superagent.token")),
    });
    expect(denied).toMatchObject({ status: "denied", code: "AGENT_DISABLED" });
  });

  it("refuses to assemble a keystore bound to another chain (INV-013)", async () => {
    await running?.shutdown();
    running = undefined;
    const otherDir = mkdtempSync(join(tmpdir(), "signbox-cli-"));
    const ksDir = join(otherDir, "keystores");
    mkdirSync(ksDir, { recursive: true });
    const pair = await generateK1KeyPair();
    const secret = Buffer.from(pair.wif, "utf8");
    createKeystoreFile(join(ksDir, "superagent.keystore.json"), secret, Buffer.from(PASSPHRASE), {
      publicKey: pair.publicKey,
      exportPolicy: "non-exportable",
      chain: { chain: "XPR", network: "testnet", chainId: "b".repeat(64) },
      agent: "superagent",
      permission: "xp2vr3",
      createdAt: "2026-07-30T00:00:00.000Z",
    });
    secret.fill(0);
    const badConfig: SignBoxConfig = {
      ...config,
      baseDir: otherDir,
      keystoreDir: ksDir,
      tokenDir: join(otherDir, "tokens"),
      socketPath: join(otherDir, "s.sock"),
      adminSocketPath: join(otherDir, "s.admin.sock"),
      stateDbPath: join(otherDir, "state.db"),
    };
    await expect(
      startDaemonFromConfig(badConfig, async () => Buffer.from(PASSPHRASE), {
        signer: new FakeSigner(),
        policyReader: new FakeReader("superagent"),
      }),
    ).rejects.toThrow(/another chain/);
  });
});
