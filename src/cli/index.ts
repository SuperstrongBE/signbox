#!/usr/bin/env node
/**
 * SignBox CLI (spec §11).
 *
 * Semantics (§11.6):
 * - `transaction inspect`  decodes without policy and without signing;
 * - `transaction explain`  evaluates a local policy without signing;
 * - `transaction sign`     asks the RUNNING DAEMON to sign (the CLI holds
 *                          no key and evaluates no policy on this path);
 * - `transaction push`     broadcasts an already-signed transaction;
 * - `sign --push`          combines both with explicit intent.
 *
 * Output is structured JSON on stdout. Secrets never appear (INV-002).
 */

import { Command } from "commander";
import { createRequire } from "node:module";
import { readFileSync, statSync, existsSync } from "node:fs";
import { JsonRpc } from "@proton/js";
import { decodeXprTransaction } from "../chains/xpr/decode.js";
import { XPR_CHAIN, XPR_NETWORKS } from "../chains/xpr/networks.js";
import { generateK1KeyPair } from "../chains/xpr/keygen.js";
import { pinChainId } from "../chains/xpr/adapter.js";
import { createKeystoreFile } from "../keystore/encryptedFile.js";
import { validatePolicy } from "../core/policy/schema.js";
import { evaluatePolicy } from "../core/policy/engine.js";
import { SignBoxError } from "../core/errors.js";
import { DEFAULT_CONFIG_PATH, expandPath, loadConfig, chainContextOf } from "./config.js";
import { promptPassphrase } from "./passphrase.js";
import { adminCommand, readToken, signViaDaemon } from "./client.js";
import { startDaemonFromConfig } from "./daemonRunner.js";
import type { ChainContext } from "../core/types.js";

const require = createRequire(import.meta.url);
const pkg = require("../../package.json") as { version: string };

/** JSON with bigint support — amounts serialize as strings, never floats. */
function print(value: unknown): void {
  process.stdout.write(
    JSON.stringify(value, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n",
  );
}

function fail(message: string): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(1);
}

function contextFor(network: string): ChainContext {
  const descriptor = XPR_NETWORKS[network];
  if (descriptor === undefined) fail(`unknown XPR network: ${network}`);
  return { chain: XPR_CHAIN, network, chainId: descriptor.chainId };
}

function readJsonFile(path: string): unknown {
  try {
    return JSON.parse(readFileSync(expandPath(path), "utf8"));
  } catch {
    fail(`cannot read JSON file: ${path}`);
  }
}

const program = new Command();
program.name("signbox").description("Local controlled-signing daemon for software agents").version(pkg.version);

// ---------------------------------------------------------------- doctor

program
  .command("doctor")
  .description("check runtime, configuration, keystores, RPC and chain identity (§11.1)")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .action(async (options: { config: string }) => {
    const checks: { check: string; ok: boolean; detail?: string }[] = [];
    const push = (check: string, ok: boolean, detail?: string): void => {
      checks.push(detail === undefined ? { check, ok } : { check, ok, detail });
    };

    push("node >= 22", Number(process.versions.node.split(".")[0]) >= 22, process.versions.node);

    let config;
    try {
      config = loadConfig(options.config);
      push("config valid", true, expandPath(options.config));
    } catch (error) {
      push("config valid", false, (error as Error).message);
    }

    if (config !== undefined) {
      for (const agent of config.agents) {
        const keystoreOk = existsSync(agent.keystorePath);
        let permsOk = false;
        if (keystoreOk) {
          permsOk = (statSync(agent.keystorePath).mode & 0o077) === 0;
        }
        push(`keystore ${agent.agent}`, keystoreOk && permsOk, keystoreOk ? undefined : "missing");
        try {
          validatePolicy(JSON.parse(readFileSync(agent.policyPath, "utf8")));
          push(`policy ${agent.agent}`, true);
        } catch (error) {
          push(`policy ${agent.agent}`, false, (error as Error).message);
        }
      }

      push("daemon socket", existsSync(config.socketPath), config.socketPath);

      try {
        const rpc = new JsonRpc(config.endpoints);
        pinChainId(rpc, config.chainId);
        const info = (await Promise.race([
          rpc.get_info(),
          new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 7000)),
        ])) as { head_block_time?: string };
        push("rpc + pinned chain id", true, config.endpoints[0]);
        if (info.head_block_time !== undefined) {
          const skew = Math.abs(Date.now() - Date.parse(`${info.head_block_time}Z`));
          push("clock within 30s of chain head", skew < 30_000, `${Math.round(skew / 1000)}s`);
        }
      } catch (error) {
        push("rpc + pinned chain id", false, (error as Error).message);
      }
    }

    print({ checks, healthy: checks.every((c) => c.ok) });
    if (!checks.every((c) => c.ok)) process.exit(1);
  });

// ------------------------------------------------------------------- key

const key = program.command("key").description("agent key management (§11.3)");

key
  .command("generate")
  .description("generate an agent key into an encrypted keystore; prints the PUBLIC key only")
  .requiredOption("--agent <name>", "agent account name")
  .requiredOption("--out <path>", "keystore file to create")
  .option("--network <network>", "XPR network", "testnet")
  .option("--permission <name>", "dedicated agent permission", "active")
  .action(async (options: { agent: string; out: string; network: string; permission: string }) => {
    const context = contextFor(options.network);
    const passphrase = await promptPassphrase("keystore passphrase: ");
    const confirm = await promptPassphrase("confirm passphrase: ");
    if (Buffer.compare(passphrase, confirm) !== 0) {
      passphrase.fill(0);
      confirm.fill(0);
      fail("passphrases do not match");
    }
    confirm.fill(0);
    const pair = await generateK1KeyPair();
    const secret = Buffer.from(pair.wif, "utf8");
    try {
      createKeystoreFile(expandPath(options.out), secret, passphrase, {
        publicKey: pair.publicKey,
        exportPolicy: "non-exportable",
        chain: context,
        agent: options.agent,
        permission: options.permission,
        createdAt: new Date().toISOString(),
      });
    } finally {
      secret.fill(0);
      passphrase.fill(0);
    }
    print({
      agent: options.agent,
      publicKey: pair.publicKey,
      keystore: expandPath(options.out),
      exportPolicy: "non-exportable",
      next: "register this public key on the agent's dedicated permission (authority wallet)",
    });
  });

// ----------------------------------------------------------- transaction

const tx = program.command("transaction").description("transaction operations (§11.6)");

tx.command("inspect")
  .description("decode a raw unserialized JSON transaction — no policy, no signature")
  .requiredOption("--transaction <file>", "transaction JSON file")
  .option("--network <network>", "XPR network", "testnet")
  .action((options: { transaction: string; network: string }) => {
    const context = contextFor(options.network);
    try {
      const decoded = decodeXprTransaction(readJsonFile(options.transaction), context);
      print({ context: decoded.context, actions: decoded.actions });
    } catch (error) {
      fail((error as Error).message);
    }
  });

tx.command("explain")
  .description("evaluate a local policy against a transaction — no signature")
  .requiredOption("--agent <name>", "agent account name")
  .requiredOption("--transaction <file>", "transaction JSON file")
  .requiredOption("--policy <file>", "policy JSON file")
  .option("--permission <name>", "agent permission", "active")
  .option("--policy-version <n>", "policy version", "1")
  .option("--network <network>", "XPR network", "testnet")
  .action(
    (options: {
      agent: string;
      transaction: string;
      policy: string;
      permission: string;
      policyVersion: string;
      network: string;
    }) => {
      const context = contextFor(options.network);
      try {
        const policy = validatePolicy(readJsonFile(options.policy));
        const decoded = decodeXprTransaction(readJsonFile(options.transaction), context);
        const result = evaluatePolicy(decoded, policy, {
          agent: options.agent,
          agentPermission: options.permission,
          chainId: context.chainId,
          policyVersion: Number(options.policyVersion),
        });
        print({
          decision: result.decision,
          statefulLimits: result.quotaDemands.length,
        });
      } catch (error) {
        fail((error as Error).message);
      }
    },
  );

tx.command("sign")
  .description("ask the running daemon to sign (never broadcasts without --push)")
  .requiredOption("--agent <name>", "agent account name")
  .requiredOption("--transaction <file>", "transaction JSON file")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .option("--push", "broadcast after signing (explicit intent, INV-011)", false)
  .action(async (options: { agent: string; transaction: string; config: string; push: boolean }) => {
    try {
      const config = loadConfig(options.config);
      const entry = config.agents.find((a) => a.agent === options.agent);
      if (entry === undefined) fail(`agent not in config: ${options.agent}`);
      const response = await signViaDaemon({
        socketPath: config.socketPath,
        agent: options.agent,
        context: chainContextOf(config),
        transaction: readJsonFile(options.transaction),
        token: readToken(entry.tokenPath),
      });
      if (response.status === "signed" && options.push) {
        const receipt = await pushSigned(config.endpoints, config.chainId, response.signedTransaction);
        print({ ...response, pushed: true, receipt });
        return;
      }
      print(response);
      if (response.status === "denied") process.exit(2);
    } catch (error) {
      fail((error as Error).message);
    }
  });

tx.command("push")
  .description("broadcast an already-signed transaction (§11.6)")
  .requiredOption("--signed-transaction <file>", "signed transaction JSON file")
  .option("--network <network>", "XPR network", "testnet")
  .action(async (options: { signedTransaction: string; network: string }) => {
    const context = contextFor(options.network);
    const descriptor = XPR_NETWORKS[options.network];
    try {
      const receipt = await pushSigned(
        descriptor?.endpoints ?? [],
        context.chainId,
        readJsonFile(options.signedTransaction),
      );
      print({ pushed: true, receipt });
    } catch (error) {
      fail((error as Error).message);
    }
  });

async function pushSigned(
  endpoints: string[],
  chainId: string,
  signed: unknown,
): Promise<unknown> {
  const payload = signed as { signatures?: string[]; packedTransaction?: string };
  if (!Array.isArray(payload?.signatures) || typeof payload?.packedTransaction !== "string") {
    throw new SignBoxError(
      "signed transaction must contain { signatures, packedTransaction } as produced by sign",
    );
  }
  const rpc = new JsonRpc(endpoints);
  pinChainId(rpc, chainId);
  await rpc.get_info(); // validates the pinned chain id before any broadcast
  return rpc.push_transaction({
    signatures: payload.signatures,
    serializedTransaction: Uint8Array.from(Buffer.from(payload.packedTransaction, "hex")),
  });
}

// ---------------------------------------------------------------- daemon

const daemonCommand = program.command("daemon").description("daemon lifecycle (§11.5)");

daemonCommand
  .command("start")
  .description("start the daemon in the foreground")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .action(async (options: { config: string }) => {
    try {
      const config = loadConfig(options.config);
      const running = await startDaemonFromConfig(config, (agent) =>
        promptPassphrase(`passphrase for agent "${agent}": `),
      );
      process.stderr.write(
        `signbox daemon listening on ${config.socketPath} (${config.agents.length} agent(s))\n`,
      );
      const shutdown = (): void => {
        void running.shutdown().then(() => process.exit(0));
      };
      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);
    } catch (error) {
      fail((error as Error).message);
    }
  });

daemonCommand
  .command("status")
  .description("query the running daemon through the admin socket")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .action(async (options: { config: string }) => {
    try {
      const config = loadConfig(options.config);
      print(await adminCommand(config.adminSocketPath, { command: "status" }));
    } catch (error) {
      fail((error as Error).message);
    }
  });

// ----------------------------------------------------------------- agent

const agentCommand = program.command("agent").description("agent administration (§11.2)");

for (const verb of ["disable", "enable"] as const) {
  agentCommand
    .command(`${verb} <agent>`)
    .description(
      verb === "disable"
        ? "kill-switch: refuse all signing for this agent immediately (§14.6)"
        : "re-enable a disabled agent",
    )
    .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
    .action(async (agent: string, options: { config: string }) => {
      try {
        const config = loadConfig(options.config);
        print(await adminCommand(config.adminSocketPath, { command: verb, agent }));
      } catch (error) {
        fail((error as Error).message);
      }
    });
}

program.parseAsync(process.argv).catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error));
});
