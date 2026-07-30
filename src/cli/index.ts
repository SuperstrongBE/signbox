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
import { join } from "node:path";
import { JsonRpc } from "@proton/js";
import { decodeXprTransaction } from "../chains/xpr/decode.js";
import { XPR_CHAIN, XPR_NETWORKS } from "../chains/xpr/networks.js";
import { generateK1KeyPair } from "../chains/xpr/keygen.js";
import { runOnboarding, type BuiltRequest } from "../onboarding/flow.js";
import { XprOnboardingBackend } from "../onboarding/xprBackend.js";
import { generatePermissionName } from "../onboarding/permission.js";
import { promoteKeystoreFile, destroyKeystoreFile } from "../keystore/encryptedFile.js";
import qrcodeTerminal from "qrcode-terminal";
import { pinChainId } from "../chains/xpr/adapter.js";
import { createKeystoreFile } from "../keystore/encryptedFile.js";
import { validatePolicy } from "../core/policy/schema.js";
import { evaluatePolicy } from "../core/policy/engine.js";
import { SignBoxError } from "../core/errors.js";
import { DEFAULT_CONFIG_PATH, expandPath, loadConfig, chainContextOf } from "./config.js";
import { promptPassphrase } from "./passphrase.js";
import { isInteractive, promptText, promptSelect, validateAccountName } from "./prompt.js";
import { adminCommand, readToken, signViaDaemon } from "./client.js";
import { startDaemonFromConfig, discoverKeystores } from "./daemonRunner.js";
import { AuditLog } from "../daemon/auditLog.js";
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
      const keystores = discoverKeystores(config.keystoreDir);
      push(`keystores in ${config.keystoreDir}`, true, `${keystores.length} found`);
      for (const keystorePath of keystores) {
        const permsOk = existsSync(keystorePath) && (statSync(keystorePath).mode & 0o077) === 0;
        push(`keystore ${keystorePath.split("/").pop()}`, permsOk, permsOk ? "0600" : "bad perms");
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

      try {
        const rpc = new JsonRpc(config.endpoints);
        pinChainId(rpc, config.chainId);
        await rpc.get_abi(config.signboxContract);
        push(`signbox contract ${config.signboxContract}`, true, "deployed");
      } catch {
        push(`signbox contract ${config.signboxContract}`, false, "not reachable / not deployed");
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
      const response = await signViaDaemon({
        socketPath: config.socketPath,
        agent: options.agent,
        context: chainContextOf(config),
        transaction: readJsonFile(options.transaction),
        token: readToken(join(config.tokenDir, `${options.agent}.token`)),
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
      const running = await startDaemonFromConfig(config, (keystore) =>
        promptPassphrase(`passphrase for ${keystore}: `),
      );
      process.stderr.write(
        `signbox daemon listening on ${config.socketPath} (${running.agents.length} agent(s): ${running.agents.join(", ") || "none"})\n`,
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

agentCommand
  .command("create")
  .description("onboard an agent: generate its key, build an ESR for the authority to sign (§10)")
  .option("--agent <name>", "agent account name")
  .option("--authority <name>", "superior authority account")
  .option("--signbox-contract <name>", "SignBox contract account")
  .option("--out <path>", "keystore file to create")
  .option("--chain <chain>", "chain (XPR only for now)")
  .option("--network <network>", "network (mainnet/testnet)")
  .option("--mode <mode>", "create a new agent account or onboard an existing one")
  .option("--export <policy>", "key export policy: non-exportable | encrypted-backup-only")
  .option("--permission <name>", "dedicated permission name (generated if omitted)")
  .option("--ram-bytes <n>", "RAM to buy for a new account (paid by the authority)")
  .option("--scheme <scheme>", "signing-request scheme: proton | proton-dev | esr (default from network)")
  .action(
    async (options: {
      agent?: string;
      authority?: string;
      signboxContract?: string;
      out?: string;
      chain?: string;
      network?: string;
      mode?: string;
      export?: string;
      permission?: string;
      ramBytes?: string;
      scheme?: string;
    }) => {
      // Resolve every input: use the flag if given; otherwise prompt on a TTY;
      // otherwise fall back to a default (or fail for the required fields).
      const req = async (
        flag: string | undefined,
        name: string,
        prompt: () => Promise<string>,
      ): Promise<string> => {
        if (flag !== undefined) return flag;
        if (isInteractive()) return prompt();
        fail(`missing --${name} (required in non-interactive mode)`);
      };
      const def = async <T extends string>(
        flag: T | undefined,
        prompt: () => Promise<T>,
        fallback: T,
      ): Promise<T> => (flag !== undefined ? flag : isInteractive() ? prompt() : fallback);

      const chain = await def(
        options.chain,
        () => promptSelect("Chain:", [{ value: "XPR", label: "XPR Network" }], { default: "XPR" }),
        "XPR",
      );
      if (chain !== "XPR") fail("only the XPR chain is supported for now");

      const network = await def(
        options.network,
        () =>
          promptSelect(
            "Network:",
            Object.keys(XPR_NETWORKS).map((n) => ({ value: n, label: n })),
            { default: "testnet" },
          ),
        "testnet",
      );
      const context = contextFor(network);
      const descriptor = XPR_NETWORKS[network];

      const authority = await req(options.authority, "authority", () =>
        promptText("Authority account (your account name)", { validate: validateAccountName }),
      );
      const agent = await req(options.agent, "agent", () =>
        promptText("Agent account name", { validate: validateAccountName }),
      );
      const mode = await def(
        options.mode,
        () =>
          promptSelect(
            "Mode:",
            [
              { value: "create", label: "create a new agent account" },
              { value: "existing", label: "onboard an existing account" },
            ],
            { default: "create" },
          ),
        "create",
      );
      if (mode !== "create" && mode !== "existing") fail(`--mode must be "create" or "existing"`);

      const exportPolicy = await def(
        options.export,
        () =>
          promptSelect(
            "Key export policy:",
            [
              { value: "non-exportable", label: "non-exportable (recommended)" },
              { value: "encrypted-backup-only", label: "encrypted-backup-only" },
            ],
            { default: "non-exportable" },
          ),
        "non-exportable",
      );
      if (exportPolicy !== "non-exportable" && exportPolicy !== "encrypted-backup-only") {
        fail(`--export must be "non-exportable" or "encrypted-backup-only"`);
      }

      // The SignBox contract account is deployment config, never asked at
      // onboarding: default "signbox", overridable only by the flag.
      const signboxContract = options.signboxContract ?? "signbox";
      const out = await def(
        options.out,
        () =>
          promptText("Keystore file", { default: `~/.signbox/keystores/${agent}.keystore.json` }),
        `~/.signbox/keystores/${agent}.keystore.json`,
      );
      // The XPR WebAuth wallet needs the `proton` (mainnet) / `proton-dev`
      // (testnet) scheme; default from the network, overridable via --scheme.
      const schemes = ["esr", "proton", "proton-dev"] as const;
      type Scheme = (typeof schemes)[number];
      let scheme: Scheme = network === "mainnet" ? "proton" : "proton-dev";
      if (options.scheme !== undefined) {
        if (!schemes.includes(options.scheme as Scheme)) {
          fail(`--scheme must be one of: ${schemes.join(", ")}`);
        }
        scheme = options.scheme as Scheme;
      }
      const permission = options.permission ?? generatePermissionName();

      const backend = new XprOnboardingBackend({
        endpoints: descriptor?.endpoints ?? [],
        chainId: context.chainId,
        signboxContract,
        scheme,
      });

      try {
        const result = await runOnboarding(
          {
            chain: context,
            authority,
            agent,
            permission,
            mode,
            exportPolicy,
            keystorePath: expandPath(out),
            ...(mode === "create" ? { ramBytes: Number(options.ramBytes ?? "4096") } : {}),
          },
          {
            backend,
            generateKey: generateK1KeyPair,
            getPassphrase: async () => {
              const p = await promptPassphrase("keystore passphrase: ");
              const c = await promptPassphrase("confirm passphrase: ");
              if (Buffer.compare(p, c) !== 0) {
                p.fill(0);
                c.fill(0);
                fail("passphrases do not match");
              }
              c.fill(0);
              return p;
            },
            keystore: {
              createTemp: createKeystoreFile,
              promote: promoteKeystoreFile,
              destroy: destroyKeystoreFile,
            },
            present: presentEsr,
            now: Date.now,
          },
        );
        print({ status: "onboarded", ...result, next: `signbox policy edit ${result.agent}` });
      } catch (error) {
        fail((error as Error).message);
      }
    },
  );

/** Render the ESR as a terminal QR code plus a human-readable action summary. */
function presentEsr(request: BuiltRequest): void {
  process.stderr.write("\nScan this request with the authority's wallet:\n\n");
  qrcodeTerminal.generate(request.esrUri, { small: true }, (qr: string) => {
    process.stderr.write(qr + "\n");
  });
  process.stderr.write(`URI: ${request.esrUri}\n\nActions the authority will sign:\n`);
  for (const a of request.summary) {
    process.stderr.write(`  - ${a.detail}\n`);
  }
  process.stderr.write("\nWaiting for on-chain confirmation (2 min)...\n");
}

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

// ----------------------------------------------------------------- audit

const auditCommand = program.command("audit").description("audit trail (§16)");

/** Parse a "--since" like "24h", "30m", "7d" into a start timestamp (ms). */
function sinceToMs(since: string | undefined): number {
  if (since === undefined) return 0;
  const match = /^(\d+)([smhd])$/.exec(since.trim());
  if (match === null) fail(`invalid --since: ${since} (use e.g. 30m, 24h, 7d)`);
  const n = Number(match[1]);
  const unit = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[match[2]!]!;
  return Date.now() - n * unit;
}

auditCommand
  .command("tail")
  .description("show the most recent audit entries")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .option("-n, --limit <n>", "number of entries", "20")
  .action((options: { config: string; limit: string }) => {
    withAudit(options.config, (audit) => print(audit.tail(Number(options.limit))));
  });

auditCommand
  .command("query")
  .description("query the audit trail")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .option("--agent <name>", "filter by agent")
  .option("--since <window>", "e.g. 30m, 24h, 7d")
  .option("--limit <n>", "max entries", "100")
  .action((options: { config: string; agent?: string; since?: string; limit: string }) => {
    withAudit(options.config, (audit) =>
      print(
        audit.query({
          ...(options.agent !== undefined ? { agent: options.agent } : {}),
          sinceMs: sinceToMs(options.since),
          limit: Number(options.limit),
        }),
      ),
    );
  });

auditCommand
  .command("verify")
  .description("verify the audit hash chain is intact (tamper detection)")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .action((options: { config: string }) => {
    withAudit(options.config, (audit) => {
      const result = audit.verify();
      print(result);
      if (!result.ok) process.exit(1);
    });
  });

function withAudit(configPath: string, fn: (audit: AuditLog) => void): void {
  try {
    const config = loadConfig(configPath);
    const audit = new AuditLog(config.stateDbPath);
    try {
      fn(audit);
    } finally {
      audit.close();
    }
  } catch (error) {
    fail((error as Error).message);
  }
}

program.parseAsync(process.argv).catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error));
});
