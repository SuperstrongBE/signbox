#!/usr/bin/env node
/**
 * SignBox CLI (spec §11).
 *
 * Semantics (§11.6):
 * - `transaction inspect`  decodes without policy and without signing;
 * - `transaction explain`  evaluates the agent's on-chain policy without
 *                          signing (same integrity gate as the daemon), or a
 *                          local --policy file to test one before deploying;
 * - `transaction sign`     asks the RUNNING DAEMON to sign (the CLI holds
 *                          no key and evaluates no policy on this path);
 * - `transaction push`     broadcasts an already-signed transaction;
 * - `sign --push`          signs AND submits through the daemon: the signature
 *                          never leaves it and the stateful quota follows the
 *                          chain outcome (committed only if the tx lands,
 *                          released on a deterministic rejection — §13).
 *
 * Output is structured JSON on stdout. Secrets never appear (INV-002).
 */

import { Command } from "commander";
import { createRequire } from "node:module";
import { readFileSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";
import { getChain, registeredChains } from "../chains/index.js";
import { runOnboarding, type BuiltRequest } from "../onboarding/flow.js";
import { promoteKeystoreFile, destroyKeystoreFile } from "../keystore/encryptedFile.js";
import qrcodeTerminal from "qrcode-terminal";
import { createKeystoreFile } from "../keystore/encryptedFile.js";
import { validatePolicy } from "../core/policy/schema.js";
import { verifyStoredPolicy } from "../core/policy/onchain.js";
import { evaluatePolicy, collectProviderQueries } from "../core/policy/engine.js";
import { resolveProviders } from "../daemon/providerResolver.js";
import { DEFAULT_CONFIG_PATH, DEFAULT_CHAIN, expandPath, loadConfig, chainContextOf } from "./config.js";
import { promptPassphrase } from "./passphrase.js";
import { isInteractive, promptText, promptSelect, validateAccountName } from "./prompt.js";
import { adminCommand, readToken, readViaDaemon, signViaDaemon } from "./client.js";
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

// Commands that take only --network (no config file) operate on the default
// chain; commands that load a config follow `config.chain`. Implementations
// always resolve through the registry.
const CLI_CHAIN = DEFAULT_CHAIN;

function contextFor(network: string): ChainContext {
  const module = getChain(CLI_CHAIN);
  const descriptor = module.networks[network];
  if (descriptor === undefined) fail(`unknown ${module.chain} network: ${network}`);
  return { chain: module.chain, network, chainId: descriptor.chainId };
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

      const doctorModule = getChain(config.chain);
      const wiring = { endpoints: config.endpoints, chainId: config.chainId };
      try {
        const { headTimeMs } = (await Promise.race([
          doctorModule.checkEndpoint(wiring),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), 7000)),
        ])) as { headTimeMs?: number };
        push("rpc + pinned chain id", true, config.endpoints[0]);
        if (headTimeMs !== undefined) {
          const skew = Math.abs(Date.now() - headTimeMs);
          push("clock within 30s of chain head", skew < 30_000, `${Math.round(skew / 1000)}s`);
        }
      } catch (error) {
        push("rpc + pinned chain id", false, (error as Error).message);
      }

      try {
        await doctorModule.checkPolicyRegistry(wiring, config.signboxContract);
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
    const pair = await getChain(CLI_CHAIN).generateKeyPair();
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
      const decoded = getChain(CLI_CHAIN).decode(readJsonFile(options.transaction), context);
      print({ context: decoded.context, actions: decoded.actions });
    } catch (error) {
      fail((error as Error).message);
    }
  });

tx.command("explain")
  .description(
    "evaluate a transaction against the agent's on-chain policy — or a local --policy to test one before deploying (§11.6)",
  )
  .requiredOption("--agent <name>", "agent account name")
  .requiredOption("--transaction <file>", "transaction JSON file")
  .option("--policy <file>", "evaluate this LOCAL policy instead of the on-chain one (test an undeployed policy)")
  .option("--permission <name>", "agent permission (only with --policy; on-chain derives it from the row)")
  .option("--policy-version <n>", "policy version to report (only with --policy)")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .option("--network <network>", "override the network (endpoints, chain id)")
  .action(
    async (options: {
      agent: string;
      transaction: string;
      policy?: string;
      permission?: string;
      policyVersion?: string;
      config: string;
      network?: string;
    }) => {
      try {
        const config = loadConfig(
          options.config,
          options.network !== undefined ? { network: options.network } : {},
        );
        const context = chainContextOf(config);

        // Resolve the policy to evaluate. Default: the on-chain policy is the
        // source of truth (INV-004). Override: a local --policy file lets an
        // author test a policy BEFORE deploying it — schema-validated only (no
        // hash/canonical gate, since a hand-authored file has neither yet).
        let policy;
        let agentPermission: string;
        let policyVersion: number;
        let source: string;
        let meta: Record<string, unknown> = {};
        if (options.policy !== undefined) {
          policy = validatePolicy(readJsonFile(options.policy));
          agentPermission = options.permission ?? "active";
          policyVersion = Number(options.policyVersion ?? "1");
          source = "local-file";
          meta = { policyFile: options.policy };
        } else {
          const raw = await getChain(config.chain)
            .createPolicyReader(
              { endpoints: config.endpoints, chainId: config.chainId },
              config.signboxContract,
            )
            .read(options.agent);
          if (raw === null) {
            fail(
              `no on-chain policy for agent "${options.agent}" in contract "${config.signboxContract}" on ${config.network} (deploy one, or pass --policy <file> to test locally)`,
            );
          }
          // Same integrity gate the daemon cache applies (§8.6): hash +
          // canonical JCS + schema. A tampered row is refused, never dry-run.
          const verified = verifyStoredPolicy(raw.policyjson, raw.policyhash);
          if (!verified.ok) {
            fail(`on-chain policy failed integrity check: ${verified.reason}`);
          }
          policy = verified.policy;
          agentPermission = raw.agentperm;
          policyVersion = raw.version;
          source = "on-chain";
          meta = { contract: config.signboxContract, enabled: raw.enabled, policyhash: raw.policyhash };
        }

        const decoded = getChain(config.chain).decode(readJsonFile(options.transaction), context);
        const baseCtx = {
          agent: options.agent,
          agentPermission,
          chainId: context.chainId,
          policyVersion,
        };
        // Resolve any providers (§8.4) the same way the daemon does, so the
        // dry-run matches: read them through the same read-only relay.
        const queries = collectProviderQueries(decoded, policy, baseCtx);
        const evidence =
          queries.length > 0
            ? await resolveProviders(
                queries,
                getChain(config.chain).createRelay({
                  endpoints: config.endpoints,
                  chainId: config.chainId,
                }),
              )
            : undefined;
        const result = evaluatePolicy(
          decoded,
          policy,
          evidence !== undefined ? { ...baseCtx, evidence } : baseCtx,
        );
        print({
          agent: options.agent,
          source,
          network: config.network,
          version: policyVersion,
          permission: agentPermission,
          ...meta,
          providers: queries.length,
          decision: result.decision,
          statefulLimits: result.quotaDemands.length,
        });
        // Parity with `sign`: a refusal is a non-zero exit for scripting.
        if (result.decision.effect === "deny") process.exit(2);
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
  .option("--push", "sign AND submit via the daemon (explicit intent, INV-011)", false)
  .action(async (options: { agent: string; transaction: string; config: string; push: boolean }) => {
    try {
      const config = loadConfig(options.config);
      // With --push the DAEMON broadcasts: the signature never leaves it and
      // the stateful quota follows the chain outcome (committed only if the tx
      // lands, released on a deterministic rejection — §13).
      const response = await signViaDaemon({
        socketPath: config.socketPath,
        agent: options.agent,
        context: chainContextOf(config),
        transaction: readJsonFile(options.transaction),
        token: readToken(join(config.tokenDir, `${options.agent}.token`)),
        broadcast: options.push,
      });

      // Legacy fallback: a sign-only daemon (no broadcaster) returns the signed
      // bytes without a broadcast report. Submit them client-side, as before.
      if (response.status === "signed" && options.push && response.broadcast === undefined) {
        const receipt = await getChain(config.chain).broadcastSigned(
          { endpoints: config.endpoints, chainId: config.chainId },
          response.signedTransaction,
        );
        print({ ...response, pushed: true, receipt });
        return;
      }

      print(response);
      // Non-zero exit on anything that did not result in a landed/valid tx.
      if (response.status === "denied") process.exit(2);
      if (response.status === "signed" && response.broadcast !== undefined && response.broadcast.status !== "accepted") {
        process.exit(2);
      }
    } catch (error) {
      fail((error as Error).message);
    }
  });

tx.command("push")
  .description("broadcast an already-signed transaction (§11.6)")
  .requiredOption("--signed-transaction <file>", "signed transaction JSON file")
  .option("--network <network>", "XPR network", "testnet")
  .action(async (options: { signedTransaction: string; network: string }) => {
    const module = getChain(CLI_CHAIN);
    const context = contextFor(options.network);
    const descriptor = module.networks[options.network];
    try {
      const receipt = await module.broadcastSigned(
        { endpoints: descriptor?.endpoints ?? [], chainId: context.chainId },
        readJsonFile(options.signedTransaction),
      );
      print({ pushed: true, receipt });
    } catch (error) {
      fail((error as Error).message);
    }
  });

// ----------------------------------------------------------------- chain

/** Parse a --params flag into a JSON object, or fail. */
function parseParamsFlag(json: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(json);
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  } catch {
    /* fall through to the failure below */
  }
  fail("--params must be a JSON object");
}

const chain = program
  .command("chain")
  .description("read-only chain access through the daemon relay (never signs, never submits)");

chain
  .command("query")
  .description("call a whitelisted read-only chain method through the daemon")
  .requiredOption("--agent <name>", "agent account name")
  .requiredOption("--method <method>", "read-only method, e.g. get_currency_balance, get_account")
  .option("--params <json>", "JSON params object for the method", "{}")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .action(async (options: { agent: string; method: string; params: string; config: string }) => {
    try {
      const config = loadConfig(options.config);
      const response = await readViaDaemon({
        socketPath: config.socketPath,
        agent: options.agent,
        token: readToken(join(config.tokenDir, `${options.agent}.token`)),
        op: "query",
        method: options.method,
        params: parseParamsFlag(options.params),
      });
      print(response);
      if (response.status === "error") process.exit(2);
    } catch (error) {
      fail((error as Error).message);
    }
  });

chain
  .command("balance")
  .description("read a token balance through the daemon relay (defaults to the agent's own account)")
  .requiredOption("--agent <name>", "agent account name")
  .option("--account <name>", "account to read (default: the agent itself)")
  .option("--contract <name>", "token contract", "eosio.token")
  .option("--symbol <symbol>", "token symbol", "XPR")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .action(
    async (options: {
      agent: string;
      account?: string;
      contract: string;
      symbol: string;
      config: string;
    }) => {
      try {
        const config = loadConfig(options.config);
        const response = await readViaDaemon({
          socketPath: config.socketPath,
          agent: options.agent,
          token: readToken(join(config.tokenDir, `${options.agent}.token`)),
          op: "query",
          method: "get_currency_balance",
          params: { code: options.contract, account: options.account ?? options.agent, symbol: options.symbol },
        });
        print(response);
        if (response.status === "error") process.exit(2);
      } catch (error) {
        fail((error as Error).message);
      }
    },
  );

chain
  .command("abi")
  .description("fetch an account's ABI through the relay — to see the actions and their fields")
  .requiredOption("--agent <name>", "agent account name")
  .requiredOption("--account <name>", "account whose ABI to read (e.g. eosio.token)")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .action(async (options: { agent: string; account: string; config: string }) => {
    try {
      const config = loadConfig(options.config);
      const response = await readViaDaemon({
        socketPath: config.socketPath,
        agent: options.agent,
        token: readToken(join(config.tokenDir, `${options.agent}.token`)),
        op: "query",
        method: "get_abi",
        params: { account_name: options.account },
      });
      print(response);
      if (response.status === "error") process.exit(2);
    } catch (error) {
      fail((error as Error).message);
    }
  });

// ---------------------------------------------------------------- daemon

const daemonCommand = program.command("daemon").description("daemon lifecycle (§11.5)");

daemonCommand
  .command("start")
  .description("start the daemon in the foreground")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .action(async (options: { config: string }) => {
    try {
      const config = loadConfig(options.config);
      const running = await startDaemonFromConfig(config, (keystore, attempt) =>
        promptPassphrase(
          attempt > 1 ? `wrong passphrase — retry for ${keystore}: ` : `passphrase for ${keystore}: `,
        ),
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
  .command("whoami")
  .description("print the agent's own identity (account, permission, public key) via the daemon")
  .requiredOption("--agent <name>", "agent account name")
  .option("--config <path>", "configuration file", DEFAULT_CONFIG_PATH)
  .action(async (options: { agent: string; config: string }) => {
    try {
      const config = loadConfig(options.config);
      const response = await readViaDaemon({
        socketPath: config.socketPath,
        agent: options.agent,
        token: readToken(join(config.tokenDir, `${options.agent}.token`)),
        op: "whoami",
      });
      print(response);
      if (response.status === "error") process.exit(2);
    } catch (error) {
      fail((error as Error).message);
    }
  });

agentCommand
  .command("create")
  .description("onboard an agent: generate its key, build an ESR for the authority to sign (§10)")
  .option("--agent <name>", "agent account name")
  .option("--authority <name>", "superior authority account")
  .option("--signbox-contract <name>", "SignBox contract account")
  .option("--out <path>", "keystore file to create")
  .option("--chain <chain>", "chain (XPR only for now)")
  .option("--network <network>", "network (mainnet/testnet)")
  .option("--export <policy>", "key export policy: non-exportable | encrypted-backup-only")
  .option("--permission <name>", "dedicated permission name (generated if omitted)")
  .option("--ram-bytes <n>", "RAM to buy for a new account (paid by the authority)")
  .option("--scheme <scheme>", "signing-request scheme: proton | proton-dev | esr (default from network)")
  .option("--companion-url <url>", "companion web app base URL (default https://signbox.rockerone.io; use http://localhost:5173 for local dev)")
  .action(
    async (options: {
      agent?: string;
      authority?: string;
      signboxContract?: string;
      out?: string;
      chain?: string;
      network?: string;
      export?: string;
      permission?: string;
      ramBytes?: string;
      scheme?: string;
      companionUrl?: string;
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
        () =>
          promptSelect(
            "Chain:",
            registeredChains().map((c) => ({ value: c, label: c })),
            { default: CLI_CHAIN },
          ),
        CLI_CHAIN,
      );
      let module;
      try {
        module = getChain(chain);
      } catch (error) {
        fail((error as Error).message);
      }

      const network = await def(
        options.network,
        () =>
          promptSelect(
            "Network:",
            Object.keys(module.networks).map((n) => ({ value: n, label: n })),
            { default: "testnet" },
          ),
        "testnet",
      );
      const descriptor = module.networks[network];
      if (descriptor === undefined) fail(`unknown ${module.chain} network: ${network}`);
      const context: ChainContext = { chain: module.chain, network, chainId: descriptor.chainId };

      const authority = await req(options.authority, "authority", () =>
        promptText("Authority account (your account name)", { validate: validateAccountName }),
      );
      const agent = await req(options.agent, "agent", () =>
        promptText("Agent account name", { validate: validateAccountName }),
      );

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
      // The agent key is placed on `active` at account creation, so that is
      // the permission the daemon signs with (overridable via --permission).
      const permission = options.permission ?? "active";

      const backend = module.createOnboardingBackend(
        { endpoints: descriptor.endpoints, chainId: context.chainId },
        signboxContract,
        {
          scheme,
          ...(options.companionUrl !== undefined ? { companionBaseUrl: options.companionUrl } : {}),
        },
      );

      try {
        const result = await runOnboarding(
          {
            chain: context,
            authority,
            agent,
            permission,
            exportPolicy,
            keystorePath: expandPath(out),
            ramBytes: Number(options.ramBytes ?? "4096"),
          },
          {
            backend,
            generateKey: () => module.generateKeyPair(),
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

/** Present the request: the companion web link (preferred) + the actions. */
function presentEsr(request: BuiltRequest): void {
  process.stderr.write("\nActions the authority will sign:\n");
  for (const a of request.summary) {
    process.stderr.write(`  - ${a.detail}\n`);
  }
  if (request.companionUrl !== undefined) {
    process.stderr.write(
      "\nOpen this link — or scan the QR with your phone — connect the authority's wallet, and sign:\n\n" +
        `  ${request.companionUrl}\n\n`,
    );
    // The QR is the companion LINK: scanning it opens the web app, which drives
    // the WebAuth session and the signature in the browser.
    qrcodeTerminal.generate(request.companionUrl, { small: true }, (qr: string) => {
      process.stderr.write(qr + "\n");
    });
  } else {
    process.stderr.write(
      "\nScan this signing request directly with a WebAuth mobile wallet:\n\n",
    );
    qrcodeTerminal.generate(request.esrUri, { small: true }, (qr: string) => {
      process.stderr.write(qr + "\n");
    });
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
