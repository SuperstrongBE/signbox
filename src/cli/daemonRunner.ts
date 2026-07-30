/**
 * Assembles a running daemon (spec §11.5, §14) — zero-config.
 *
 * Agents are DISCOVERED from the keystores in the configured directory: each
 * `*.keystore.json` is unlocked, and its authenticated metadata (agent name,
 * chain) drives registration. There is no agents list and no local policy
 * file — the policy comes from the on-chain contract through the anti-rollback
 * cache (§14).
 *
 * Fail closed at assembly: a keystore bound to another chain refuses to start
 * (INV-013). The registered policy is a deny-all placeholder; the cache is the
 * runtime source of truth and overrides it (§14.1).
 */

import { randomBytes } from "node:crypto";
import { writeFileSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { SignBoxDaemon } from "../daemon/server.js";
import { QuotaJournal } from "../daemon/quotaJournal.js";
import { PolicyCache } from "../daemon/policyCache.js";
import { ChainPolicyReader } from "../daemon/chainPolicyReader.js";
import { AuditLog } from "../daemon/auditLog.js";
import { XprTransactionSigner } from "../chains/xpr/adapter.js";
import { decodeXprTransaction } from "../chains/xpr/decode.js";
import { openKeystoreFile, wipeSecret } from "../keystore/encryptedFile.js";
import { emptyPolicy } from "../core/policy/schema.js";
import { ValidationError } from "../core/errors.js";
import { chainContextOf, type SignBoxConfig } from "./config.js";
import type { PolicyReader } from "../daemon/chainPolicyReader.js";
import type { KeyHandle, TransactionSigner } from "../core/types.js";

export interface RunningDaemon {
  daemon: SignBoxDaemon;
  agents: string[];
  shutdown: () => Promise<void>;
}

/** Test seams: inject a fake chain reader / signer / clock. */
export interface DaemonRunnerOverrides {
  policyReader?: PolicyReader;
  signer?: TransactionSigner;
  now?: () => number;
}

/** Discover keystore files (`*.keystore.json`) in the keystore directory. */
export function discoverKeystores(keystoreDir: string): string[] {
  if (!existsSync(keystoreDir)) return [];
  return readdirSync(keystoreDir)
    .filter((name) => name.endsWith(".keystore.json"))
    .sort()
    .map((name) => join(keystoreDir, name));
}

export async function startDaemonFromConfig(
  config: SignBoxConfig,
  /** Prompts for a keystore's passphrase, keyed by its file label. */
  passphraseFor: (keystoreLabel: string) => Promise<Buffer>,
  overrides: DaemonRunnerOverrides = {},
): Promise<RunningDaemon> {
  const context = chainContextOf(config);
  const secrets = new Map<string, Buffer>();

  const signer =
    overrides.signer ??
    new XprTransactionSigner({
      endpoints: config.endpoints,
      chainId: config.chainId,
      privateKeyProvider: async (key: KeyHandle) => {
        const secret = secrets.get(key.keyId);
        if (secret === undefined) throw new ValidationError(`no unlocked key for: ${key.keyId}`);
        return secret.toString("utf8");
      },
    });

  const quotas = new QuotaJournal(config.stateDbPath);
  const policyReader =
    overrides.policyReader ??
    new ChainPolicyReader({
      endpoints: config.endpoints,
      chainId: config.chainId,
      contractAccount: config.signboxContract,
    });
  const policyCache = new PolicyCache(config.stateDbPath, policyReader, {}, overrides.now);
  const audit = new AuditLog(config.stateDbPath);

  const daemon = new SignBoxDaemon(
    { socketPath: config.socketPath, adminSocketPath: config.adminSocketPath },
    overrides.now === undefined
      ? { decode: decodeXprTransaction, signer, quotas, policyCache, audit }
      : { decode: decodeXprTransaction, signer, quotas, policyCache, audit, now: overrides.now },
  );

  const wipeAll = (): void => {
    for (const secret of secrets.values()) wipeSecret(secret);
    secrets.clear();
  };

  const registered: string[] = [];
  try {
    mkdirSync(config.tokenDir, { recursive: true });

    for (const keystorePath of discoverKeystores(config.keystoreDir)) {
      const label = keystorePath.split("/").pop() ?? keystorePath;
      const passphrase = await passphraseFor(label);
      let opened;
      try {
        opened = openKeystoreFile(keystorePath, passphrase);
      } finally {
        passphrase.fill(0);
      }

      const meta = opened.meta;
      // A keystore bound to another chain must never sign here (INV-013).
      if (meta.chain.chainId !== context.chainId) {
        wipeSecret(opened.secret);
        throw new ValidationError(`keystore ${keystorePath} is bound to another chain (INV-013)`);
      }
      if (secrets.has(meta.agent)) {
        wipeSecret(opened.secret);
        throw new ValidationError(`duplicate keystore for agent "${meta.agent}"`);
      }
      secrets.set(meta.agent, opened.secret);

      // Rotating local token (§12.3), written 0600 under the token dir.
      const token = randomBytes(32).toString("base64url");
      writeFileSync(join(config.tokenDir, `${meta.agent}.token`), token + "\n", { mode: 0o600 });

      daemon.registerAgent({
        agent: meta.agent,
        permission: meta.permission,
        chain: context,
        // Placeholder — the on-chain cache is the runtime source of truth.
        policy: emptyPolicy(context.chain, context.chainId),
        policyVersion: 0,
        enabled: true,
        token: Buffer.from(token, "utf8"),
        key: {
          keyId: meta.agent,
          publicKey: meta.publicKey,
          exportPolicy: meta.exportPolicy,
          chain: context,
          agent: meta.agent,
          permission: meta.permission,
        },
      });
      registered.push(meta.agent);
    }

    await daemon.start();

    // Warm the policy cache once at startup (§14.3); best-effort, the runtime
    // get() re-confirms and fails closed if a policy can't be confirmed.
    await Promise.all(registered.map((agent) => policyCache.refresh(agent).catch(() => undefined)));
    policyCache.startBackgroundRefresh(registered);
  } catch (error) {
    wipeAll();
    policyCache.close();
    quotas.close();
    audit.close();
    throw error;
  }

  return {
    daemon,
    agents: registered,
    shutdown: async () => {
      await daemon.stop();
      wipeAll();
      policyCache.close();
      quotas.close();
      audit.close();
    },
  };
}
