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
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { SignBoxDaemon, type DaemonDependencies } from "../daemon/server.js";
import { QuotaJournal } from "../daemon/quotaJournal.js";
import { PolicyCache } from "../daemon/policyCache.js";
import { AuthorityCache, type AuthorityResolver } from "../daemon/authorityCache.js";
import { AuditLog } from "../daemon/auditLog.js";
import type { TransactionBroadcaster } from "../daemon/broadcaster.js";
import type { ChainReadRelay } from "../daemon/chainRelay.js";
import { getChain } from "../chains/index.js";
import { EncryptedFileKeystore, discoverKeystoreFiles } from "../keystore/encryptedFileBackend.js";
import { emptyPolicy } from "../core/policy/schema.js";
import { ValidationError } from "../core/errors.js";
import { chainContextOf, type SignBoxConfig } from "./config.js";
import type { PolicyReader } from "../daemon/chainPolicyReader.js";
import type { TransactionSigner } from "../core/types.js";

export interface RunningDaemon {
  daemon: SignBoxDaemon;
  agents: string[];
  shutdown: () => Promise<void>;
}

/** Test seams: inject a fake chain reader / signer / broadcaster / authority / clock. */
export interface DaemonRunnerOverrides {
  policyReader?: PolicyReader;
  signer?: TransactionSigner;
  broadcaster?: TransactionBroadcaster;
  relay?: ChainReadRelay;
  /** Fake the on-chain key-authority resolution (#39) — offline tests. */
  resolveKeyAuthority?: AuthorityResolver;
  now?: () => number;
}

/** Discover keystore files — canonical implementation lives with the backend. */
export const discoverKeystores = discoverKeystoreFiles;

export async function startDaemonFromConfig(
  config: SignBoxConfig,
  /** Prompts for a keystore's passphrase (attempt starts at 1, bumped on retry). */
  passphraseFor: (keystoreLabel: string, attempt: number) => Promise<Buffer>,
  overrides: DaemonRunnerOverrides = {},
): Promise<RunningDaemon> {
  const context = chainContextOf(config);

  // Key material lives in the keystore backend and never leaves it (issue
  // #46): the chain signer signs through the backend's signDigest.
  const keystore = new EncryptedFileKeystore(config.keystoreDir);

  // All chain-specific implementations come from the registry (issue #44) —
  // this assembly never names an Xpr* class.
  const chainModule = getChain(config.chain);
  const wiring = { endpoints: config.endpoints, chainId: config.chainId };

  const signer = overrides.signer ?? chainModule.createSigner(wiring, keystore);

  // Broadcast is a SEPARATE, opt-in capability (#42): wire a broadcaster ONLY
  // when the deployment enabled it. Left off, every broadcast — fused or
  // standalone — is refused; a daemon-wide broadcaster can never silently turn
  // a sign-only agent into a sign-and-broadcast one.
  const broadcastCfg = config.broadcast ?? { enabled: false, agents: [] };
  const broadcaster =
    overrides.broadcaster ?? (broadcastCfg.enabled ? chainModule.createBroadcaster(wiring) : undefined);
  const relay = overrides.relay ?? chainModule.createRelay(wiring);

  const quotas = new QuotaJournal(config.stateDbPath);
  const policyReader =
    overrides.policyReader ?? chainModule.createPolicyReader(wiring, config.signboxContract);
  const policyCache = new PolicyCache(config.stateDbPath, policyReader, chainModule.dialect, {}, overrides.now);
  const audit = new AuditLog(config.stateDbPath);

  // On-chain key-authority binding (#39): every action is gated on the daemon
  // key still being authorized by the account's on-chain permission, cached
  // with bounded freshness (rotation detection), fail closed.
  const resolveAuthority: AuthorityResolver =
    overrides.resolveKeyAuthority ??
    ((account, permission, expectedPublicKey) =>
      chainModule.resolveKeyAuthority(wiring, account, permission, expectedPublicKey));
  const authority = new AuthorityCache(
    resolveAuthority,
    overrides.now !== undefined ? { now: overrides.now } : {},
  );

  const decode = chainModule.decode.bind(chainModule);
  const dialect = chainModule.dialect;
  // Build deps with optional seams present ONLY when defined (the daemon uses
  // exactOptionalPropertyTypes: a `broadcaster: undefined` is not the same as
  // an absent one — an absent broadcaster is what disables the submit path).
  const deps: DaemonDependencies = { decode, dialect, signer, relay, quotas, policyCache, audit, authority };
  if (broadcaster !== undefined) deps.broadcaster = broadcaster;
  if (overrides.now !== undefined) deps.now = overrides.now;
  const daemon = new SignBoxDaemon(
    { socketPath: config.socketPath, adminSocketPath: config.adminSocketPath },
    deps,
  );

  const wipeAll = (): void => keystore.wipe();

  const registered: string[] = [];
  try {
    mkdirSync(config.tokenDir, { recursive: true });

    // Unlock every keystore through the backend (bounded passphrase retries,
    // duplicate refusal live there); the runner applies its own policy checks
    // on the returned metadata.
    const unlockedKeys = await keystore.unlock({ kind: "passphrase", passphraseFor });
    for (const meta of unlockedKeys) {
      // A keystore bound to another chain must never sign here (INV-013).
      if (meta.chain.chainId !== context.chainId) {
        throw new ValidationError(
          `keystore for agent "${meta.agent}" is bound to another chain (INV-013)`,
        );
      }

      // Startup identity gate (#39): the unlocked private key MUST derive the
      // public key its own metadata declares — a tampered/mismatched keystore
      // never starts the daemon (verified in-backend, no key export).
      if (!(await keystore.verifyKeyBinding(meta.agent))) {
        throw new ValidationError(
          `keystore for agent "${meta.agent}" fails its key binding (private key ≠ declared public key)`,
        );
      }

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
        // Sign-only unless the deployment granted broadcast to this agent (#42).
        capabilities: {
          sign: true,
          broadcast: broadcastCfg.enabled && broadcastCfg.agents.includes(meta.agent),
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
