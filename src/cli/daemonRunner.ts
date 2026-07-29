/**
 * Assembles a running daemon from a validated configuration (§11.5):
 * keystores unlocked in-process, per-agent rotating tokens written to disk,
 * local policies validated, quota journal attached, signer wired.
 *
 * Fail closed at assembly: a keystore whose metadata disagrees with the
 * configuration (agent, chain identity) refuses to start — a swapped
 * keystore file must never sign under another agent's policy.
 */

import { randomBytes } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { SignBoxDaemon } from "../daemon/server.js";
import { QuotaJournal } from "../daemon/quotaJournal.js";
import { XprTransactionSigner } from "../chains/xpr/adapter.js";
import { decodeXprTransaction } from "../chains/xpr/decode.js";
import { openKeystoreFile, wipeSecret } from "../keystore/encryptedFile.js";
import { validatePolicy } from "../core/policy/schema.js";
import { ValidationError } from "../core/errors.js";
import { chainContextOf, type SignBoxConfig } from "./config.js";
import { readFileSync } from "node:fs";
import type { KeyHandle } from "../core/types.js";

export interface RunningDaemon {
  daemon: SignBoxDaemon;
  /** Wipes unlocked secrets and stops the sockets. */
  shutdown: () => Promise<void>;
}

export async function startDaemonFromConfig(
  config: SignBoxConfig,
  passphraseFor: (agent: string) => Promise<Buffer>,
): Promise<RunningDaemon> {
  const context = chainContextOf(config);
  const secrets = new Map<string, Buffer>();

  const signer = new XprTransactionSigner({
    endpoints: config.endpoints,
    chainId: config.chainId,
    privateKeyProvider: async (key: KeyHandle) => {
      const secret = secrets.get(key.keyId);
      if (secret === undefined) {
        throw new ValidationError(`no unlocked key for: ${key.keyId}`);
      }
      return secret.toString("utf8");
    },
  });

  const quotas = config.quotaDbPath !== undefined ? new QuotaJournal(config.quotaDbPath) : undefined;

  const daemon = new SignBoxDaemon(
    { socketPath: config.socketPath, adminSocketPath: config.adminSocketPath },
    quotas === undefined
      ? { decode: decodeXprTransaction, signer }
      : { decode: decodeXprTransaction, signer, quotas },
  );

  const wipeAll = (): void => {
    for (const secret of secrets.values()) wipeSecret(secret);
    secrets.clear();
  };

  try {
    for (const entry of config.agents) {
      // Local policy file (on-chain cache replaces this in a later phase).
      const policy = validatePolicy(JSON.parse(readFileSync(entry.policyPath, "utf8")));

      const passphrase = await passphraseFor(entry.agent);
      let opened;
      try {
        opened = openKeystoreFile(entry.keystorePath, passphrase);
      } finally {
        passphrase.fill(0);
      }

      // The keystore's authenticated metadata must agree with the config.
      const meta = opened.meta;
      if (meta.agent !== entry.agent) {
        wipeSecret(opened.secret);
        throw new ValidationError(
          `keystore ${entry.keystorePath} belongs to agent "${meta.agent}", not "${entry.agent}"`,
        );
      }
      if (meta.chain.chainId !== context.chainId) {
        wipeSecret(opened.secret);
        throw new ValidationError(
          `keystore ${entry.keystorePath} is bound to another chain (INV-013)`,
        );
      }
      secrets.set(entry.agent, opened.secret);

      // Rotating local token (§12.3): written 0600, path readable only by
      // the agent's OS user in a multi-user deployment.
      const token = randomBytes(32).toString("base64url");
      mkdirSync(dirname(entry.tokenPath), { recursive: true });
      writeFileSync(entry.tokenPath, token + "\n", { mode: 0o600 });

      daemon.registerAgent({
        agent: entry.agent,
        permission: entry.permission,
        chain: context,
        policy,
        policyVersion: entry.policyVersion,
        enabled: true,
        token: Buffer.from(token, "utf8"),
        key: {
          keyId: entry.agent,
          publicKey: meta.publicKey,
          exportPolicy: meta.exportPolicy,
          chain: context,
          agent: entry.agent,
          permission: entry.permission,
        },
      });
    }

    await daemon.start();
  } catch (error) {
    wipeAll();
    quotas?.close();
    throw error;
  }

  return {
    daemon,
    shutdown: async () => {
      await daemon.stop();
      wipeAll();
      quotas?.close();
    },
  };
}
