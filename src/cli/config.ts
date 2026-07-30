/**
 * Daemon configuration (spec §11, §14) — zero-config by default.
 *
 * There is NO agents/policies configuration:
 * - agents are discovered from the keystores the daemon holds (their agent
 *   name and chain come from the keystore's authenticated metadata);
 * - policies live on-chain in the SignBox contract and are read through the
 *   anti-rollback cache (§14) — never a local file.
 *
 * A config file is OPTIONAL and only overrides deployment settings (network,
 * endpoints, contract account, paths). It is strictly validated (a typoed
 * security option must never be silently ignored). Absent a file, everything
 * defaults under ~/.signbox/.
 */

import { Ajv, type ValidateFunction } from "ajv";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { ValidationError } from "../core/errors.js";
import { XPR_NETWORKS } from "../chains/xpr/networks.js";
import type { ChainContext } from "../core/types.js";

export interface SignBoxConfig {
  chain: "XPR";
  network: string;
  chainId: string;
  endpoints: string[];
  /** Account hosting the SignBox policy contract. */
  signboxContract: string;
  baseDir: string;
  keystoreDir: string;
  tokenDir: string;
  socketPath: string;
  adminSocketPath: string;
  /** Shared local state: quota journal + policy cache (§14.2). */
  stateDbPath: string;
}

const NAME_PATTERN = "^[a-z1-5.]{1,12}$";

/** Optional deployment overrides — never agents or policies. */
const configSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    chain: { const: "XPR" },
    network: { type: "string", minLength: 1, maxLength: 32 },
    chainId: { type: "string", pattern: "^[0-9a-f]{64}$" },
    endpoints: {
      type: "array",
      minItems: 1,
      maxItems: 8,
      items: { type: "string", pattern: "^https?://" },
    },
    signboxContract: { type: "string", pattern: NAME_PATTERN },
    baseDir: { type: "string", minLength: 1 },
    keystoreDir: { type: "string", minLength: 1 },
    tokenDir: { type: "string", minLength: 1 },
    socketPath: { type: "string", minLength: 1 },
    adminSocketPath: { type: "string", minLength: 1 },
    stateDbPath: { type: "string", minLength: 1 },
  },
} as const;

interface ConfigFile {
  chain?: "XPR";
  network?: string;
  chainId?: string;
  endpoints?: string[];
  signboxContract?: string;
  baseDir?: string;
  keystoreDir?: string;
  tokenDir?: string;
  socketPath?: string;
  adminSocketPath?: string;
  stateDbPath?: string;
}

const ajv = new Ajv({ strict: true, allErrors: false });
const validateShape: ValidateFunction = ajv.compile(configSchema);

export function expandPath(input: string): string {
  if (input === "~") return homedir();
  if (input.startsWith("~/")) return resolve(homedir(), input.slice(2));
  return resolve(input);
}

export const DEFAULT_CONFIG_PATH = "~/.signbox/config.json";
const DEFAULT_BASE_DIR = "~/.signbox";
const DEFAULT_NETWORK = "testnet";
const DEFAULT_CONTRACT = "signbox";

export interface ConfigOverrides {
  network?: string;
  signboxContract?: string;
}

/**
 * Resolve the daemon configuration. Reads the config file if present (never
 * required — zero-config), applies optional CLI overrides, and pins the
 * chain id from the network table (INV-009/INV-013).
 */
export function loadConfig(path: string = DEFAULT_CONFIG_PATH, overrides: ConfigOverrides = {}): SignBoxConfig {
  const configPath = expandPath(path);
  let file: ConfigFile = {};
  if (existsSync(configPath)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(configPath, "utf8"));
    } catch {
      throw new ValidationError("config file is not valid JSON");
    }
    if (!validateShape(parsed)) {
      const detail = validateShape.errors?.[0];
      throw new ValidationError(
        `config schema violation${detail ? `: ${detail.instancePath || "/"} ${detail.message ?? ""}` : ""}`,
      );
    }
    file = parsed as ConfigFile;
  }

  const network = overrides.network ?? file.network ?? DEFAULT_NETWORK;
  const descriptor = XPR_NETWORKS[network];
  const chainId = file.chainId ?? descriptor?.chainId;
  if (chainId === undefined) {
    throw new ValidationError(`unknown network "${network}" and no explicit chainId provided`);
  }
  const endpoints = file.endpoints ?? descriptor?.endpoints;
  if (endpoints === undefined || endpoints.length === 0) {
    throw new ValidationError(`no endpoints known for network "${network}"`);
  }

  const baseDir = expandPath(file.baseDir ?? DEFAULT_BASE_DIR);
  return {
    chain: "XPR",
    network,
    chainId,
    endpoints,
    signboxContract: overrides.signboxContract ?? file.signboxContract ?? DEFAULT_CONTRACT,
    baseDir,
    keystoreDir: file.keystoreDir !== undefined ? expandPath(file.keystoreDir) : join(baseDir, "keystores"),
    tokenDir: file.tokenDir !== undefined ? expandPath(file.tokenDir) : join(baseDir, "tokens"),
    socketPath: file.socketPath !== undefined ? expandPath(file.socketPath) : join(baseDir, "signbox.sock"),
    adminSocketPath:
      file.adminSocketPath !== undefined ? expandPath(file.adminSocketPath) : join(baseDir, "signbox.admin.sock"),
    stateDbPath: file.stateDbPath !== undefined ? expandPath(file.stateDbPath) : join(baseDir, "state.db"),
  };
}

export function chainContextOf(config: SignBoxConfig): ChainContext {
  return { chain: config.chain, network: config.network, chainId: config.chainId };
}
