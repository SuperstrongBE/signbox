/**
 * Daemon/CLI configuration file (spec §11).
 *
 * Strictly validated (unknown fields refuse — INV-010 applies to config
 * too: a typoed security option must never be silently ignored). Policies
 * are LOCAL files in this phase; the on-chain policy cache replaces them
 * as the source of truth in a later milestone (§14).
 */

import { Ajv, type ValidateFunction } from "ajv";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { ValidationError } from "../core/errors.js";
import { XPR_NETWORKS } from "../chains/xpr/networks.js";
import type { ChainContext } from "../core/types.js";

export interface AgentConfigEntry {
  agent: string;
  permission: string;
  keystorePath: string;
  policyPath: string;
  policyVersion: number;
  tokenPath: string;
}

export interface SignBoxConfig {
  chain: "XPR";
  network: string;
  chainId: string;
  endpoints: string[];
  socketPath: string;
  adminSocketPath: string;
  quotaDbPath?: string;
  agents: AgentConfigEntry[];
}

const NAME_PATTERN = "^[a-z1-5.]{1,12}$";

const configSchema = {
  type: "object",
  additionalProperties: false,
  required: ["chain", "network", "socketPath", "agents"],
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
    socketPath: { type: "string", minLength: 1 },
    adminSocketPath: { type: "string", minLength: 1 },
    quotaDbPath: { type: "string", minLength: 1 },
    agents: {
      type: "array",
      minItems: 0,
      maxItems: 64,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["agent", "permission", "keystorePath", "policyPath", "policyVersion", "tokenPath"],
        properties: {
          agent: { type: "string", pattern: NAME_PATTERN },
          permission: { type: "string", pattern: NAME_PATTERN },
          keystorePath: { type: "string", minLength: 1 },
          policyPath: { type: "string", minLength: 1 },
          policyVersion: { type: "integer", minimum: 1 },
          tokenPath: { type: "string", minLength: 1 },
        },
      },
    },
  },
} as const;

const ajv = new Ajv({ strict: true, allErrors: false });
const validateShape: ValidateFunction = ajv.compile(configSchema);

export function expandPath(input: string): string {
  if (input === "~") return homedir();
  if (input.startsWith("~/")) return resolve(homedir(), input.slice(2));
  return resolve(input);
}

export const DEFAULT_CONFIG_PATH = "~/.signbox/config.json";

export function loadConfig(path: string): SignBoxConfig {
  let raw: string;
  try {
    raw = readFileSync(expandPath(path), "utf8");
  } catch {
    throw new ValidationError(`cannot read config file: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ValidationError("config file is not valid JSON");
  }
  if (!validateShape(parsed)) {
    const detail = validateShape.errors?.[0];
    throw new ValidationError(
      `config schema violation${detail ? `: ${detail.instancePath || "/"} ${detail.message ?? ""}` : ""}`,
    );
  }
  const file = parsed as Partial<SignBoxConfig> & {
    chain: "XPR";
    network: string;
    socketPath: string;
    agents: AgentConfigEntry[];
  };

  // INV-013/INV-009: the chain id comes from the PINNED network table, or
  // must be stated explicitly; it is never inferred from an endpoint.
  const descriptor = XPR_NETWORKS[file.network];
  const chainId = file.chainId ?? descriptor?.chainId;
  if (chainId === undefined) {
    throw new ValidationError(
      `unknown network "${file.network}" and no explicit chainId provided`,
    );
  }
  const endpoints = file.endpoints ?? descriptor?.endpoints;
  if (endpoints === undefined || endpoints.length === 0) {
    throw new ValidationError(`no endpoints known for network "${file.network}"`);
  }

  const socketPath = expandPath(file.socketPath);
  const config: SignBoxConfig = {
    chain: "XPR",
    network: file.network,
    chainId,
    endpoints,
    socketPath,
    adminSocketPath: expandPath(file.adminSocketPath ?? `${file.socketPath}.admin`),
    agents: file.agents.map((agent) => ({
      ...agent,
      keystorePath: expandPath(agent.keystorePath),
      policyPath: expandPath(agent.policyPath),
      tokenPath: expandPath(agent.tokenPath),
    })),
  };
  if (file.quotaDbPath !== undefined) {
    config.quotaDbPath = expandPath(file.quotaDbPath);
  }
  return config;
}

export function chainContextOf(config: SignBoxConfig): ChainContext {
  return { chain: config.chain, network: config.network, chainId: config.chainId };
}
