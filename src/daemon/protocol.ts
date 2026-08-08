/**
 * Daemon request/response protocol (spec §12).
 *
 * Transport framing: newline-delimited JSON over a Unix domain socket.
 * One line = one request; one line = one response. Anything that does not
 * validate against the strict schema is refused before evaluation.
 *
 * Spec delta (to fold into v0.4): a `token` field is added to SignRequest —
 * the rotating local token of §12.3 rides in the request body.
 */

import { Ajv, type ValidateFunction } from "ajv";
import { ValidationError } from "../core/errors.js";
import type { DenyCode } from "../core/types.js";

export interface SignRequestJson {
  requestId: string;
  agent: string;
  chain: string;
  network: string;
  chainId: string;
  /** Raw unserialized JSON transaction — the only accepted format (INV-014). */
  transaction: unknown;
  /**
   * When true, SignBox signs AND submits, owning the whole lifecycle: the
   * signature never leaves the daemon, and the reserved quota is committed only
   * if the tx lands / released on a deterministic chain rejection (§13).
   */
  broadcast?: boolean;
  requestedAt: string;
  expiresAt: string;
  nonce: string;
  token: string;
}

/** Outcome of the daemon-owned submit path, and its effect on stateful quota. */
export interface BroadcastReport {
  status: "accepted" | "rejected" | "ambiguous";
  receipt?: unknown;
  reason?: string;
  /** Fate of the reserved stateful quota: "none" when the policy set none. */
  quota: "committed" | "released" | "none";
}

export type SignResponseJson =
  | {
      requestId: string;
      status: "signed";
      signature: string;
      transactionDigest: string;
      signedTransaction?: unknown;
      policyVersion: number;
      /** Present only when the request asked the daemon to broadcast. */
      broadcast?: BroadcastReport;
    }
  | {
      requestId: string;
      status: "denied";
      code: DenyCode;
      safeReason: string;
      policyVersion?: number;
    };

/**
 * Standalone broadcast request (#42): submit an ALREADY-SIGNED transaction for
 * network submission, WITHOUT ever reaching the signer or the private key. It
 * is a distinct capability from signing (§5.5): a principal granted only
 * `broadcast` can submit bytes but can never obtain a signature, and a
 * sign-only principal can never submit. Discriminated by `op: "broadcast"`.
 */
export interface BroadcastRequestJson {
  op: "broadcast";
  requestId: string;
  agent: string;
  chain: string;
  network: string;
  chainId: string;
  /** The opaque signed transaction produced earlier by a sign request. */
  signedTransaction: unknown;
  requestedAt: string;
  expiresAt: string;
  nonce: string;
  token: string;
}

export type BroadcastResponseJson =
  | { requestId: string; status: "broadcast"; report: BroadcastReport }
  | { requestId: string; status: "denied"; code: DenyCode; safeReason: string };

/**
 * Read-only operations on the same authenticated socket (§12): the agent can
 * ask who it is and read public chain data through the daemon's relay, without
 * any path to signing. Discriminated from a sign request by `op`.
 */
export interface ReadRequestJson {
  op: "whoami" | "query";
  requestId: string;
  agent: string;
  requestedAt: string;
  expiresAt: string;
  token: string;
  /** query only: a whitelisted read-only chain method and its params. */
  method?: string;
  params?: Record<string, unknown>;
}

export type ReadResponseJson =
  | {
      requestId: string;
      status: "ok";
      op: "whoami";
      agent: string;
      permission: string;
      publicKey: string;
      chain: string;
      network: string;
      chainId: string;
    }
  | { requestId: string; status: "ok"; op: "query"; method: string; result: unknown }
  | { requestId: string; status: "error"; op: "whoami" | "query"; error: string };

const ISO_DATETIME_PATTERN =
  "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,3})?Z$";

const signRequestSchema = {
  type: "object",
  additionalProperties: false,
  required: [
    "requestId",
    "agent",
    "chain",
    "network",
    "chainId",
    "transaction",
    "requestedAt",
    "expiresAt",
    "nonce",
    "token",
  ],
  properties: {
    requestId: { type: "string", pattern: "^[A-Za-z0-9-]{8,64}$" },
    agent: { type: "string", pattern: "^[a-z1-5.]{1,12}$" },
    chain: { type: "string", minLength: 1, maxLength: 32 },
    network: { type: "string", minLength: 1, maxLength: 32 },
    chainId: { type: "string", pattern: "^[0-9a-f]{64}$" },
    transaction: { type: "object" },
    broadcast: { type: "boolean" },
    requestedAt: { type: "string", pattern: ISO_DATETIME_PATTERN },
    expiresAt: { type: "string", pattern: ISO_DATETIME_PATTERN },
    nonce: { type: "string", pattern: "^[A-Za-z0-9_-]{16,128}$" },
    token: { type: "string", pattern: "^[A-Za-z0-9_-]{16,256}$" },
  },
} as const;

const broadcastRequestSchema = {
  type: "object",
  additionalProperties: false,
  required: [
    "op",
    "requestId",
    "agent",
    "chain",
    "network",
    "chainId",
    "signedTransaction",
    "requestedAt",
    "expiresAt",
    "nonce",
    "token",
  ],
  properties: {
    op: { const: "broadcast" },
    requestId: { type: "string", pattern: "^[A-Za-z0-9-]{8,64}$" },
    agent: { type: "string", pattern: "^[a-z1-5.]{1,12}$" },
    chain: { type: "string", minLength: 1, maxLength: 32 },
    network: { type: "string", minLength: 1, maxLength: 32 },
    chainId: { type: "string", pattern: "^[0-9a-f]{64}$" },
    signedTransaction: { type: "object" },
    requestedAt: { type: "string", pattern: ISO_DATETIME_PATTERN },
    expiresAt: { type: "string", pattern: ISO_DATETIME_PATTERN },
    nonce: { type: "string", pattern: "^[A-Za-z0-9_-]{16,128}$" },
    token: { type: "string", pattern: "^[A-Za-z0-9_-]{16,256}$" },
  },
} as const;

const readRequestSchema = {
  type: "object",
  additionalProperties: false,
  required: ["op", "requestId", "agent", "requestedAt", "expiresAt", "token"],
  properties: {
    op: { enum: ["whoami", "query"] },
    requestId: { type: "string", pattern: "^[A-Za-z0-9-]{8,64}$" },
    agent: { type: "string", pattern: "^[a-z1-5.]{1,12}$" },
    requestedAt: { type: "string", pattern: ISO_DATETIME_PATTERN },
    expiresAt: { type: "string", pattern: ISO_DATETIME_PATTERN },
    token: { type: "string", pattern: "^[A-Za-z0-9_-]{16,256}$" },
    method: { type: "string", pattern: "^[a-z_]{1,40}$" },
    params: { type: "object" },
  },
} as const;

const ajv = new Ajv({ strict: true, allErrors: false });
const validateShape: ValidateFunction = ajv.compile(signRequestSchema);
const validateReadShape: ValidateFunction = ajv.compile(readRequestSchema);
const validateBroadcastShape: ValidateFunction = ajv.compile(broadcastRequestSchema);

/** Parse and validate one request line. Throws ValidationError on anything off. */
export function parseSignRequest(line: string): SignRequestJson {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new ValidationError("request is not valid JSON");
  }
  if (!validateShape(parsed)) {
    const detail = validateShape.errors?.[0];
    throw new ValidationError(
      `request schema violation${detail ? `: ${detail.instancePath || "/"} ${detail.message ?? ""}` : ""}`,
    );
  }
  const request = parsed as SignRequestJson;
  if (Number.isNaN(Date.parse(request.requestedAt)) || Number.isNaN(Date.parse(request.expiresAt))) {
    throw new ValidationError("request timestamps are not valid dates");
  }
  return request;
}

/** Peek the operation kind without full validation. Defaults to "sign". */
export function peekOp(line: string): "sign" | "broadcast" | "whoami" | "query" {
  try {
    const op = (JSON.parse(line) as { op?: unknown }).op;
    return op === "whoami" || op === "query" || op === "broadcast" ? op : "sign";
  } catch {
    return "sign";
  }
}

/** Parse and validate a standalone broadcast request line. Throws on anything off. */
export function parseBroadcastRequest(line: string): BroadcastRequestJson {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new ValidationError("request is not valid JSON");
  }
  if (!validateBroadcastShape(parsed)) {
    const detail = validateBroadcastShape.errors?.[0];
    throw new ValidationError(
      `broadcast request schema violation${detail ? `: ${detail.instancePath || "/"} ${detail.message ?? ""}` : ""}`,
    );
  }
  const request = parsed as BroadcastRequestJson;
  if (Number.isNaN(Date.parse(request.requestedAt)) || Number.isNaN(Date.parse(request.expiresAt))) {
    throw new ValidationError("request timestamps are not valid dates");
  }
  return request;
}

/** Parse and validate a read-only request line. Throws on anything off. */
export function parseReadRequest(line: string): ReadRequestJson {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new ValidationError("request is not valid JSON");
  }
  if (!validateReadShape(parsed)) {
    throw new ValidationError("read request does not match the expected schema");
  }
  const request = parsed as ReadRequestJson;
  if (request.op === "query" && (request.method === undefined || request.method === "")) {
    throw new ValidationError("query requires a method");
  }
  if (Number.isNaN(Date.parse(request.requestedAt)) || Number.isNaN(Date.parse(request.expiresAt))) {
    throw new ValidationError("request timestamps are not valid dates");
  }
  return request;
}
