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

const ajv = new Ajv({ strict: true, allErrors: false });
const validateShape: ValidateFunction = ajv.compile(signRequestSchema);

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
