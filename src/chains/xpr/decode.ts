/**
 * XPR unserialized-JSON transaction validation and normalization (INV-014).
 *
 * The ONLY accepted input shape is a list of readable actions:
 *
 *   { "actions": [ { "account", "name", "authorization": [{actor, permission}], "data": {…} } ] }
 *
 * Everything else is rejected before any evaluation:
 * - packed transactions, hex `data`, digests: `data` must be a JSON object;
 * - `context_free_actions`, `transaction_extensions`, `delay_sec`,
 *   `expiration`, TAPOS fields: unknown top-level fields (§15.5) — the
 *   transaction envelope belongs to the signing path, not to the agent;
 * - more than one authorization per action (fail closed, MVP scope);
 * - prototype-polluting or non-ABI-shaped keys inside `data`.
 *
 * Normalization maps XPR vocabulary to the chain-agnostic core form
 * (actor → accountIdentifier, Appendix E) and expands asset strings
 * ("12.0000 XPR") into { amount, symbol, precision } so the policy engine
 * compares integers of minimal units, never floats (§8.6).
 */

import { Ajv, type ValidateFunction } from "ajv";
import { ValidationError } from "../../core/errors.js";
import type { ChainContext, DecodedAction, DecodedTransaction } from "../../core/types.js";

/** Antelope account name: 1-12 chars of a-z, 1-5 and dots. */
const NAME_PATTERN = "^[a-z1-5.]{1,12}$";
/** Action names allow 13 chars. */
const ACTION_NAME_PATTERN = "^[a-z1-5.]{1,13}$";

const DATA_KEY_RE = /^[a-zA-Z0-9_]{1,64}$/;
const ASSET_STRING_RE = /^(\d+)(?:\.(\d+))? ([A-Z]{1,7})$/;
const MAX_DATA_DEPTH = 8;
const MAX_INPUT_BYTES = 32 * 1024;

const transactionJsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["actions"],
  properties: {
    actions: {
      type: "array",
      minItems: 1,
      maxItems: 16,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["account", "name", "authorization", "data"],
        properties: {
          account: { type: "string", pattern: NAME_PATTERN },
          name: { type: "string", pattern: ACTION_NAME_PATTERN },
          authorization: {
            type: "array",
            minItems: 1,
            maxItems: 1,
            items: {
              type: "object",
              additionalProperties: false,
              required: ["actor", "permission"],
              properties: {
                actor: { type: "string", pattern: NAME_PATTERN },
                permission: { type: "string", pattern: NAME_PATTERN },
              },
            },
          },
          data: { type: "object" },
        },
      },
    },
  },
} as const;

interface XprActionJson {
  account: string;
  name: string;
  authorization: { actor: string; permission: string }[];
  data: Record<string, unknown>;
}

interface XprTransactionJson {
  actions: XprActionJson[];
}

const ajv = new Ajv({ strict: true, allErrors: false });
const validateShape: ValidateFunction = ajv.compile(transactionJsonSchema);

/** Expand "12.0000 XPR" into a structured, integer-comparable form. */
function expandAssetString(value: string): unknown {
  const match = ASSET_STRING_RE.exec(value);
  if (match === null) return value;
  const [, intPart, fracPart, symbol] = match;
  if (intPart === undefined || symbol === undefined) return value;
  return {
    amount: fracPart === undefined ? intPart : `${intPart}.${fracPart}`,
    symbol,
    precision: fracPart?.length ?? 0,
  };
}

function normalizeValue(value: unknown, depth: number): unknown {
  if (depth > MAX_DATA_DEPTH) {
    throw new ValidationError("transaction data exceeds maximum nesting depth");
  }
  if (value === null) return null;
  switch (typeof value) {
    case "string":
      return expandAssetString(value);
    case "boolean":
      return value;
    case "number":
      if (!Number.isFinite(value)) {
        throw new ValidationError("transaction data contains a non-finite number");
      }
      return value;
    case "object": {
      if (Array.isArray(value)) {
        return value.map((item) => normalizeValue(item, depth + 1));
      }
      const out: Record<string, unknown> = {};
      for (const [key, member] of Object.entries(value as Record<string, unknown>)) {
        if (!DATA_KEY_RE.test(key)) {
          throw new ValidationError("transaction data contains an invalid field name");
        }
        out[key] = normalizeValue(member, depth + 1);
      }
      return out;
    }
    default:
      throw new ValidationError(`transaction data contains an unsupported type: ${typeof value}`);
  }
}

/**
 * Validate and normalize a raw unserialized JSON transaction.
 * Throws ValidationError on ANY structural deviation — never a partial
 * decode (INV-003, INV-010).
 */
export function decodeXprTransaction(input: unknown, context: ChainContext): DecodedTransaction {
  if (typeof input === "string" || Buffer.isBuffer(input)) {
    // A string or byte payload IS a packed-transaction attempt: reject
    // categorically rather than trying to parse it (INV-014).
    throw new ValidationError("packed or serialized transactions are never accepted");
  }
  if (JSON.stringify(input)?.length > MAX_INPUT_BYTES) {
    throw new ValidationError("transaction JSON exceeds the maximum accepted size");
  }
  if (!validateShape(input)) {
    const detail = validateShape.errors?.[0];
    throw new ValidationError(
      `transaction schema violation${detail ? `: ${detail.instancePath || "/"} ${detail.message ?? ""}` : ""}`,
    );
  }
  const tx = input as XprTransactionJson;

  const actions: DecodedAction[] = tx.actions.map((action) => ({
    contract: action.account,
    action: action.name,
    authorization: action.authorization.map((auth) => ({
      accountIdentifier: auth.actor,
      permission: auth.permission,
    })),
    data: normalizeValue(action.data, 0) as Record<string, unknown>,
  }));

  return { context, actions };
}
