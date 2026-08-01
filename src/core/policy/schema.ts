/**
 * Policy document v1 (spec §8) — canonical JSON, declarative, deterministic.
 *
 * The daemon is the SOLE policy validator (spec §7.5): anything that does not
 * pass this schema — including a policy read from the chain — results in a
 * total signing refusal, never an attempt at interpretation.
 */

import { Ajv, type ValidateFunction } from "ajv";
import { ValidationError } from "../errors.js";
import { parseAsset } from "../asset.js";

export type MatchOperator =
  | { lte: string }
  | { gte: string }
  | { eq: string }
  | { in: string[] }
  | { notIn: string[] };

export type MatchValue = string | MatchOperator;

/**
 * A deterministic async provider requirement (spec §8.4, INV-008-A). V1 ships
 * one typed provider: `xpr.rpc.tableRow`. It reads a single row from a table of
 * a contract (key derived from the transaction) and asserts a condition on a
 * field of that row. It can only NARROW a rule (an extra AND condition), never
 * widen the rights the policy already grants (INV-008-A).
 *
 * `args.*` and `value` may be literals or `$`-variables ($agent,
 * $agentPermission, or a transaction path like $data.to) resolved against the
 * action being evaluated. `scope` defaults to `contract` when omitted.
 */
export interface TableRowProvider {
  provider: "xpr.rpc.tableRow";
  args: { contract: string; scope?: string; table: string; key: string };
  /** Field of the fetched row to test (single level). */
  select: string;
  /** `contains`: the field is an array holding `value`; `eq`: the field equals `value`. */
  op: "contains" | "eq";
  value: string;
}

export type ProviderRequirement = TableRowProvider;

export interface RuleLimits {
  /** Max TOTAL value moved by this rule's matching actions in one transaction. */
  maxPerTransaction?: string;
  maxPerHour?: string;
  maxPerDay?: string;
  cooldownPerRecipientMs?: number;
  /** Count-based rate limits: number of matching actions in a window. */
  maxCountPerHour?: number;
  maxCountPerDay?: number;
  maxCountPerRecipientPerHour?: number;
}

export interface PolicyRule {
  id: string;
  effect: "allow" | "deny";
  match: Record<string, MatchValue>;
  limits?: RuleLimits;
  /** Extra AND conditions resolved against on-chain state (§8.4). */
  providers?: ProviderRequirement[];
}

export interface Policy {
  schemaVersion: 1;
  default: "deny";
  chain: { name: string; chainId: string };
  rules: PolicyRule[];
  /**
   * Maximum number of actions in a single transaction. Defaults to 1 when
   * omitted: multi-action transactions are refused unless the policy opts in.
   * A multi-action transaction is the vector that both multiplies value
   * limits and smuggles a confused-deputy action (§15.5), so the safe
   * default is single-action.
   */
  maxActionsPerTransaction?: number;
}

/** Match paths are a closed vocabulary — unknown paths are schema errors. */
const MATCH_PATH_PATTERN =
  "^(contract|action|authorization\\.(actor|permission)|data\\.[a-zA-Z0-9_]{1,64}(\\.[a-zA-Z0-9_]{1,64}){0,4})$";

const matchValueSchema = {
  oneOf: [
    { type: "string", minLength: 1, maxLength: 256 },
    {
      type: "object",
      additionalProperties: false,
      required: ["lte"],
      properties: { lte: { type: "string", minLength: 1, maxLength: 64 } },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["gte"],
      properties: { gte: { type: "string", minLength: 1, maxLength: 64 } },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["eq"],
      properties: { eq: { type: "string", minLength: 1, maxLength: 256 } },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["in"],
      properties: {
        in: {
          type: "array",
          minItems: 1,
          maxItems: 256,
          items: { type: "string", minLength: 1, maxLength: 256 },
        },
      },
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["notIn"],
      properties: {
        notIn: {
          type: "array",
          minItems: 1,
          maxItems: 256,
          items: { type: "string", minLength: 1, maxLength: 256 },
        },
      },
    },
  ],
} as const;

const policyJsonSchema = {
  type: "object",
  additionalProperties: false,
  required: ["schemaVersion", "default", "chain", "rules"],
  properties: {
    schemaVersion: { const: 1 },
    default: { const: "deny" },
    maxActionsPerTransaction: { type: "integer", minimum: 1, maximum: 64 },
    chain: {
      type: "object",
      additionalProperties: false,
      required: ["name", "chainId"],
      properties: {
        name: { type: "string", minLength: 1, maxLength: 32 },
        chainId: { type: "string", pattern: "^[0-9a-f]{64}$" },
      },
    },
    rules: {
      type: "array",
      maxItems: 256,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "effect", "match"],
        properties: {
          id: { type: "string", pattern: "^[a-z0-9][a-z0-9-]{0,63}$" },
          effect: { enum: ["allow", "deny"] },
          match: {
            type: "object",
            minProperties: 1,
            maxProperties: 32,
            propertyNames: { pattern: MATCH_PATH_PATTERN },
            additionalProperties: matchValueSchema,
          },
          limits: {
            type: "object",
            additionalProperties: false,
            minProperties: 1,
            properties: {
              maxPerTransaction: { type: "string", minLength: 1, maxLength: 64 },
              maxPerHour: { type: "string", minLength: 1, maxLength: 64 },
              maxPerDay: { type: "string", minLength: 1, maxLength: 64 },
              cooldownPerRecipientMs: { type: "integer", minimum: 0, maximum: 86_400_000 },
              maxCountPerHour: { type: "integer", minimum: 1, maximum: 1_000_000 },
              maxCountPerDay: { type: "integer", minimum: 1, maximum: 1_000_000 },
              maxCountPerRecipientPerHour: { type: "integer", minimum: 1, maximum: 1_000_000 },
            },
          },
          providers: {
            type: "array",
            minItems: 1,
            maxItems: 8,
            items: {
              type: "object",
              additionalProperties: false,
              required: ["provider", "args", "select", "op", "value"],
              properties: {
                provider: { const: "xpr.rpc.tableRow" },
                args: {
                  type: "object",
                  additionalProperties: false,
                  required: ["contract", "table", "key"],
                  properties: {
                    contract: { type: "string", minLength: 1, maxLength: 64 },
                    scope: { type: "string", minLength: 1, maxLength: 64 },
                    table: { type: "string", minLength: 1, maxLength: 64 },
                    key: { type: "string", minLength: 1, maxLength: 64 },
                  },
                },
                select: { type: "string", pattern: "^[a-zA-Z0-9_]{1,64}$" },
                op: { enum: ["contains", "eq"] },
                value: { type: "string", minLength: 1, maxLength: 256 },
              },
            },
          },
        },
      },
    },
  },
} as const;

const ajv = new Ajv({ strict: true, allErrors: false });
const validateSchema: ValidateFunction = ajv.compile(policyJsonSchema);

/**
 * Validate a policy document. Throws ValidationError on ANY deviation:
 * unknown field, duplicate rule id, unparsable limit asset, deny rule with
 * limits. Returns the typed policy on success.
 */
export function validatePolicy(input: unknown): Policy {
  if (!validateSchema(input)) {
    const detail = validateSchema.errors?.[0];
    throw new ValidationError(
      `policy schema violation${detail ? `: ${detail.instancePath || "/"} ${detail.message ?? ""}` : ""}`,
    );
  }
  const policy = input as Policy;

  const seenIds = new Set<string>();
  for (const rule of policy.rules) {
    if (seenIds.has(rule.id)) {
      throw new ValidationError(`duplicate rule id: ${rule.id}`);
    }
    seenIds.add(rule.id);

    if (rule.effect === "deny" && rule.limits !== undefined) {
      throw new ValidationError(`deny rule "${rule.id}" must not declare limits`);
    }

    // Limit assets must parse at load time — a policy with a malformed cap
    // is rejected entirely rather than discovered at signing time.
    const limits = rule.limits;
    if (limits !== undefined) {
      for (const field of ["maxPerTransaction", "maxPerHour", "maxPerDay"] as const) {
        const raw = limits[field];
        if (raw !== undefined) {
          try {
            parseAsset(raw);
          } catch {
            throw new ValidationError(`rule "${rule.id}": ${field} is not a valid asset string`);
          }
        }
      }
    }
  }
  return policy;
}

/** The canonical empty policy for a chain (INV-001: authorizes nothing). */
export function emptyPolicy(chainName: string, chainId: string): Policy {
  return { schemaVersion: 1, default: "deny", chain: { name: chainName, chainId }, rules: [] };
}
