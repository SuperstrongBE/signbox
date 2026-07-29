/**
 * Deterministic policy engine (spec §8, §13, INV-008/INV-010).
 *
 * Pure function of (decoded transaction, policy, evaluation context):
 * no I/O, no clock, no randomness. Async providers (INV-008-A) are resolved
 * by the daemon BEFORE evaluation and injected as data; the engine itself
 * never fetches anything.
 *
 * Semantics:
 * - explicit deny always wins over allow (§8.3);
 * - every action must be individually allowed, otherwise total refusal (Q8);
 * - rules are evaluated in policy order; the first allow rule whose match
 *   applies governs the action, and its limits are then enforced;
 * - any ambiguity (precision mismatch, missing comparable value, unknown
 *   operator) resolves to a refusal — never a coercion (INV-010).
 */

import type { DecodedAction, DecodedTransaction, Decision, DenyCode } from "../types.js";
import type { MatchValue, Policy, PolicyRule } from "./schema.js";
import { AmbiguousValueError, AssetError } from "../errors.js";
import {
  compareAssets,
  compareBareAmounts,
  parseAsset,
  parseBareAmount,
  type AssetAmount,
} from "../asset.js";

export interface EvaluationContext {
  agent: string;
  agentPermission: string;
  chainId: string;
  policyVersion: number;
}

/**
 * Stateful limits the daemon must reserve atomically in the quota journal
 * BEFORE signing (spec §8.5, §15.6). Until a journal is wired in, any
 * non-empty demand list MUST be treated as a refusal by the caller.
 */
export interface QuotaDemand {
  ruleId: string;
  amount: AssetAmount;
  recipient?: string;
  maxPerHour?: AssetAmount;
  maxPerDay?: AssetAmount;
  cooldownPerRecipientMs?: number;
}

export interface EvaluationResult {
  decision: Decision;
  quotaDemands: QuotaDemand[];
}

const VARIABLES = ["$agent", "$agentPermission"] as const;

function substitute(value: string, ctx: EvaluationContext): string {
  switch (value) {
    case "$agent":
      return ctx.agent;
    case "$agentPermission":
      return ctx.agentPermission;
    default:
      if ((VARIABLES as readonly string[]).some((v) => value.includes(v))) {
        // Embedded variables ("prefix$agent") are not a supported construct:
        // refusing is safer than guessing.
        throw new AmbiguousValueError(`unsupported embedded variable in "${value}"`);
      }
      return value;
  }
}

function resolvePath(action: DecodedAction, path: string): unknown {
  if (path === "contract") return action.contract;
  if (path === "action") return action.action;
  if (path === "authorization.actor") return action.authorization[0]?.accountIdentifier;
  if (path === "authorization.permission") return action.authorization[0]?.permission;
  if (path.startsWith("data.")) {
    let current: unknown = action.data;
    for (const segment of path.slice(5).split(".")) {
      if (typeof current !== "object" || current === null || Array.isArray(current)) {
        return undefined;
      }
      current = (current as Record<string, unknown>)[segment];
    }
    return current;
  }
  // Unknown paths are rejected by the schema; reaching this is a logic error.
  throw new AmbiguousValueError(`unresolvable match path: ${path}`);
}

/** Ordered comparison. Strings must be bare amounts of equal precision; safe integers are compared as integers. */
function compareOrdered(actual: unknown, expected: string): -1 | 0 | 1 {
  if (typeof actual === "string") {
    return compareBareAmounts(parseBareAmount(actual), parseBareAmount(expected));
  }
  if (typeof actual === "number" && Number.isSafeInteger(actual)) {
    if (!/^\d+$/.test(expected)) {
      throw new AmbiguousValueError("integer field compared against non-integer bound");
    }
    const a = BigInt(actual);
    const b = BigInt(expected);
    return a < b ? -1 : a > b ? 1 : 0;
  }
  throw new AmbiguousValueError("value is not comparable");
}

/**
 * Does one predicate hold? A missing or non-matching value yields false;
 * a value that EXISTS but cannot be compared safely throws (→ refusal).
 */
function predicateHolds(actual: unknown, expected: MatchValue, ctx: EvaluationContext): boolean {
  if (typeof expected === "string") {
    return typeof actual === "string" && actual === substitute(expected, ctx);
  }
  if ("eq" in expected) {
    return typeof actual === "string" && actual === substitute(expected.eq, ctx);
  }
  if ("in" in expected) {
    return typeof actual === "string" && expected.in.some((v) => actual === substitute(v, ctx));
  }
  if ("notIn" in expected) {
    return typeof actual === "string" && !expected.notIn.some((v) => actual === substitute(v, ctx));
  }
  if ("lte" in expected) {
    if (actual === undefined || actual === null) return false;
    return compareOrdered(actual, expected.lte) <= 0;
  }
  if ("gte" in expected) {
    if (actual === undefined || actual === null) return false;
    return compareOrdered(actual, expected.gte) >= 0;
  }
  // Exhaustive; the schema forbids anything else.
  throw new AmbiguousValueError("unknown match operator");
}

function ruleMatches(action: DecodedAction, rule: PolicyRule, ctx: EvaluationContext): boolean {
  for (const [path, expected] of Object.entries(rule.match)) {
    if (!predicateHolds(resolvePath(action, path), expected, ctx)) return false;
  }
  return true;
}

/**
 * Extract the action's normalized asset (produced by the ChainAdapter
 * normalizer as data.quantity = { amount, symbol, precision }). A rule with
 * limits applied to an action without a comparable asset is an ambiguity.
 */
function actionAsset(action: DecodedAction): AssetAmount {
  const quantity = action.data["quantity"];
  if (
    typeof quantity === "object" &&
    quantity !== null &&
    typeof (quantity as Record<string, unknown>)["amount"] === "string" &&
    typeof (quantity as Record<string, unknown>)["symbol"] === "string" &&
    typeof (quantity as Record<string, unknown>)["precision"] === "number"
  ) {
    const q = quantity as { amount: string; symbol: string; precision: number };
    const bare = parseBareAmount(q.amount);
    if (bare.precision !== q.precision) {
      throw new AmbiguousValueError("normalized quantity precision mismatch");
    }
    return { units: bare.units, symbol: q.symbol, precision: q.precision };
  }
  throw new AmbiguousValueError("rule has limits but the action carries no comparable asset");
}

function deny(code: DenyCode, safeReason: string, policyVersion?: number): Decision {
  return policyVersion === undefined
    ? { effect: "deny", code, safeReason }
    : { effect: "deny", code, safeReason, policyVersion };
}

export function evaluatePolicy(
  tx: DecodedTransaction,
  policy: Policy,
  ctx: EvaluationContext,
): EvaluationResult {
  const v = ctx.policyVersion;
  const refuse = (code: DenyCode, safeReason: string): EvaluationResult => ({
    decision: deny(code, safeReason, v),
    quotaDemands: [],
  });

  try {
    // INV-013: the policy, the transaction and the daemon context must agree
    // on the exact chain identity before anything else is looked at.
    if (policy.chain.chainId !== ctx.chainId || tx.context.chainId !== ctx.chainId) {
      return refuse("CHAIN_MISMATCH", "transaction chain does not match the configured chain");
    }

    if (tx.actions.length === 0) {
      return refuse("EMPTY_TRANSACTION", "transaction contains no action");
    }

    // Fail closed on anything but exactly one authorization per action:
    // multi-auth flows are out of MVP scope and must not slip through.
    for (const action of tx.actions) {
      if (action.authorization.length !== 1) {
        return refuse("MULTI_AUTHORIZATION", "actions must carry exactly one authorization");
      }
    }

    // Explicit deny always wins (§8.3): one denied action refuses everything.
    for (const action of tx.actions) {
      for (const rule of policy.rules) {
        if (rule.effect === "deny" && ruleMatches(action, rule, ctx)) {
          return refuse("RULE_DENY", "a policy rule denies this transaction");
        }
      }
    }

    // Every action must be individually allowed (Q8: total refusal otherwise).
    const ruleIds: string[] = [];
    const quotaDemands: QuotaDemand[] = [];
    for (const action of tx.actions) {
      const governing = policy.rules.find((r) => r.effect === "allow" && ruleMatches(action, r, ctx));
      if (governing === undefined) {
        return refuse("DEFAULT_DENY", "no policy rule allows this transaction");
      }

      const limits = governing.limits;
      if (limits !== undefined) {
        const asset = actionAsset(action);
        if (limits.maxPerTransaction !== undefined) {
          if (compareAssets(asset, parseAsset(limits.maxPerTransaction)) > 0) {
            return refuse("LIMIT_EXCEEDED", "transaction exceeds a policy limit");
          }
        }
        if (
          limits.maxPerHour !== undefined ||
          limits.maxPerDay !== undefined ||
          limits.cooldownPerRecipientMs !== undefined
        ) {
          const to = action.data["to"];
          const demand: QuotaDemand = { ruleId: governing.id, amount: asset };
          if (typeof to === "string") demand.recipient = to;
          if (limits.maxPerHour !== undefined) demand.maxPerHour = parseAsset(limits.maxPerHour);
          if (limits.maxPerDay !== undefined) demand.maxPerDay = parseAsset(limits.maxPerDay);
          if (limits.cooldownPerRecipientMs !== undefined) {
            demand.cooldownPerRecipientMs = limits.cooldownPerRecipientMs;
            if (demand.recipient === undefined) {
              throw new AmbiguousValueError("cooldownPerRecipientMs requires a string data.to");
            }
          }
          quotaDemands.push(demand);
        }
      }
      ruleIds.push(governing.id);
    }

    return { decision: { effect: "allow", ruleIds, policyVersion: v }, quotaDemands };
  } catch (error) {
    // INV-010: any evaluation ambiguity or internal failure is a refusal.
    if (error instanceof AmbiguousValueError || error instanceof AssetError) {
      return refuse("AMBIGUOUS_VALUE", "transaction contains a value the policy cannot compare safely");
    }
    return refuse("INTERNAL_ERROR", "policy evaluation failed");
  }
}
