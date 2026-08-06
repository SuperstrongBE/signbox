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
import type { MatchValue, Policy, PolicyRule, TableRowProvider } from "./schema.js";
import type { PolicyDialect } from "./dialect.js";
import { AmbiguousValueError, AssetError, ProviderUnavailableError } from "../errors.js";
import { canonicalize } from "../canonical/jcs.js";
import { compareBareAmounts, parseBareAmount, type AssetAmount } from "../asset.js";

/** Resolved arguments of a table-row provider query. */
export interface ProviderQuery {
  key: string;
  /** The dialect's provider namespace (XPR: "xpr.rpc.tableRow"). */
  provider: string;
  args: { contract: string; scope: string; table: string; key: string };
}

/** Evidence for one resolved provider query, injected by the daemon (§8.4). */
export type ProviderEvidence =
  | { ok: true; found: boolean; row: Record<string, unknown> | null }
  | { ok: false };

/** Evidence keyed by canonical(provider + resolved args). */
export type ProviderEvidenceMap = Record<string, ProviderEvidence>;

export interface EvaluationContext {
  agent: string;
  agentPermission: string;
  chainId: string;
  policyVersion: number;
  /** The chain's policy dialect (#45) — path resolution, asset grammar, providers. */
  dialect: PolicyDialect;
  /**
   * Resolved provider evidence (§8.4). The daemon resolves the queries listed
   * by collectProviderQueries() and passes them here. A rule whose provider has
   * no evidence — or unresolvable evidence — fails closed (PROVIDER_UNAVAILABLE).
   */
  evidence?: ProviderEvidenceMap;
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
  maxCountPerHour?: number;
  maxCountPerDay?: number;
  maxCountPerRecipientPerHour?: number;
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

/** The static part of a rule: its `match` field predicates only (no providers). */
function staticMatch(action: DecodedAction, rule: PolicyRule, ctx: EvaluationContext): boolean {
  for (const [path, expected] of Object.entries(rule.match)) {
    if (!predicateHolds(ctx.dialect.resolvePath(action, path), expected, ctx)) return false;
  }
  return true;
}

/**
 * Substitute a provider arg/value. Literals pass through; a `$`-variable is
 * resolved against the action ($agent, $agentPermission, or a match path like
 * $data.to). Anything that does not resolve to a string is an ambiguity.
 */
function substituteArg(value: string, action: DecodedAction, ctx: EvaluationContext): string {
  if (!value.startsWith("$")) return value;
  if (value === "$agent") return ctx.agent;
  if (value === "$agentPermission") return ctx.agentPermission;
  const resolved = ctx.dialect.resolvePath(action, value.slice(1));
  if (typeof resolved !== "string") {
    throw new AmbiguousValueError(`provider variable "${value}" did not resolve to a string`);
  }
  return resolved;
}

/** Fully resolve a table-row provider's args against the action (scope defaults to contract). */
function resolveTableRowArgs(
  req: TableRowProvider,
  action: DecodedAction,
  ctx: EvaluationContext,
): ProviderQuery["args"] {
  return {
    contract: substituteArg(req.args.contract, action, ctx),
    scope: substituteArg(req.args.scope ?? req.args.contract, action, ctx),
    table: substituteArg(req.args.table, action, ctx),
    key: substituteArg(req.args.key, action, ctx),
  };
}

/** Canonical evidence key so the daemon resolver and the engine agree exactly. */
function evidenceKey(provider: string, args: ProviderQuery["args"]): string {
  return canonicalize({ provider, args });
}

/**
 * The queries the daemon must resolve before evaluation: one per distinct
 * (provider, resolved args) referenced by a rule whose STATIC match already
 * passes for an action. Pure — args are built by substitution, nothing fetched.
 */
export function collectProviderQueries(
  tx: DecodedTransaction,
  policy: Policy,
  ctx: EvaluationContext,
): ProviderQuery[] {
  const out = new Map<string, ProviderQuery>();
  for (const action of tx.actions) {
    for (const rule of policy.rules) {
      if (rule.providers === undefined || rule.providers.length === 0) continue;
      if (!staticMatch(action, rule, ctx)) continue;
      for (const req of rule.providers) {
        try {
          const args = resolveTableRowArgs(req, action, ctx);
          const key = evidenceKey(req.provider, args);
          if (!out.has(key)) out.set(key, { key, provider: req.provider, args });
        } catch {
          // An arg that cannot be resolved will make the engine refuse when it
          // evaluates this rule; nothing to fetch here.
        }
      }
    }
  }
  return [...out.values()];
}

/** Does a single provider requirement hold against the injected evidence? */
function providerHolds(req: TableRowProvider, action: DecodedAction, ctx: EvaluationContext): boolean {
  const args = resolveTableRowArgs(req, action, ctx);
  const evidence = ctx.evidence?.[evidenceKey(req.provider, args)];
  if (evidence === undefined || evidence.ok !== true) {
    // Missing or unresolvable evidence — never silently pass (fail closed).
    throw new ProviderUnavailableError(`provider "${req.provider}" evidence is unavailable`);
  }
  if (!evidence.found || evidence.row === null) return false; // row absent → condition false
  const field = evidence.row[req.select];
  const target = substituteArg(req.value, action, ctx);
  if (req.op === "contains") {
    if (!Array.isArray(field)) {
      throw new AmbiguousValueError(`provider field "${req.select}" is not an array for "contains"`);
    }
    return field.map((x) => String(x)).includes(target);
  }
  // op === "eq"
  return field !== undefined && field !== null && String(field) === target;
}

function ruleMatches(action: DecodedAction, rule: PolicyRule, ctx: EvaluationContext): boolean {
  if (!staticMatch(action, rule, ctx)) return false;
  if (rule.providers !== undefined) {
    for (const req of rule.providers) {
      if (!providerHolds(req, action, ctx)) return false;
    }
  }
  return true;
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

    // A multi-action transaction is the vector that both multiplies value
    // limits and smuggles a confused-deputy action (§15.5). The default is
    // single-action; the policy must explicitly opt into more.
    const maxActions = policy.maxActionsPerTransaction ?? 1;
    if (tx.actions.length > maxActions) {
      return refuse("TOO_MANY_ACTIONS", "transaction has more actions than the policy allows");
    }

    // Every action must be individually allowed (Q8: total refusal otherwise).
    const ruleIds: string[] = [];
    const quotaDemands: QuotaDemand[] = [];
    // maxPerTransaction is the SUM across all of a rule's matching actions in
    // this transaction, so N actions cannot multiply a per-transaction cap.
    const perRuleTotals = new Map<string, { units: bigint; cap: AssetAmount }>();

    for (const action of tx.actions) {
      const governing = policy.rules.find((r) => r.effect === "allow" && ruleMatches(action, r, ctx));
      if (governing === undefined) {
        return refuse("DEFAULT_DENY", "no policy rule allows this transaction");
      }

      const limits = governing.limits;
      if (limits !== undefined) {
        const asset = ctx.dialect.assetOf(action);

        if (limits.maxPerTransaction !== undefined) {
          const cap = ctx.dialect.parseAssetLimit(limits.maxPerTransaction);
          // The cap is per symbol; an action of a different symbol under a
          // value cap would go uncapped — refuse rather than let it through.
          if (asset.symbol !== cap.symbol || asset.precision !== cap.precision) {
            throw new AmbiguousValueError("action asset does not match the rule's per-transaction cap");
          }
          const entry = perRuleTotals.get(governing.id) ?? { units: 0n, cap };
          entry.units += asset.units;
          perRuleTotals.set(governing.id, entry);
        }

        const wantsWindow =
          limits.maxPerHour !== undefined ||
          limits.maxPerDay !== undefined ||
          limits.cooldownPerRecipientMs !== undefined ||
          limits.maxCountPerHour !== undefined ||
          limits.maxCountPerDay !== undefined ||
          limits.maxCountPerRecipientPerHour !== undefined;
        if (wantsWindow) {
          const recipient = ctx.dialect.recipientOf(action);
          const demand: QuotaDemand = { ruleId: governing.id, amount: asset };
          if (recipient !== undefined) demand.recipient = recipient;
          if (limits.maxPerHour !== undefined) demand.maxPerHour = ctx.dialect.parseAssetLimit(limits.maxPerHour);
          if (limits.maxPerDay !== undefined) demand.maxPerDay = ctx.dialect.parseAssetLimit(limits.maxPerDay);
          if (limits.cooldownPerRecipientMs !== undefined) {
            demand.cooldownPerRecipientMs = limits.cooldownPerRecipientMs;
            if (demand.recipient === undefined) {
              throw new AmbiguousValueError("cooldownPerRecipientMs requires a recipient on the action");
            }
          }
          if (limits.maxCountPerHour !== undefined) demand.maxCountPerHour = limits.maxCountPerHour;
          if (limits.maxCountPerDay !== undefined) demand.maxCountPerDay = limits.maxCountPerDay;
          if (limits.maxCountPerRecipientPerHour !== undefined) {
            demand.maxCountPerRecipientPerHour = limits.maxCountPerRecipientPerHour;
            if (demand.recipient === undefined) {
              throw new AmbiguousValueError("maxCountPerRecipientPerHour requires a recipient on the action");
            }
          }
          quotaDemands.push(demand);
        }
      }
      ruleIds.push(governing.id);
    }

    // Enforce the aggregated per-transaction caps: the SUM, not per action.
    for (const { units, cap } of perRuleTotals.values()) {
      if (units > cap.units) {
        return refuse("LIMIT_EXCEEDED", "transaction exceeds a policy limit");
      }
    }

    return { decision: { effect: "allow", ruleIds, policyVersion: v }, quotaDemands };
  } catch (error) {
    // INV-010: any evaluation ambiguity or internal failure is a refusal.
    if (error instanceof ProviderUnavailableError) {
      return refuse("PROVIDER_UNAVAILABLE", "a policy provider could not be resolved");
    }
    if (error instanceof AmbiguousValueError || error instanceof AssetError) {
      return refuse("AMBIGUOUS_VALUE", "transaction contains a value the policy cannot compare safely");
    }
    return refuse("INTERNAL_ERROR", "policy evaluation failed");
  }
}
