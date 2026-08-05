/**
 * PolicyDialect (issue #45, C.2) — the chain-specific VOCABULARY of the
 * policy engine, extracted behind an interface so the skeleton (deny-first
 * control flow, JCS canonicalization, limits model, fail-closed pipeline)
 * stays chain-agnostic and byte-identical on every chain.
 *
 * A dialect owns exactly what varies per chain:
 *  - which match paths exist and how they resolve against a decoded action
 *    (XPR: `authorization.actor|permission`, `data.*`);
 *  - the asset grammar of limit bounds ("1.0000 XPR") and how an action's
 *    comparable asset is extracted (XPR: `data.quantity`);
 *  - which field names the recipient for per-recipient quotas (XPR: `data.to`);
 *  - the deterministic provider namespace and how a resolved query maps to a
 *    read-only relay call (XPR: `xpr.rpc.tableRow` → `get_table_rows`).
 *
 * Implementations live in src/chains/<chain>/dialect.ts and are exposed
 * through the ChainModule (#44). The engine receives the dialect through the
 * EvaluationContext; the validator takes it as a parameter — a policy is
 * always validated in ITS chain's dialect (INV-013).
 */

import type { DecodedAction } from "../types.js";
import type { AssetAmount } from "../asset.js";
import type { ProviderEvidence, ProviderQuery } from "./engine.js";

/** Structural view of the daemon's read-only relay (no daemon import here). */
export interface DialectRelay {
  call(method: string, params: unknown): Promise<unknown>;
}

export interface PolicyDialect {
  /**
   * Closed match-path vocabulary, as a schema-embeddable pattern. Drives BOTH
   * the validator (propertyNames) and the editor's compiler.
   */
  readonly matchPathPattern: string;

  /** Provider `select` field names (spec §8.4). */
  readonly selectFieldPattern: string;

  /** The chain's chain-id format (embedded in the policy document). */
  readonly chainIdPattern: string;

  /** The deterministic provider namespace this dialect serves. */
  readonly providerNamespace: string;

  /**
   * Resolve a match path against a decoded action. `undefined` means absent;
   * an unresolvable path throws AmbiguousValueError (schema-validated paths
   * only reach this on logic errors — fail closed).
   */
  resolvePath(action: DecodedAction, path: string): unknown;

  /**
   * The action's comparable asset, for value limits. Throws
   * AmbiguousValueError when the action carries none (a rule with limits on
   * such an action is a refusal, never a pass).
   */
  assetOf(action: DecodedAction): AssetAmount;

  /** The action's recipient for per-recipient quotas, if any. */
  recipientOf(action: DecodedAction): string | undefined;

  /** Parse a limit bound written in the chain's asset grammar. */
  parseAssetLimit(text: string): AssetAmount;

  /**
   * Resolve one provider query through the read-only relay (spec §8.4). The
   * generic resolver wraps this with the timeout and the fail-closed catch —
   * implementations just map the query to the chain's read call and shape
   * the row.
   */
  resolveProviderQuery(query: ProviderQuery, relay: DialectRelay): Promise<ProviderEvidence>;
}
