/**
 * The XPR policy dialect (issue #45, C.2) — the Antelope vocabulary that used
 * to be hardcoded in the core engine and resolver, now behind PolicyDialect:
 *
 *  - match paths: contract / action / authorization.(actor|permission) /
 *    data.* (single-authorization model, actor → accountIdentifier);
 *  - assets: the "1.0000 XPR" grammar (parseAsset) and the normalizer's
 *    data.quantity = { amount, symbol, precision } shape;
 *  - recipient: data.to;
 *  - provider: xpr.rpc.tableRow → get_table_rows bounded on the primary key.
 *
 * The shared patterns come from core/policy/vocabulary.ts — the SAME module
 * the web editor imports, so daemon, validator and editor stay in lockstep.
 */

import { AmbiguousValueError } from "../../core/errors.js";
import { parseAsset, parseBareAmount, type AssetAmount } from "../../core/asset.js";
import {
  CHAIN_ID_PATTERN,
  MATCH_PATH_PATTERN,
  SELECT_FIELD_PATTERN,
} from "../../core/policy/vocabulary.js";
import type { DecodedAction } from "../../core/types.js";
import type { DialectRelay, PolicyDialect } from "../../core/policy/dialect.js";
import type { ProviderEvidence, ProviderQuery } from "../../core/policy/engine.js";

export const xprDialect: PolicyDialect = {
  matchPathPattern: MATCH_PATH_PATTERN,
  selectFieldPattern: SELECT_FIELD_PATTERN,
  chainIdPattern: CHAIN_ID_PATTERN,
  providerNamespace: "xpr.rpc.tableRow",

  resolvePath(action: DecodedAction, path: string): unknown {
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
  },

  /**
   * The normalizer produces data.quantity = { amount, symbol, precision };
   * a rule with limits applied to an action without it is an ambiguity.
   */
  assetOf(action: DecodedAction): AssetAmount {
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
  },

  recipientOf(action: DecodedAction): string | undefined {
    const to = action.data["to"];
    return typeof to === "string" ? to : undefined;
  },

  parseAssetLimit: parseAsset,

  async resolveProviderQuery(query: ProviderQuery, relay: DialectRelay): Promise<ProviderEvidence> {
    // xpr.rpc.tableRow → a single row bounded on the primary key.
    const params = {
      code: query.args.contract,
      scope: query.args.scope,
      table: query.args.table,
      lower_bound: query.args.key,
      upper_bound: query.args.key,
      limit: 1,
      json: true,
    };
    const result = await relay.call("get_table_rows", params);
    const rows = (result as { rows?: unknown }).rows;
    if (!Array.isArray(rows)) return { ok: false };
    const row = rows[0];
    if (row === undefined) return { ok: true, found: false, row: null };
    if (row === null || typeof row !== "object" || Array.isArray(row)) return { ok: false };
    return { ok: true, found: true, row: row as Record<string, unknown> };
  },
};
