/**
 * Resolves the deterministic async provider queries a policy needs (spec §8.4),
 * turning each into evidence the PURE engine then evaluates. This is the only
 * place that touches the network for policy evaluation; the engine never does.
 *
 * Everything fails closed: an unreachable relay, a timeout, or a malformed
 * response yields `{ ok: false }`, which the engine maps to a refusal
 * (PROVIDER_UNAVAILABLE). A successful query that finds no row is a valid,
 * deterministic "not found" — distinct from "could not resolve".
 */

import type { ChainReadRelay } from "./chainRelay.js";
import type { ProviderEvidence, ProviderEvidenceMap, ProviderQuery } from "../core/policy/engine.js";

const DEFAULT_TIMEOUT_MS = 3000;

export async function resolveProviders(
  queries: ProviderQuery[],
  relay: ChainReadRelay | undefined,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<ProviderEvidenceMap> {
  const evidence: ProviderEvidenceMap = {};
  await Promise.all(
    queries.map(async (query) => {
      evidence[query.key] = await resolveOne(query, relay, timeoutMs);
    }),
  );
  return evidence;
}

async function resolveOne(
  query: ProviderQuery,
  relay: ChainReadRelay | undefined,
  timeoutMs: number,
): Promise<ProviderEvidence> {
  if (relay === undefined) return { ok: false };
  try {
    // V1 provider: xpr.rpc.tableRow → a single row bounded on the primary key.
    const params = {
      code: query.args.contract,
      scope: query.args.scope,
      table: query.args.table,
      lower_bound: query.args.key,
      upper_bound: query.args.key,
      limit: 1,
      json: true,
    };
    const result = await withTimeout(relay.call("get_table_rows", params), timeoutMs);
    const rows = (result as { rows?: unknown }).rows;
    if (!Array.isArray(rows)) return { ok: false };
    const row = rows[0];
    if (row === undefined) return { ok: true, found: false, row: null };
    if (row === null || typeof row !== "object" || Array.isArray(row)) return { ok: false };
    return { ok: true, found: true, row: row as Record<string, unknown> };
  } catch {
    return { ok: false };
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("provider timeout")), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}
