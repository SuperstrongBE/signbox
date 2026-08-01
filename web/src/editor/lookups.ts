/**
 * Real resolution of Lookup nodes for the editor's test pipeline.
 *
 * Two sources:
 *  - "table" (default): the daemon's deterministic xpr.rpc.tableRow provider.
 *    Mirrors the daemon exactly (get_table_rows bounded on the key, limit 1),
 *    so what you test is what gets enforced.
 *  - "http" (test-only): a generic GET + JSON-path extraction. Handy for
 *    exploring/prototyping, but NON-deterministic and NOT a daemon provider —
 *    the compiler omits any rule that uses it (a policy must stay reproducible
 *    from on-chain data alone). Browser CORS applies to arbitrary endpoints.
 *
 * Evidence is keyed by a canonical string so the pure interpreter can read it
 * synchronously (same shape as the daemon's collect → resolve → evidence).
 */

import type { GraphNode, SampleAction } from "./types";
import { substitute, getPath } from "./eval";
import { getTableRows } from "../chain/rpc";

export interface LookupQuery {
  canon: string;
  mode: "table" | "http";
  // table
  contract?: string;
  scope?: string;
  table?: string;
  key?: string;
  // http
  url?: string;
  httpPath?: string;
}

export type LookupOutcome =
  | { status: "found"; row: unknown }
  | { status: "not_found"; row: null }
  | { status: "error"; row: null };

export type LookupEvidence = Map<string, LookupOutcome>;

function queryFor(fields: Record<string, string | boolean>, action: SampleAction): LookupQuery {
  if (fields["mode"] === "http") {
    const url = String(fields["url"] ?? "");
    const httpPath = String(fields["httpPath"] ?? "");
    return { canon: `http|${url}|${httpPath}`, mode: "http", url, httpPath };
  }
  const contract = substitute(String(fields["contract"] ?? ""), action);
  const table = substitute(String(fields["table"] ?? ""), action);
  const key = substitute(String(fields["key"] ?? "$agent"), action);
  return { canon: `${contract}|${contract}|${table}|${key}`, mode: "table", contract, scope: contract, table, key };
}

/** The canonical key the resolver uses to find this node's evidence. */
export function canonForNode(fields: Record<string, string | boolean>, action: SampleAction): string {
  return queryFor(fields, action).canon;
}

/** Distinct (lookup × action) queries with all parts resolved. */
export function collectLookupQueries(nodes: GraphNode[], actions: SampleAction[]): LookupQuery[] {
  const out = new Map<string, LookupQuery>();
  for (const n of nodes) {
    if (n.type !== "lookup") continue;
    for (const action of actions) {
      const q = queryFor(n.fields, action);
      if (q.mode === "http" ? q.url === "" : q.contract === "" || q.table === "" || q.key === "") continue;
      out.set(q.canon, q);
    }
  }
  return [...out.values()];
}

/** Fetch every query once; fail-soft (unreachable/malformed → error, empty → not_found). */
export async function resolveLookups(endpoints: string[], queries: LookupQuery[]): Promise<LookupEvidence> {
  const entries = await Promise.all(
    queries.map(async (q): Promise<[string, LookupOutcome]> => {
      try {
        if (q.mode === "http") {
          const res = await fetch(q.url ?? "");
          if (!res.ok) return [q.canon, { status: "error", row: null }];
          const json: unknown = await res.json();
          const value = q.httpPath ? getPath(json, q.httpPath) : json;
          if (value === undefined || value === null) return [q.canon, { status: "not_found", row: null }];
          return [q.canon, { status: "found", row: value }];
        }
        const res = await getTableRows<Record<string, unknown>>(endpoints, {
          code: q.contract ?? "",
          scope: q.scope ?? "",
          table: q.table ?? "",
          lower_bound: q.key,
          upper_bound: q.key,
          limit: 1,
        });
        const row = res.rows[0];
        if (row === undefined || row === null) return [q.canon, { status: "not_found", row: null }];
        if (typeof row !== "object" || Array.isArray(row)) return [q.canon, { status: "error", row: null }];
        return [q.canon, { status: "found", row }];
      } catch {
        return [q.canon, { status: "error", row: null }];
      }
    }),
  );
  return new Map(entries);
}
