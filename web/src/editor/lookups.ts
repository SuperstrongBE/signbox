/**
 * Real on-chain resolution of Lookup nodes for the editor's test pipeline.
 *
 * Mirrors the daemon (collectProviderQueries → resolveProviders → evidence):
 * we gather every lookup's resolved args against the test action, fetch each
 * once via the read-only relay with the SAME query the daemon uses
 * (get_table_rows bounded on the key, limit 1), and key the evidence by a
 * canonical string so the pure interpreter can read it synchronously.
 */

import type { GraphNode, SampleAction } from "./types";
import { substitute } from "./eval";
import { getTableRows } from "../chain/rpc";

export interface LookupQuery {
  canon: string;
  contract: string;
  scope: string;
  table: string;
  key: string;
}

export type LookupOutcome =
  | { status: "found"; row: Record<string, unknown> }
  | { status: "not_found"; row: null }
  | { status: "error"; row: null };

export type LookupEvidence = Map<string, LookupOutcome>;

/** Resolve a lookup node's args against an action (scope defaults to contract). */
function queryFor(fields: Record<string, string | boolean>, action: SampleAction): LookupQuery {
  const contract = substitute(String(fields["contract"] ?? ""), action);
  const table = substitute(String(fields["table"] ?? ""), action);
  const key = substitute(String(fields["key"] ?? "$agent"), action);
  const scope = contract;
  return { canon: `${contract}|${scope}|${table}|${key}`, contract, scope, table, key };
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
      if (q.contract === "" || q.table === "" || q.key === "") continue;
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
        const res = await getTableRows<Record<string, unknown>>(endpoints, {
          code: q.contract,
          scope: q.scope,
          table: q.table,
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
