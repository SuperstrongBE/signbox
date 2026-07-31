/**
 * Minimal read-only chain access via plain fetch — no SDK dependency.
 * Tries each endpoint in order and returns the first success (fail over).
 * Read-only by construction: only /v1/chain/get_table_rows is exposed.
 */

export interface GetTableRowsArgs {
  code: string;
  scope: string;
  table: string;
  lower_bound?: string;
  upper_bound?: string;
  limit?: number;
}

export interface TableRowsResult<T> {
  rows: T[];
  more: boolean;
  next_key?: string;
}

export async function getTableRows<T>(
  endpoints: string[],
  args: GetTableRowsArgs,
): Promise<TableRowsResult<T>> {
  let lastError: unknown = new Error("no endpoint configured");
  for (const endpoint of endpoints) {
    try {
      const res = await fetch(`${endpoint.replace(/\/$/, "")}/v1/chain/get_table_rows`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ json: true, limit: 100, ...args }),
      });
      if (!res.ok) throw new Error(`${endpoint} answered ${res.status}`);
      return (await res.json()) as TableRowsResult<T>;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

/** One row of the SignBox contract's `policies` table (spec §7.1). */
export interface PolicyRow {
  agent: string;
  authority: string;
  agentperm: string;
  version: number;
  policyhash: string;
  policyjson: string;
  enabled: boolean | number;
  updatedat: number;
}

export async function listPolicies(endpoints: string[], contract: string): Promise<PolicyRow[]> {
  const result = await getTableRows<PolicyRow>(endpoints, {
    code: contract,
    scope: contract,
    table: "policies",
    limit: 100,
  });
  return result.rows;
}
