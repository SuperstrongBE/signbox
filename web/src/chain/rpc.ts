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

export interface AntelopeAccount {
  account_name: string;
  permissions: {
    perm_name: string;
    parent: string;
    required_auth: { threshold: number; keys: { key: string; weight: number }[] };
  }[];
}

/**
 * Read an account, pinning the endpoint's chain id first (#41): a lying or
 * cross-chain endpoint must not feed a forged authority key into onboarding
 * validation. Returns null when the account provably does not exist (used as
 * the stale/replay guard); throws on an unreachable/unverifiable chain.
 */
export async function getAccount(
  endpoints: string[],
  chainId: string,
  name: string,
): Promise<AntelopeAccount | null> {
  let lastError: unknown = new Error("no endpoint configured");
  for (const endpoint of endpoints) {
    const base = endpoint.replace(/\/$/, "");
    try {
      const info = await fetch(`${base}/v1/chain/get_info`, { method: "POST" });
      if (!info.ok) throw new Error(`${endpoint} get_info ${info.status}`);
      const chain = (await info.json()) as { chain_id?: string };
      if (chain.chain_id !== chainId) throw new Error(`${endpoint} serves another chain`);

      const res = await fetch(`${base}/v1/chain/get_account`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ account_name: name }),
      });
      if (res.ok) return (await res.json()) as AntelopeAccount;
      // A missing account is a definitive answer, not an endpoint failure.
      const body = await res.text();
      if (res.status === 500 && /unknown key|account_query_exception|does not exist/i.test(body)) {
        return null;
      }
      throw new Error(`${endpoint} get_account ${res.status}`);
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

/** Fetch ONE agent's policy row (bounded primary-key query), or null. */
export async function getPolicy(
  endpoints: string[],
  contract: string,
  agent: string,
): Promise<PolicyRow | null> {
  const result = await getTableRows<PolicyRow>(endpoints, {
    code: contract,
    scope: contract,
    table: "policies",
    lower_bound: agent,
    upper_bound: agent,
    limit: 1,
  });
  const row = result.rows[0];
  return row !== undefined && row.agent === agent ? row : null;
}
