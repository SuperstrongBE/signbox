/**
 * My Agents — real on-chain data: the SignBox contract's `policies` table on
 * the currently selected network (read-only fetch, no SDK). Switching the
 * header selector re-queries automatically.
 */

import { useCallback, useEffect, useState } from "react";
import { useNetwork } from "../context/NetworkContext";
import { SIGNBOX_CONTRACT } from "../networks";
import { listPolicies, type PolicyRow } from "../chain/rpc";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; rows: PolicyRow[] };

export function AgentsView({ onEdit }: { onEdit: (agent: string) => void }) {
  const { network, endpoints, explorer } = useNetwork();
  const [state, setState] = useState<State>({ kind: "loading" });

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const rows = await listPolicies(endpoints, SIGNBOX_CONTRACT);
      setState({ kind: "ready", rows });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : String(error) });
    }
  }, [endpoints]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section className="agents">
      <h1>Agents</h1>
      <p className="sub">
        Rows of the <code>{SIGNBOX_CONTRACT}</code> contract&apos;s policy table on{" "}
        <code>{network}</code>. The key never leaves each agent&apos;s daemon — what you manage
        here is the policy, not the secret.
      </p>

      {state.kind === "loading" && <div className="state">Reading the {network} chain…</div>}

      {state.kind === "error" && (
        <div className="state error">
          Could not reach a {network} RPC endpoint: {state.message}
          <button className="ghostbtn" onClick={() => void load()}>Retry</button>
        </div>
      )}

      {state.kind === "ready" && state.rows.length === 0 && (
        <div className="state">
          No agent registered on {network} yet. Onboard one with <code className="mono">signbox agent create</code>.
        </div>
      )}

      {state.kind === "ready" && state.rows.length > 0 && (
        <div className="agentgrid">
          {state.rows.map((row) => (
            <AgentCard key={row.agent} row={row} explorer={explorer} onEdit={onEdit} />
          ))}
        </div>
      )}
    </section>
  );
}

function AgentCard({
  row,
  explorer,
  onEdit,
}: {
  row: PolicyRow;
  explorer: string;
  onEdit: (agent: string) => void;
}) {
  const enabled = row.enabled === true || row.enabled === 1;
  const rules = countRules(row.policyjson);
  return (
    <article className={`agentcard ${enabled ? "" : "disabled"}`}>
      <span className="rail" aria-hidden="true" />
      <div className="cardtop">
        <div>
          <div className="acct">{row.agent}</div>
          <div className="perm">@{row.agentperm}</div>
        </div>
        <span className={`pill ${enabled ? "live" : "off"}`}>{enabled ? "● guarded" : "✕ disabled"}</span>
      </div>
      <div className="kv">
        <div className="k">Authority</div>
        <div className="v">{row.authority}</div>
        <div className="k">Policy</div>
        <div className="v">v{row.version} · {rules} rule{rules === 1 ? "" : "s"}</div>
        <div className="k">Hash</div>
        <div className="v">{row.policyhash.slice(0, 16)}…</div>
      </div>
      <div className="cardfoot">
        <button className="ghostbtn" onClick={() => onEdit(row.agent)}>Edit policy</button>
        <a
          className="ghostbtn"
          style={{ textAlign: "center", textDecoration: "none" }}
          href={`${explorer}/account/${row.agent}`}
          target="_blank"
          rel="noreferrer"
        >
          Explorer ↗
        </a>
      </div>
    </article>
  );
}

function countRules(policyjson: string): number {
  try {
    const parsed = JSON.parse(policyjson) as { rules?: unknown[] };
    return Array.isArray(parsed.rules) ? parsed.rules.length : 0;
  } catch {
    return 0;
  }
}
