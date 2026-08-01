/**
 * My Agents — the agents the CONNECTED authority controls. Empty until you
 * connect a wallet; then it lists the SignBox contract rows whose `authority`
 * is the connected account, read live from the selected network.
 */

import { useCallback, useEffect, useState } from "react";
import { useNetwork } from "../context/NetworkContext";
import { useWallet } from "../context/WalletContext";
import { SIGNBOX_CONTRACT } from "../networks";
import { listPolicies, type PolicyRow } from "../chain/rpc";

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; rows: PolicyRow[] };

export function AgentsView({ onEdit }: { onEdit: (agent: string) => void }) {
  const { network, endpoints, explorer } = useNetwork();
  const { session, connecting, openPicker } = useWallet();
  const [state, setState] = useState<State>({ kind: "loading" });

  const authority = session?.actor ?? null;

  const load = useCallback(async () => {
    if (authority === null) return;
    setState({ kind: "loading" });
    try {
      const rows = await listPolicies(endpoints, SIGNBOX_CONTRACT);
      setState({ kind: "ready", rows: rows.filter((r) => r.authority === authority) });
    } catch (err) {
      setState({ kind: "error", message: err instanceof Error ? err.message : String(err) });
    }
  }, [endpoints, authority]);

  useEffect(() => {
    void load();
  }, [load]);

  // Not connected → gate everything behind a connect prompt.
  if (authority === null) {
    return (
      <section className="agents">
        <div className="gate">
          <div className="gatemark" aria-hidden="true" />
          <h1>Connect your wallet</h1>
          <p>
            SignBox shows the agents <b>you</b> control. Connect your authority account — you&apos;ll pick
            testnet or mainnet — to see and edit their policies.
          </p>
          <button className="pushbtn gatebtn" onClick={openPicker} disabled={connecting !== null}>
            {connecting !== null ? "Opening wallet…" : "Connect wallet"}
          </button>
        </div>
      </section>
    );
  }

  return (
    <section className="agents">
      <h1>Your agents</h1>
      <p className="sub">
        Agents controlled by <code>{authority}</code> on <code>{network}</code>. The key never leaves each
        agent&apos;s daemon — what you manage here is the policy, not the secret.
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
          No agent is controlled by <code className="mono">{authority}</code> on {network} yet. Onboard one with{" "}
          <code className="mono">signbox agent create</code>.
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
