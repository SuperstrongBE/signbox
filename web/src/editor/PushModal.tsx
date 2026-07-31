/**
 * Commit modal: pick a target agent (REAL rows from the selected network's
 * SignBox contract), preview the compiled bounded policy + its policyhash.
 * Preview-only this pass — the wallet-signed setpolicy broadcast is a
 * follow-up; the modal says so honestly.
 */

import { useEffect, useState } from "react";
import { useNetwork } from "../context/NetworkContext";
import { SIGNBOX_CONTRACT } from "../networks";
import { listPolicies, type PolicyRow } from "../chain/rpc";
import { canonicalize, sha256Hex, type CompileResult } from "./compile";

type AgentsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; rows: PolicyRow[] };

export function PushModal({ compiled, onClose }: { compiled: CompileResult; onClose: () => void }) {
  const { network, endpoints } = useNetwork();
  const [agents, setAgents] = useState<AgentsState>({ kind: "loading" });
  const [selected, setSelected] = useState<string | null>(null);
  const [hash, setHash] = useState<string>("");

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const rows = await listPolicies(endpoints, SIGNBOX_CONTRACT);
        if (!alive) return;
        setAgents({ kind: "ready", rows });
        setSelected((prev) => prev ?? rows[0]?.agent ?? null);
      } catch (error) {
        if (!alive) return;
        setAgents({ kind: "error", message: error instanceof Error ? error.message : String(error) });
      }
    })();
    return () => {
      alive = false;
    };
  }, [endpoints]);

  useEffect(() => {
    let alive = true;
    void sha256Hex(canonicalize(compiled.policy)).then((h) => {
      if (alive) setHash(h);
    });
    return () => {
      alive = false;
    };
  }, [compiled]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const selectedRow = agents.kind === "ready" ? agents.rows.find((r) => r.agent === selected) : undefined;

  return (
    <div className="modalbg" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Commit policy on-chain">
        <div className="mh">
          <span>Commit policy on-chain</span>
          <button className="x" aria-label="close" onClick={onClose}>×</button>
        </div>
        <div className="mp">
          <div className="mlbl">Target agent — SignBox row on {network}</div>
          {agents.kind === "loading" && <div className="gempty">Reading the {network} chain…</div>}
          {agents.kind === "error" && <div className="mwarn">⚠ cannot reach {network}: {agents.message}</div>}
          {agents.kind === "ready" && agents.rows.length === 0 && (
            <div className="gempty">No agent registered on {network} — onboard one with <span className="mono">signbox agent create</span>.</div>
          )}
          {agents.kind === "ready" && agents.rows.length > 0 && (
            <div className="agentlist">
              {agents.rows.map((row) => (
                <div
                  key={row.agent}
                  className={`arow ${selected === row.agent ? "sel" : ""}`}
                  onClick={() => setSelected(row.agent)}
                >
                  <input type="radio" name="agent" checked={selected === row.agent} readOnly />
                  <span className="an">{row.agent}</span>
                  <span className="am">v{row.version} → v{row.version + 1} · {network}</span>
                </div>
              ))}
            </div>
          )}

          <div className="mlbl mt">Compiled policy — graph → bounded declarative</div>
          <pre className="mjson">{JSON.stringify(compiled.policy, null, 2)}</pre>
          {compiled.warnings.length > 0 && (
            <div className="mwarn">{compiled.warnings.map((w, i) => (<div key={i}>⚠ {w}</div>))}</div>
          )}
          <div className="mhash">policyhash <b>{hash === "" ? "…" : hash}</b></div>
          <p className="mnote">
            Signing &amp; broadcasting <span className="mono">setpolicy</span>
            {selectedRow !== undefined ? ` (v${selectedRow.version + 1} for ${selectedRow.agent})` : ""} with the
            authority wallet ships in the next pass — this preview is exactly the artifact it will push.
          </p>
        </div>
        <div className="mf">
          <button className="ghostbtn" onClick={onClose}>Close</button>
          <button className="pushbtn" disabled title="Wallet signing ships in the next pass">
            Sign &amp; push (coming soon)
          </button>
        </div>
      </div>
    </div>
  );
}
