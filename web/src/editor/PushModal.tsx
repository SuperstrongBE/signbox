/**
 * Commit modal: pick a target agent (REAL rows from the selected network's
 * SignBox contract), preview the compiled bounded policy + its policyhash, and
 * push it on-chain with the authority's wallet.
 *
 * The pushed `policyjson` is the CANONICAL string (verified byte-identical to
 * what the daemon produces) and `policyhash = sha256(policyjson)`, so the
 * contract's integrity check and the daemon's canonical check both pass.
 * SignBox never sees a key — the authority signs `setpolicy` in its own wallet.
 */

import { useEffect, useMemo, useState } from "react";
import { useNetwork } from "../context/NetworkContext";
import { SIGNBOX_CONTRACT } from "../networks";
import { listPolicies, type PolicyRow } from "../chain/rpc";
import { connectNetwork, type Connected } from "../wallet";
import { canonicalize, sha256Hex, type CompileResult } from "./compile";

type AgentsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; rows: PolicyRow[] };

type Phase =
  | { kind: "idle" }
  | { kind: "connecting" }
  | { kind: "signing" }
  | { kind: "done"; txid: string; version: number }
  | { kind: "error"; message: string };

export function PushModal({
  compiled,
  preselect,
  onClose,
}: {
  compiled: CompileResult;
  preselect: string | null;
  onClose: () => void;
}) {
  const { network, endpoints, chainId, explorer } = useNetwork();
  const [agents, setAgents] = useState<AgentsState>({ kind: "loading" });
  const [selected, setSelected] = useState<string | null>(preselect);
  const [hash, setHash] = useState<string>("");
  const [session, setSession] = useState<Connected | null>(null);
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });

  // policyjson MUST be the canonical form (what the daemon re-derives).
  const policyjson = useMemo(() => canonicalize(compiled.policy), [compiled]);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const rows = await listPolicies(endpoints, SIGNBOX_CONTRACT);
        if (!alive) return;
        setAgents({ kind: "ready", rows });
        setSelected((prev) => (prev !== null && rows.some((r) => r.agent === prev) ? prev : rows[0]?.agent ?? null));
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
    void sha256Hex(policyjson).then((h) => {
      if (alive) setHash(h);
    });
    return () => {
      alive = false;
    };
  }, [policyjson]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const row = agents.kind === "ready" ? agents.rows.find((r) => r.agent === selected) : undefined;
  const authorityMismatch = session !== null && row !== undefined && session.actor !== row.authority;
  const busy = phase.kind === "connecting" || phase.kind === "signing";

  async function onConnect() {
    setPhase({ kind: "connecting" });
    try {
      const s = await connectNetwork(endpoints, chainId, SIGNBOX_CONTRACT);
      setSession(s);
      setPhase({ kind: "idle" });
    } catch (error) {
      setPhase({ kind: "error", message: error instanceof Error ? error.message : String(error) });
    }
  }

  async function onPush() {
    if (session === null || row === undefined || hash === "") return;
    const version = row.version + 1;
    setPhase({ kind: "signing" });
    try {
      const { txid } = await session.transact([
        {
          account: SIGNBOX_CONTRACT,
          name: "setpolicy",
          authorization: [{ actor: session.actor, permission: session.permission }],
          data: { agent: row.agent, version, policyhash: hash, policyjson },
        },
      ]);
      setPhase({ kind: "done", txid, version });
    } catch (error) {
      setPhase({ kind: "error", message: error instanceof Error ? error.message : String(error) });
    }
  }

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
              {agents.rows.map((r) => (
                <div key={r.agent} className={`arow ${selected === r.agent ? "sel" : ""}`} onClick={() => setSelected(r.agent)}>
                  <input type="radio" name="agent" checked={selected === r.agent} readOnly />
                  <span className="an">{r.agent}</span>
                  <span className="am">v{r.version} → v{r.version + 1} · {r.authority}</span>
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

          {phase.kind === "done" ? (
            <div className="pushresult ok">
              ✓ setpolicy v{phase.version} pushed for {row?.agent}.{" "}
              <a href={`${explorer}/transaction/${phase.txid}`} target="_blank" rel="noreferrer">tx {phase.txid.slice(0, 12)}…</a>
            </div>
          ) : authorityMismatch ? (
            <div className="pushresult warn">
              Connected as <b>{session?.actor}</b>, but this row&apos;s authority is <b>{row?.authority}</b>. Reconnect with the authority account.
              <button className="ghostbtn" style={{ marginTop: 10 }} onClick={() => setSession(null)}>Reconnect</button>
            </div>
          ) : session !== null ? (
            <div className="mnote">Connected as <span className="mono">{session.actor}@{session.permission}</span> — this signs <span className="mono">setpolicy</span> in your own wallet; SignBox never sees a key.</div>
          ) : (
            <div className="mnote">Push writes the policy to the <span className="mono">{SIGNBOX_CONTRACT}</span> contract, signed by the agent&apos;s authority.</div>
          )}
          {phase.kind === "error" && <div className="mwarn">⚠ {phase.message}</div>}
        </div>
        <div className="mf">
          <button className="ghostbtn" onClick={onClose}>Close</button>
          {phase.kind === "done" ? (
            <button className="pushbtn" onClick={onClose}>Done</button>
          ) : session === null ? (
            <button className="pushbtn" onClick={onConnect} disabled={busy || row === undefined}>
              {phase.kind === "connecting" ? "Opening wallet…" : `Connect ${network} wallet`}
            </button>
          ) : (
            <button className="pushbtn" onClick={onPush} disabled={busy || authorityMismatch || hash === "" || row === undefined}>
              {phase.kind === "signing" ? "Signing…" : `Sign & push · v${(row?.version ?? 0) + 1}`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
