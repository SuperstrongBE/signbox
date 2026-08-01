/**
 * Commit modal. You reach it already connected (you can only edit your own
 * agents), so it reuses the global wallet session. It lists YOUR agents on the
 * selected network, previews the compiled bounded policy + its policyhash, and
 * pushes `signbox::setpolicy` signed by your authority.
 *
 * The pushed `policyjson` is the CANONICAL string (verified byte-identical to
 * what the daemon produces) and `policyhash = sha256(policyjson)`, so the
 * contract's integrity check and the daemon's canonical check both pass.
 */

import { useEffect, useMemo, useState } from "react";
import { useNetwork } from "../context/NetworkContext";
import { useWallet } from "../context/WalletContext";
import { SIGNBOX_CONTRACT } from "../networks";
import { listPolicies, type PolicyRow } from "../chain/rpc";
import { canonicalize, sha256Hex, type CompileResult } from "./compile";

type AgentsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; rows: PolicyRow[] };

type Phase =
  | { kind: "idle" }
  | { kind: "signing" }
  | { kind: "done"; txid: string; version: number }
  | { kind: "error"; message: string };

export function PushModal({
  compiled,
  preselect,
  onClose,
}: {
  compiled: CompileResult;
  preselect: string;
  onClose: () => void;
}) {
  const { network, endpoints, explorer } = useNetwork();
  const { session, connecting, connect } = useWallet();
  const [agents, setAgents] = useState<AgentsState>({ kind: "loading" });
  const [selected, setSelected] = useState<string>(preselect);
  const [hash, setHash] = useState<string>("");
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });

  const policyjson = useMemo(() => canonicalize(compiled.policy), [compiled]);
  const authority = session?.actor ?? null;

  useEffect(() => {
    if (authority === null) return;
    let alive = true;
    void (async () => {
      try {
        const rows = await listPolicies(endpoints, SIGNBOX_CONTRACT);
        if (!alive) return;
        const mine = rows.filter((r) => r.authority === authority);
        setAgents({ kind: "ready", rows: mine });
        setSelected((prev) => (mine.some((r) => r.agent === prev) ? prev : mine[0]?.agent ?? prev));
      } catch (error) {
        if (!alive) return;
        setAgents({ kind: "error", message: error instanceof Error ? error.message : String(error) });
      }
    })();
    return () => {
      alive = false;
    };
  }, [endpoints, authority]);

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
          <div className="mlbl">Target agent — your rows on {network}</div>
          {authority === null && <div className="gempty">Connect your wallet to choose an agent.</div>}
          {authority !== null && agents.kind === "loading" && <div className="gempty">Reading the {network} chain…</div>}
          {authority !== null && agents.kind === "error" && <div className="mwarn">⚠ cannot reach {network}: {agents.message}</div>}
          {authority !== null && agents.kind === "ready" && agents.rows.length === 0 && (
            <div className="gempty">No agent controlled by {authority} on {network}.</div>
          )}
          {authority !== null && agents.kind === "ready" && agents.rows.length > 0 && (
            <div className="agentlist">
              {agents.rows.map((r) => (
                <div key={r.agent} className={`arow ${selected === r.agent ? "sel" : ""}`} onClick={() => setSelected(r.agent)}>
                  <input type="radio" name="agent" checked={selected === r.agent} readOnly />
                  <span className="an">{r.agent}</span>
                  <span className="am">v{r.version} → v{r.version + 1}</span>
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
          ) : authority !== null ? (
            <div className="mnote">Signed as <span className="mono">{session?.actor}@{session?.permission}</span> — <span className="mono">setpolicy</span> goes to your wallet; SignBox never sees a key.</div>
          ) : (
            <div className="mnote">Connect the agent&apos;s authority wallet to push.</div>
          )}
          {phase.kind === "error" && <div className="mwarn">⚠ {phase.message}</div>}
        </div>
        <div className="mf">
          <button className="ghostbtn" onClick={onClose}>Close</button>
          {phase.kind === "done" ? (
            <button className="pushbtn" onClick={onClose}>Done</button>
          ) : session === null ? (
            <button className="pushbtn" onClick={() => void connect()} disabled={connecting}>
              {connecting ? "Opening wallet…" : `Connect ${network} wallet`}
            </button>
          ) : (
            <button className="pushbtn" onClick={onPush} disabled={phase.kind === "signing" || hash === "" || row === undefined}>
              {phase.kind === "signing" ? "Signing…" : `Sign & push · v${(row?.version ?? 0) + 1}`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
