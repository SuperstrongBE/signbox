import { useEffect, useMemo, useState } from "react";
import { loadPayload, clearPayload, type OnboardPayload } from "./link";
import { connect, type Connected } from "./wallet";

type Phase = "idle" | "connecting" | "connected" | "signing" | "done" | "error";

export function App() {
  const [payload, setPayload] = useState<OnboardPayload | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [session, setSession] = useState<Connected | null>(null);
  const [txid, setTxid] = useState<string>("");
  const [error, setError] = useState<string>("");

  useEffect(() => {
    setPayload(loadPayload());
  }, []);

  const actions = useMemo(() => summarizeActions(payload), [payload]);

  if (payload === null) {
    return (
      <main className="shell">
        <div className="card empty">
          <h1>Nothing to authorize</h1>
          <p>Open the link from <code>signbox agent create</code> to review and sign an onboarding request.</p>
        </div>
      </main>
    );
  }

  const authorityMismatch =
    session !== null && session.actor !== payload.summary.authority;

  async function onConnect() {
    setError("");
    setPhase("connecting");
    try {
      const c = await connect(payload!);
      setSession(c);
      setPhase("connected");
    } catch (e) {
      setError(errMsg(e));
      setPhase("error");
    }
  }

  async function onSign() {
    if (session === null) return;
    setError("");
    setPhase("signing");
    try {
      const { txid: id } = await session.transact(payload!.actions);
      setTxid(id);
      clearPayload();
      setPhase("done");
    } catch (e) {
      setError(errMsg(e));
      setPhase("error");
    }
  }

  return (
    <main className="shell">
      <div className="card">
        <header>
          <div className="mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <rect x="4" y="10" width="16" height="10" rx="2"></rect>
              <path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
              <path d="M12 14v2"></path>
            </svg>
          </div>
          <div>
            <h1>Authorize a new agent</h1>
            <p className="net">{payload.network} &middot; contract {payload.signboxContract}</p>
          </div>
        </header>

        <dl className="summary">
          <div><dt>Agent</dt><dd>{payload.summary.agent}</dd></div>
          <div><dt>Authority</dt><dd>{payload.summary.authority}</dd></div>
          <div><dt>Permission</dt><dd>{payload.summary.permission}</dd></div>
          <div><dt>Mode</dt><dd>{payload.summary.mode}</dd></div>
          <div className="wide"><dt>Agent public key</dt><dd className="mono">{payload.summary.publicKey}</dd></div>
        </dl>

        <div className="actions-list">
          <span className="lbl">The wallet will sign {payload.actions.length} action{payload.actions.length === 1 ? "" : "s"}</span>
          <ul>
            {actions.map((a, i) => (
              <li key={i}><span className="an">{a.name}</span> <span className="ad">{a.detail}</span></li>
            ))}
          </ul>
        </div>

        {phase === "done" ? (
          <div className="result ok">
            <strong>Signed &amp; broadcast.</strong>
            <p>Transaction <code className="mono">{txid}</code>. Return to your terminal — SignBox confirms it on-chain and activates the agent key.</p>
          </div>
        ) : (
          <div className="controls">
            {session === null ? (
              <button className="btn primary" onClick={onConnect} disabled={phase === "connecting"}>
                {phase === "connecting" ? "Opening wallet…" : `Connect ${payload.network} wallet`}
              </button>
            ) : authorityMismatch ? (
              <div className="result warn">
                <strong>Wrong account.</strong>
                <p>Connected as <code>{session.actor}</code>, but this request must be signed by the authority <code>{payload.summary.authority}</code>. Reconnect with the right account.</p>
                <button className="btn" onClick={() => { setSession(null); setPhase("idle"); }}>Reconnect</button>
              </div>
            ) : (
              <button className="btn primary" onClick={onSign} disabled={phase === "signing"}>
                {phase === "signing" ? "Signing…" : "Sign & create agent"}
              </button>
            )}
            {session !== null && !authorityMismatch && (
              <p className="who">Connected as <code>{session.actor}@{session.permission}</code></p>
            )}
          </div>
        )}

        {error !== "" && <div className="result err"><strong>Failed.</strong><p>{error}</p></div>}
      </div>

      <p className="foot">SignBox never sees your keys. You sign in your own wallet; the daemon verifies the result on-chain before activating the agent.</p>
    </main>
  );
}

function summarizeActions(payload: OnboardPayload | null): { name: string; detail: string }[] {
  if (payload === null) return [];
  return payload.actions.map((a) => {
    const d = a.data;
    switch (`${a.account}::${a.name}`) {
      case "eosio::newaccount":
        return { name: "newaccount", detail: `create ${String(d["name"])}` };
      case "eosio::buyrambytes":
        return { name: "buyrambytes", detail: `${String(d["bytes"])} bytes, paid by ${String(d["payer"])}` };
      case "eosio::updateauth":
        return { name: "updateauth", detail: `add permission "${String(d["permission"])}"` };
      default:
        return a.name === "createpolicy"
          ? { name: "createpolicy", detail: "register empty deny-all policy" }
          : { name: `${a.account}::${a.name}`, detail: "" };
    }
  });
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
