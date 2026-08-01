/**
 * Landing page: what SignBox is, the model, and the flow. Static content —
 * the only interactive bits are the CTAs into /getting-started and /my-agents.
 */

import { Link } from "../router";

const FLOW: { n: string; title: string; body: string }[] = [
  {
    n: "01",
    title: "Create an agent",
    body: "The CLI provisions the agent its OWN on-chain account and key. The private key is generated and sealed inside the local daemon — it never touches your app or the model.",
  },
  {
    n: "02",
    title: "Sign the setup",
    body: "Scan the QR (or open the link) with your WebAuth wallet and sign the on-chain setup as the authority. You pay for the account; you stay in control.",
  },
  {
    n: "03",
    title: "Author a policy",
    body: "Draw the rules in the node editor — who it may pay, how much, how often, gated on live on-chain state — and push it. The policy lives on-chain, public and auditable.",
  },
  {
    n: "04",
    title: "Let it spend",
    body: "Your agent submits raw transactions to SignBox. SignBox — not the agent — decides, applying the policy, and returns a signature or a refusal.",
  },
];

const PROPS: { k: string; title: string; body: string }[] = [
  { k: "custody", title: "Keys never leave", body: "The signing key is held by the daemon and never enters the agent's context. A fully jailbroken model still cannot read, export, or leak it." },
  { k: "policy", title: "The policy is the ceiling", body: "An on-chain, hashed, reproducible policy is the only thing that decides. Security lives in the rules, not in the agent's good behaviour." },
  { k: "failclosed", title: "Fail-closed", body: "Anything the policy can't confirm — an ambiguous value, an unreachable provider, a rollback — is a refusal. The safe answer is always “no”." },
  { k: "limits", title: "Real limits", body: "Per-transaction caps, rate limits, per-recipient cooldowns, absolute ceilings — enforced across every action, plus a local kill-switch." },
];

export function LandingView() {
  return (
    <div className="page landing">
      <section className="hero">
        <div className="herobadge">Controlled signing for AI agents · XPR Network</div>
        <h1>
          The wallet your <span className="hl">agent can’t drain</span>.
        </h1>
        <p className="lede">
          SignBox is a local controlled-signing daemon. It gives an autonomous agent its own on-chain
          wallet, while a policy <em>you</em> own — living on-chain — decides what it is ever allowed to sign.
          The key never leaves the daemon; the agent only ever gets back a signature or a refusal.
        </p>
        <div className="herocta">
          <Link to="/getting-started" className="btn primary">Get started →</Link>
          <Link to="/my-agents" className="btn ghost">My agents</Link>
        </div>
      </section>

      <section className="band">
        <div className="bandhead">
          <h2>Agents need to transact. You can’t hand an LLM your keys.</h2>
          <p>
            Give a model a private key and one poisoned prompt drains the wallet. SignBox breaks the chain:
            the agent proposes, a policy disposes. It’s a black box — raw JSON goes in, a signed transaction
            or a plain refusal comes out — and the secret stays sealed inside.
          </p>
        </div>
        <div className="blackbox">
          <div className="bbcol">
            <span className="bblabel">agent proposes</span>
            <code>{`{ actions: [ … ] }`}</code>
            <span className="bbnote">raw, unserialized JSON — no packed transactions</span>
          </div>
          <div className="bbarrow" aria-hidden="true">→</div>
          <div className="bbcore">
            <span className="brandmark" aria-hidden="true" />
            <b>SignBox</b>
            <span className="bbnote">holds the key · enforces the on-chain policy</span>
          </div>
          <div className="bbarrow" aria-hidden="true">→</div>
          <div className="bbcol">
            <span className="bblabel">SignBox disposes</span>
            <code className="ok">signature + txid</code>
            <code className="no">or ✕ refusal</code>
          </div>
        </div>
      </section>

      <section className="band">
        <div className="bandhead">
          <h2>How it works</h2>
          <p>Four steps from zero to an agent that spends within rails you can see and change.</p>
        </div>
        <ol className="flow">
          {FLOW.map((s) => (
            <li key={s.n} className="flowstep">
              <span className="flown">{s.n}</span>
              <div>
                <h3>{s.title}</h3>
                <p>{s.body}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section className="band">
        <div className="bandhead">
          <h2>Why it holds</h2>
        </div>
        <div className="propgrid">
          {PROPS.map((p) => (
            <div key={p.k} className="propcard">
              <h3>{p.title}</h3>
              <p>{p.body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="cta">
        <h2>Give your agent a wallet it can’t abuse.</h2>
        <div className="herocta">
          <Link to="/getting-started" className="btn primary">Get started →</Link>
          <a className="btn ghost" href="https://github.com/SuperstrongBE/signbox" target="_blank" rel="noreferrer">Read the code ↗</a>
        </div>
      </section>
    </div>
  );
}
