/**
 * Getting started: the end-to-end path, CLI-first, ending in the web editor.
 * Commands mirror the real CLI (agent create / daemon start / transaction).
 */

import type { ReactNode } from "react";
import { Link } from "../router";

function Step({ n, title, children }: { n: string; title: string; children: ReactNode }) {
  return (
    <li className="gsstep">
      <span className="flown">{n}</span>
      <div className="gsbody">
        <h3>{title}</h3>
        {children}
      </div>
    </li>
  );
}

function Cmd({ children }: { children: ReactNode }) {
  return <pre className="gscmd mono">{children}</pre>;
}

export function GettingStartedView() {
  return (
    <div className="page gs">
      <header className="gshead">
        <div className="herobadge">Getting started</div>
        <h1>From zero to a policed agent wallet</h1>
        <p className="lede">
          SignBox runs on your machine: a local daemon custodies the agent’s key and enforces its on-chain
          policy. You drive setup from the CLI, then author the policy here in the browser.
        </p>
      </header>

      <ol className="gssteps">
        <Step n="01" title="Install the CLI">
          <p>Clone the repo, build, and link the <code>signbox</code> binary onto your PATH.</p>
          <Cmd>{`git clone https://github.com/SuperstrongBE/signbox
cd signbox && npm install && npm run build && npm link`}</Cmd>
        </Step>

        <Step n="02" title="Create the agent">
          <p>
            This generates the agent’s key <b>inside the daemon</b> and prints a link + QR. Scan it with your
            WebAuth wallet (or open the link), then sign the on-chain setup as the authority.
          </p>
          <Cmd>{`signbox agent create \\
  --agent myagent \\
  --authority youraccount \\
  --network testnet`}</Cmd>
          <p className="gsnote">The private key never leaves the daemon — not this process, not the model.</p>
        </Step>

        <Step n="03" title="Start the daemon">
          <p>The daemon is what actually signs, gated by the on-chain policy. Keep it running.</p>
          <Cmd>{`signbox daemon start`}</Cmd>
        </Step>

        <Step n="04" title="Author & push a policy">
          <p>
            Open <Link to="/my-agents">My agents</Link>, connect the authority’s wallet, and edit{" "}
            <code>myagent</code>. Draw the rules — recipients, caps, cooldowns, on-chain lookups — and{" "}
            <b>Commit</b> to push <code>setpolicy</code> from your own wallet. Test any transaction against
            it before you push.
          </p>
          <Cmd>{`# dry-run a transaction against the on-chain policy
signbox transaction explain --agent myagent --transaction tx.json`}</Cmd>
        </Step>

        <Step n="05" title="Let your agent spend">
          <p>
            Point your app at the <code>signbox</code> CLI: it submits a raw, unserialized transaction and
            gets back a signature or a refusal. See the Telegram agent in{" "}
            <code>examples/telegram-agent</code> for a full jailbreak-resistant demo.
          </p>
          <Cmd>{`signbox transaction sign --agent myagent --transaction tx.json --push`}</Cmd>
        </Step>
      </ol>

      <section className="cta">
        <h2>Ready?</h2>
        <div className="herocta">
          <Link to="/my-agents" className="btn primary">Open the editor →</Link>
          <a className="btn ghost" href="https://github.com/SuperstrongBE/signbox" target="_blank" rel="noreferrer">GitHub ↗</a>
        </div>
      </section>
    </div>
  );
}
