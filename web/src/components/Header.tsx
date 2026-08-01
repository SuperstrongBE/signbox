/**
 * App header: brand (→ home), wallet connect state, and the GLOBAL network
 * selector. No standalone editor tab — the editor is only reachable by editing
 * an agent you control, once connected.
 */

import { useNetwork } from "../context/NetworkContext";
import { useWallet } from "../context/WalletContext";
import type { NetworkName } from "../networks";

const NETS: NetworkName[] = ["testnet", "mainnet"];

export function Header({ onHome }: { onHome: () => void }) {
  const { network, setNetwork } = useNetwork();
  const { session, connecting, connect, disconnect } = useWallet();

  return (
    <header className="topbar">
      <button className="brand brandbtn" onClick={onHome} aria-label="home">
        <span className="brandmark" aria-hidden="true" />
        SignBox <small>companion</small>
      </button>
      <div className="topspacer" />

      {session === null ? (
        <button className="ghostbtn connectbtn" onClick={() => void connect()} disabled={connecting}>
          {connecting ? "Opening wallet…" : "Connect wallet"}
        </button>
      ) : (
        <div className="walletchip">
          <span className="wdot" aria-hidden="true" />
          <span className="mono">{session.actor}</span>
          <button className="wdisc" onClick={disconnect} aria-label="disconnect">Disconnect</button>
        </div>
      )}

      <div className="netsel">
        <span className="netlbl">Network</span>
        <div className="netseg" role="radiogroup" aria-label="network">
          {NETS.map((n) => (
            <button
              key={n}
              data-net={n}
              className={network === n ? "active" : ""}
              aria-pressed={network === n}
              onClick={() => setNetwork(n)}
            >
              <span className="netdot" aria-hidden="true" />
              {n}
            </button>
          ))}
        </div>
      </div>
    </header>
  );
}
