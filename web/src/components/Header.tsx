/**
 * App header: brand (→ home), primary nav, and the wallet state. The network is
 * chosen when connecting, so there's no free network toggle here — the
 * connected network is shown in the wallet chip.
 */

import { useNetwork } from "../context/NetworkContext";
import { useWallet } from "../context/WalletContext";
import { Link, useRoute } from "../router";

export function Header() {
  const route = useRoute();
  const { network } = useNetwork();
  const { session, connecting, openPicker, disconnect } = useWallet();
  const agentsActive = route.name === "agents" || route.name === "editor";

  return (
    <header className="topbar">
      <Link to="/" className="brand brandbtn" aria-label="home">
        <span className="brandmark" aria-hidden="true" />
        SignBox <small>agent wallet</small>
      </Link>

      <nav className="topnav">
        <Link to="/getting-started" className={`navlink ${route.name === "getting-started" ? "active" : ""}`}>
          Getting started
        </Link>
        <Link to="/my-agents" className={`navlink ${agentsActive ? "active" : ""}`}>
          My agents
        </Link>
      </nav>

      <div className="topspacer" />

      {session === null ? (
        <button className="ghostbtn connectbtn" onClick={openPicker} disabled={connecting !== null}>
          {connecting !== null ? "Opening wallet…" : "Connect wallet"}
        </button>
      ) : (
        <div className="walletchip">
          <span className="wnet" data-net={network}>{network}</span>
          <span className="mono">{session.actor}</span>
          <button className="wdisc" onClick={disconnect} aria-label="disconnect">Disconnect</button>
        </div>
      )}
    </header>
  );
}
