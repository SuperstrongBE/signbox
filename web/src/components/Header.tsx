/**
 * App header: brand, view tabs, and the GLOBAL network selector. The selector
 * switches testnet/mainnet at runtime for the whole app (one build, one image).
 */

import { useNetwork } from "../context/NetworkContext";
import type { NetworkName } from "../networks";

export type ViewName = "agents" | "editor";

const NETS: NetworkName[] = ["testnet", "mainnet"];

export function Header({ view, onView }: { view: ViewName; onView: (v: ViewName) => void }) {
  const { network, setNetwork } = useNetwork();
  return (
    <header className="topbar">
      <div className="brand">
        <span className="brandmark" aria-hidden="true" />
        SignBox <small>companion</small>
      </div>
      <nav className="tabs" aria-label="views">
        <button className={`tab ${view === "agents" ? "active" : ""}`} onClick={() => onView("agents")}>
          Agents
        </button>
        <button className={`tab ${view === "editor" ? "active" : ""}`} onClick={() => onView("editor")}>
          Policy editor
        </button>
      </nav>
      <div className="topspacer" />
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
