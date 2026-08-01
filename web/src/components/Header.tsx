/**
 * App header: brand (→ home) and the wallet state. The network is chosen when
 * connecting, so there's no free network toggle here — the connected network
 * is shown in the wallet chip.
 */

import { useNetwork } from "../context/NetworkContext";
import { useWallet } from "../context/WalletContext";

export function Header({ onHome }: { onHome: () => void }) {
  const { network } = useNetwork();
  const { session, connecting, openPicker, disconnect } = useWallet();

  return (
    <header className="topbar">
      <button className="brand brandbtn" onClick={onHome} aria-label="home">
        <span className="brandmark" aria-hidden="true" />
        SignBox <small>companion</small>
      </button>
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
