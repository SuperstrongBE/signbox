/**
 * Connect picker: choose the network, which opens the WebAuth session for it.
 * The network is a connect-time decision, not a free header toggle.
 */

import { NETWORKS, type NetworkName } from "../networks";
import { useWallet } from "../context/WalletContext";

const OPTIONS: { net: NetworkName; blurb: string }[] = [
  { net: "testnet", blurb: "XPR testnet — for trying things out" },
  { net: "mainnet", blurb: "XPR mainnet — real funds" },
];

/** Renders the picker only when open — mounted INSIDE the themed appshell. */
export function ConnectPortal() {
  const { pickerOpen, session } = useWallet();
  return pickerOpen && session === null ? <ConnectModal /> : null;
}

function ConnectModal() {
  const { connect, connecting, error, closePicker } = useWallet();
  const busy = connecting !== null;

  return (
    <div className="modalbg" onClick={(e) => { if (e.target === e.currentTarget && !busy) closePicker(); }}>
      <div className="modal connectmodal" role="dialog" aria-modal="true" aria-label="Connect wallet">
        <div className="mh">
          <span>Connect wallet</span>
          <button className="x" aria-label="close" onClick={closePicker} disabled={busy}>×</button>
        </div>
        <div className="mp">
          <div className="mlbl">Choose a network — the wallet opens for it</div>
          <div className="netchoice">
            {OPTIONS.map(({ net, blurb }) => (
              <button
                key={net}
                className="netcard"
                data-net={net}
                onClick={() => void connect(net)}
                disabled={busy}
              >
                <span className="netcarddot" aria-hidden="true" />
                <span className="netcardname">{net}</span>
                <span className="netcardblurb">{connecting === net ? "Opening wallet…" : blurb}</span>
                <span className="netcardid mono">{NETWORKS[net].chainId.slice(0, 10)}…</span>
              </button>
            ))}
          </div>
          {error !== null && <div className="mwarn">⚠ {error}</div>}
          <p className="mnote">SignBox never sees a key — you sign in your own WebAuth wallet.</p>
        </div>
      </div>
    </div>
  );
}
