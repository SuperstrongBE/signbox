/**
 * Global wallet session. Connecting proves who the AUTHORITY is — the app then
 * only ever shows and edits the agents that authority controls. A wallet
 * session is chain-specific, so switching network drops it (reconnect required).
 * SignBox never sees a key: the authority signs in its own wallet.
 */

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useNetwork } from "./NetworkContext";
import { SIGNBOX_CONTRACT } from "../networks";
import { connectNetwork, type Connected } from "../wallet";

interface WalletState {
  session: Connected | null;
  connecting: boolean;
  error: string | null;
  connect: () => Promise<void>;
  disconnect: () => void;
}

const WalletContext = createContext<WalletState | null>(null);

export function WalletProvider({ children }: { children: ReactNode }) {
  const { network, endpoints, chainId } = useNetwork();
  const [session, setSession] = useState<Connected | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A session is bound to one chain — drop it whenever the network changes.
  useEffect(() => {
    setSession(null);
    setError(null);
  }, [network]);

  const connect = useCallback(async () => {
    setConnecting(true);
    setError(null);
    try {
      setSession(await connectNetwork(endpoints, chainId, SIGNBOX_CONTRACT));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setConnecting(false);
    }
  }, [endpoints, chainId]);

  const disconnect = useCallback(() => setSession(null), []);

  return (
    <WalletContext.Provider value={{ session, connecting, error, connect, disconnect }}>
      {children}
    </WalletContext.Provider>
  );
}

export function useWallet(): WalletState {
  const ctx = useContext(WalletContext);
  if (ctx === null) throw new Error("useWallet must be used inside <WalletProvider>");
  return ctx;
}
