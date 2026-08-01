/**
 * Global network state (testnet/mainnet), driven by the header selector and
 * persisted in localStorage. Everything network-dependent (agent listing, the
 * compiled policy's chainId) reads from here.
 */

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { NETWORKS, type NetworkDescriptor, type NetworkName } from "../networks";

const STORAGE_KEY = "signbox.network";

interface NetworkState extends NetworkDescriptor {
  setNetwork: (name: NetworkName) => void;
}

const NetworkContext = createContext<NetworkState | null>(null);

function initialNetwork(): NetworkName {
  const stored = localStorage.getItem(STORAGE_KEY);
  return stored === "mainnet" ? "mainnet" : "testnet";
}

export function NetworkProvider({ children }: { children: ReactNode }) {
  const [name, setName] = useState<NetworkName>(initialNetwork);

  const setNetwork = useCallback((next: NetworkName) => {
    localStorage.setItem(STORAGE_KEY, next);
    setName(next);
  }, []);

  const value = useMemo<NetworkState>(() => ({ ...NETWORKS[name], setNetwork }), [name, setNetwork]);
  return <NetworkContext.Provider value={value}>{children}</NetworkContext.Provider>;
}

export function useNetwork(): NetworkState {
  const ctx = useContext(NetworkContext);
  if (ctx === null) throw new Error("useNetwork must be used inside <NetworkProvider>");
  return ctx;
}
