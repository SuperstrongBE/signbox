/**
 * Global wallet session. The NETWORK is chosen at connect time: "Connect
 * wallet" opens a picker (testnet / mainnet) which sets the network and opens
 * the WebAuth session for it. Being connected therefore means "connected to
 * network N as authority A"; the app only ever shows/edits A's agents on N.
 * Switching network = disconnect + reconnect. SignBox never sees a key.
 */

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useNetwork } from "./NetworkContext";
import { NETWORKS, SIGNBOX_CONTRACT, type NetworkName } from "../networks";
import { connectNetwork, type Connected } from "../wallet";

interface WalletState {
  session: Connected | null;
  /** The network currently being connected, or null. */
  connecting: NetworkName | null;
  error: string | null;
  pickerOpen: boolean;
  openPicker: () => void;
  closePicker: () => void;
  connect: (network: NetworkName) => Promise<void>;
  disconnect: () => void;
}

const WalletContext = createContext<WalletState | null>(null);

export function WalletProvider({ children }: { children: ReactNode }) {
  const { setNetwork } = useNetwork();
  const [session, setSession] = useState<Connected | null>(null);
  const [connecting, setConnecting] = useState<NetworkName | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  const connect = useCallback(
    async (network: NetworkName) => {
      setNetwork(network); // the rest of the app follows the connected network
      setConnecting(network);
      setError(null);
      try {
        const desc = NETWORKS[network];
        setSession(await connectNetwork(desc.endpoints, desc.chainId, SIGNBOX_CONTRACT));
        setPickerOpen(false);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setConnecting(null);
      }
    },
    [setNetwork],
  );

  const disconnect = useCallback(() => setSession(null), []);
  const openPicker = useCallback(() => {
    setError(null);
    setPickerOpen(true);
  }, []);
  const closePicker = useCallback(() => setPickerOpen(false), []);

  // Close the picker once a session lands.
  useEffect(() => {
    if (session !== null) setPickerOpen(false);
  }, [session]);

  return (
    <WalletContext.Provider
      value={{ session, connecting, error, pickerOpen, openPicker, closePicker, connect, disconnect }}
    >
      {children}
    </WalletContext.Provider>
  );
}

export function useWallet(): WalletState {
  const ctx = useContext(WalletContext);
  if (ctx === null) throw new Error("useWallet must be used inside <WalletProvider>");
  return ctx;
}
