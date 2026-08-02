/**
 * Global wallet session. The NETWORK is chosen at connect time: "Connect
 * wallet" opens a picker (testnet / mainnet) which sets the network and opens
 * the WebAuth session for it. Being connected therefore means "connected to
 * network N as authority A"; the app only ever shows/edits A's agents on N.
 * Switching network = disconnect + reconnect. SignBox never sees a key.
 */

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useNetwork } from "./NetworkContext";
import { NETWORKS, SIGNBOX_CONTRACT, type NetworkName } from "../networks";
import { connectNetwork, restoreNetwork, type Connected } from "../wallet";

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
  /**
   * Install a guard that intercepts `disconnect` (e.g. the editor confirming
   * unsaved changes). The guard receives a `proceed` callback and must call it
   * to actually drop the session. Pass `null` to remove the guard.
   */
  setLeaveGuard: (guard: ((proceed: () => void) => void) | null) => void;
}

const WalletContext = createContext<WalletState | null>(null);

export function WalletProvider({ children }: { children: ReactNode }) {
  const { network, setNetwork } = useNetwork();
  const [session, setSession] = useState<Connected | null>(null);
  const [connecting, setConnecting] = useState<NetworkName | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  // Re-hydrate a persisted session on mount. On mobile the WebAuth app returns
  // via a callback that RELOADS the page, so the connection completed but the
  // fresh JS context lost the in-flight promise; restoring repopulates the UI.
  // Silent (no picker) when there's nothing stored.
  const restored = useRef(false);
  useEffect(() => {
    if (restored.current) return;
    restored.current = true;
    const desc = NETWORKS[network];
    void restoreNetwork(desc.endpoints, desc.chainId, SIGNBOX_CONTRACT, desc.scheme)
      .then((c) => {
        if (c !== null) setSession(c);
      })
      .catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const connect = useCallback(
    async (network: NetworkName) => {
      setNetwork(network); // the rest of the app follows the connected network
      setConnecting(network);
      setError(null);
      try {
        const desc = NETWORKS[network];
        setSession(await connectNetwork(desc.endpoints, desc.chainId, SIGNBOX_CONTRACT, desc.scheme));
        setPickerOpen(false);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setConnecting(null);
      }
    },
    [setNetwork],
  );

  // A view (the editor) can gate disconnect behind its own confirm flow.
  const leaveGuardRef = useRef<((proceed: () => void) => void) | null>(null);
  const setLeaveGuard = useCallback((guard: ((proceed: () => void) => void) | null) => {
    leaveGuardRef.current = guard;
  }, []);
  const disconnect = useCallback(() => {
    const drop = () => setSession(null);
    const guard = leaveGuardRef.current;
    if (guard !== null) guard(drop);
    else drop();
  }, []);
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
      value={{ session, connecting, error, pickerOpen, openPicker, closePicker, connect, disconnect, setLeaveGuard }}
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
