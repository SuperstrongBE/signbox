/**
 * Node help state. A single provider renders the help modal; any node header or
 * palette entry calls `useHelp().open(type)` to show it.
 */

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import type { NodeType } from "./types";
import { NodeHelpModal } from "./NodeHelpModal";

const HelpContext = createContext<{ open: (type: NodeType) => void } | null>(null);

export function HelpProvider({ children }: { children: ReactNode }) {
  const [type, setType] = useState<NodeType | null>(null);
  const open = useCallback((t: NodeType) => setType(t), []);
  const value = useMemo(() => ({ open }), [open]);
  return (
    <HelpContext.Provider value={value}>
      {children}
      {type !== null && <NodeHelpModal type={type} onClose={() => setType(null)} />}
    </HelpContext.Provider>
  );
}

export function useHelp(): { open: (type: NodeType) => void } {
  const ctx = useContext(HelpContext);
  if (ctx === null) throw new Error("useHelp must be used inside <HelpProvider>");
  return ctx;
}
