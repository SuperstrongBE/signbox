/**
 * Companion app root.
 *
 * Routing rule: a URL hash carrying an onboarding payload (from
 * `signbox agent create`) renders the onboarding flow — it brings its OWN
 * network. Otherwise the main shell renders behind a wallet connection: the
 * Agents list (only the connected authority's agents) and, reached by editing
 * one of them, the policy editor.
 */

import { Suspense, lazy, useMemo, useState } from "react";
import { loadPayload } from "./link";
import { AgentsView } from "./views/AgentsView";
import { EditorView } from "./views/EditorView";
import { Header } from "./components/Header";
import { NetworkProvider } from "./context/NetworkContext";
import { WalletProvider } from "./context/WalletContext";

// Lazy: the onboarding flow pulls @proton/web-sdk; the main shell only needs it
// once the user connects, so keep it split out of the initial chunk.
const OnboardingView = lazy(() =>
  import("./views/OnboardingView").then((m) => ({ default: m.OnboardingView })),
);

type View = { name: "agents" } | { name: "editor"; agent: string };

export function App() {
  const payload = useMemo(
    () => (window.location.hash.replace(/^#/, "").trim().length > 0 ? loadPayload() : null),
    [],
  );
  const [view, setView] = useState<View>({ name: "agents" });

  if (payload !== null) {
    return (
      <Suspense fallback={null}>
        <OnboardingView payload={payload} />
      </Suspense>
    );
  }

  return (
    <NetworkProvider>
      <WalletProvider>
        <div className="appshell">
          <Header onHome={() => setView({ name: "agents" })} />
          <div className="viewport">
            {view.name === "agents" ? (
              <AgentsView onEdit={(agent) => setView({ name: "editor", agent })} />
            ) : (
              <EditorView key={view.agent} agent={view.agent} onBack={() => setView({ name: "agents" })} />
            )}
          </div>
        </div>
      </WalletProvider>
    </NetworkProvider>
  );
}
