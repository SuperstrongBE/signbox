/**
 * Companion app root.
 *
 * Routing rule: a URL hash carrying an onboarding payload (from
 * `signbox agent create`) renders the onboarding flow — it brings its OWN
 * network. Otherwise the main shell renders: header with the global
 * testnet/mainnet selector + the Agents and Policy editor views.
 */

import { Suspense, lazy, useMemo, useState } from "react";
import { loadPayload } from "./link";
import { AgentsView } from "./views/AgentsView";
import { EditorView } from "./views/EditorView";
import { Header, type ViewName } from "./components/Header";
import { NetworkProvider } from "./context/NetworkContext";

// Lazy: the onboarding flow pulls @proton/web-sdk (~most of the bundle); the
// main shell never needs it.
const OnboardingView = lazy(() =>
  import("./views/OnboardingView").then((m) => ({ default: m.OnboardingView })),
);

export function App() {
  // Decide once at mount: an onboarding link owns the page for its whole flow.
  const payload = useMemo(
    () => (window.location.hash.replace(/^#/, "").trim().length > 0 ? loadPayload() : null),
    [],
  );
  const [view, setView] = useState<ViewName>("agents");
  // Agent whose on-chain policy the editor loads; null = blank/demo editing.
  const [editAgent, setEditAgent] = useState<string | null>(null);

  if (payload !== null) {
    return (
      <Suspense fallback={null}>
        <OnboardingView payload={payload} />
      </Suspense>
    );
  }

  return (
    <NetworkProvider>
      <div className="appshell">
        <Header view={view} onView={setView} />
        <div className="viewport">
          {view === "agents" ? (
            <AgentsView
              onEdit={(agent) => {
                setEditAgent(agent);
                setView("editor");
              }}
            />
          ) : (
            // Key by agent: picking another agent reloads its policy fresh.
            <EditorView key={editAgent ?? "blank"} agent={editAgent} />
          )}
        </div>
      </div>
    </NetworkProvider>
  );
}
