/**
 * Companion app root.
 *
 * A URL hash carrying an onboarding payload (from `signbox agent create`)
 * renders the onboarding flow — it brings its OWN network. Otherwise the site
 * routes by path: landing, getting-started, the agents list (behind a wallet),
 * and the policy editor.
 */

import { Suspense, lazy, useMemo } from "react";
import { loadPayload } from "./link";
import { useRoute, navigate } from "./router";
import { AgentsView } from "./views/AgentsView";
import { EditorView } from "./views/EditorView";
import { LandingView } from "./views/LandingView";
import { GettingStartedView } from "./views/GettingStartedView";
import { Header } from "./components/Header";
import { Footer } from "./components/Footer";
import { ConnectPortal } from "./components/ConnectModal";
import { NetworkProvider } from "./context/NetworkContext";
import { WalletProvider } from "./context/WalletContext";

// Lazy: the onboarding flow pulls @proton/web-sdk; keep it off the site chunk.
const OnboardingView = lazy(() =>
  import("./views/OnboardingView").then((m) => ({ default: m.OnboardingView })),
);

function Shell() {
  const route = useRoute();
  const isTool = route.name === "editor";
  return (
    <div className={`appshell ${isTool ? "tool" : "site"}`}>
      <Header />
      <ConnectPortal />
      <main className="appmain">
        {route.name === "home" && <LandingView />}
        {route.name === "getting-started" && <GettingStartedView />}
        {route.name === "agents" && <AgentsView onEdit={(agent) => navigate(`/my-agents/${agent}`)} />}
        {route.name === "editor" && (
          <EditorView key={route.agent} agent={route.agent} onBack={() => navigate("/my-agents")} />
        )}
      </main>
      {!isTool && <Footer />}
    </div>
  );
}

export function App() {
  const payload = useMemo(
    () => (window.location.hash.replace(/^#/, "").trim().length > 0 ? loadPayload() : null),
    [],
  );

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
        <Shell />
      </WalletProvider>
    </NetworkProvider>
  );
}
