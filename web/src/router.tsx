/**
 * Tiny path-based router (no dependency). Onboarding still travels in the URL
 * hash and is handled in App before routing, so paths here govern the site:
 *   /                     → landing
 *   /getting-started      → guide
 *   /my-agents            → the connected authority's agents
 *   /my-agents/<agent>    → that agent's policy editor
 */

import { useEffect, useState, type AnchorHTMLAttributes } from "react";

export type Route =
  | { name: "home" }
  | { name: "getting-started" }
  | { name: "agents" }
  | { name: "editor"; agent: string };

const AGENT_RE = /^[a-z1-5.]{1,12}$/;

export function parseRoute(pathname: string): Route {
  const p = pathname.replace(/\/+$/, "") || "/";
  if (p === "/") return { name: "home" };
  if (p === "/getting-started") return { name: "getting-started" };
  if (p === "/my-agents") return { name: "agents" };
  const m = /^\/my-agents\/([^/]+)$/.exec(p);
  if (m !== null && m[1] !== undefined && AGENT_RE.test(m[1])) return { name: "editor", agent: m[1] };
  return { name: "home" };
}

export function routeToPath(route: Route): string {
  switch (route.name) {
    case "home":
      return "/";
    case "getting-started":
      return "/getting-started";
    case "agents":
      return "/my-agents";
    case "editor":
      return `/my-agents/${route.agent}`;
  }
}

const listeners = new Set<() => void>();

export function navigate(path: string): void {
  if (path !== window.location.pathname) window.history.pushState({}, "", path);
  listeners.forEach((l) => l());
  window.scrollTo(0, 0);
}

export function useRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.pathname));
  useEffect(() => {
    const update = () => setRoute(parseRoute(window.location.pathname));
    listeners.add(update);
    window.addEventListener("popstate", update);
    return () => {
      listeners.delete(update);
      window.removeEventListener("popstate", update);
    };
  }, []);
  return route;
}

/** An <a> that routes client-side (falls back to a real navigation on modified clicks). */
export function Link({
  to,
  children,
  ...rest
}: { to: string } & AnchorHTMLAttributes<HTMLAnchorElement>) {
  return (
    <a
      href={to}
      onClick={(e) => {
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        e.preventDefault();
        navigate(to);
      }}
      {...rest}
    >
      {children}
    </a>
  );
}
