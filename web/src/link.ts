/**
 * The onboarding payload the CLI puts in the URL hash fragment.
 *
 * It carries the FULL actions the CLI built, so the web app signs EXACTLY
 * what the CLI intended — no action-building logic is duplicated here. The
 * fragment stays client-side (never sent to a server). The payload is not a
 * secret: it contains only public data (account names, the agent's PUBLIC
 * key, an empty deny-all policy). The trust anchor remains the CLI's on-chain
 * verification before it activates the agent key.
 */

export interface OnboardAction {
  account: string;
  name: string;
  authorization: { actor: string; permission: string }[];
  data: Record<string, unknown>;
}

export interface OnboardPayload {
  v: 1;
  kind: "onboard";
  network: string;
  chainId: string;
  endpoints: string[];
  signboxContract: string;
  summary: {
    agent: string;
    authority: string;
    permission: string;
    publicKey: string;
    mode: string;
  };
  actions: OnboardAction[];
}

function base64UrlToString(b64url: string): string {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

const STORAGE_KEY = "signbox.onboard.pending";

/** Decode the payload from the URL hash, falling back to localStorage. */
export function loadPayload(): OnboardPayload | null {
  const hash = window.location.hash.replace(/^#/, "").trim();
  if (hash.length > 0) {
    try {
      const payload = JSON.parse(base64UrlToString(hash)) as OnboardPayload;
      if (payload.v === 1 && payload.kind === "onboard" && Array.isArray(payload.actions)) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
        return payload;
      }
    } catch {
      /* fall through to storage */
    }
  }
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored !== null) {
    try {
      return JSON.parse(stored) as OnboardPayload;
    } catch {
      return null;
    }
  }
  return null;
}

export function clearPayload(): void {
  localStorage.removeItem(STORAGE_KEY);
}
