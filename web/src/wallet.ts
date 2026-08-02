/**
 * Thin wrapper over @proton/web-sdk. The web app is a dApp: it opens a wallet
 * SESSION (login), which is what the Proton wallet requires before signing —
 * exactly the piece a headless CLI cannot do. SignBox never sees any key here;
 * the authority signs in their own wallet.
 *
 * Mobile note: the WebAuth app returns to the browser via a callback URL, which
 * RELOADS the page — the in-flight ConnectWallet promise is lost, but the SDK
 * has persisted the session. `restoreNetwork` re-hydrates it on mount so the UI
 * reflects the connection after the round-trip.
 */

import ConnectWallet from "@proton/web-sdk";
import type { OnboardAction, OnboardPayload } from "./link";

export interface Connected {
  actor: string;
  permission: string;
  transact: (actions: OnboardAction[]) => Promise<{ txid: string }>;
}

export async function connect(payload: OnboardPayload): Promise<Connected> {
  // Onboarding brings its own network; pick the wallet scheme to match.
  const scheme = payload.network === "mainnet" ? "proton" : "proton-dev";
  const c = await openSession(payload.endpoints, payload.chainId, payload.signboxContract, scheme, false);
  if (c === null) throw new Error("wallet connection was cancelled");
  return c;
}

/** Open a wallet session for the selected network (explicit connect). */
export async function connectNetwork(
  endpoints: string[],
  chainId: string,
  requestAccount: string,
  scheme: "proton" | "proton-dev",
): Promise<Connected> {
  const c = await openSession(endpoints, chainId, requestAccount, scheme, false);
  if (c === null) throw new Error("wallet connection was cancelled");
  return c;
}

/**
 * Silently restore a persisted session (no wallet UI). Returns null when there
 * is nothing to restore. Used on mount so a mobile round-trip that reloaded the
 * page still shows the connection.
 */
export async function restoreNetwork(
  endpoints: string[],
  chainId: string,
  requestAccount: string,
  scheme: "proton" | "proton-dev",
): Promise<Connected | null> {
  return openSession(endpoints, chainId, requestAccount, scheme, true);
}

async function openSession(
  endpoints: string[],
  chainId: string,
  requestAccount: string,
  scheme: "proton" | "proton-dev",
  restore: boolean,
): Promise<Connected | null> {
  // `scheme` drives the deep link that opens the WebAuth app on mobile; it must
  // match the network. restoreSession:true is a silent re-hydrate — the SDK
  // returns no session (never a picker) when there's nothing stored.
  let ret: Awaited<ReturnType<typeof ConnectWallet>>;
  try {
    ret = await ConnectWallet({
      linkOptions: { endpoints, chainId, scheme, restoreSession: restore },
      transportOptions: { requestAccount, requestStatus: true },
    });
  } catch (error) {
    if (restore) return null;
    throw error;
  }

  const { session, link } = ret;
  if (session === undefined) {
    if (restore) return null;
    throw new Error("wallet connection was cancelled");
  }

  return {
    actor: session.auth.actor.toString(),
    permission: session.auth.permission.toString(),
    transact: async (actions: OnboardAction[]) => {
      const result = (await session.transact(
        { actions },
        { broadcast: true },
      )) as { processed?: { id?: string }; transaction_id?: string };
      const txid = result.processed?.id ?? result.transaction_id ?? "confirmed";
      // Keep the link reference alive for the session lifetime.
      void link;
      return { txid };
    },
  };
}
