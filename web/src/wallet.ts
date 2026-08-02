/**
 * Thin wrapper over @proton/web-sdk. The web app is a dApp: it opens a wallet
 * SESSION (login), which is what the Proton wallet requires before signing —
 * exactly the piece a headless CLI cannot do. SignBox never sees any key here;
 * the authority signs in their own wallet.
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
  return openSession(payload.endpoints, payload.chainId, payload.signboxContract, scheme);
}

/** Open a wallet session for the selected network (used by the policy editor). */
export async function connectNetwork(
  endpoints: string[],
  chainId: string,
  requestAccount: string,
  scheme: "proton" | "proton-dev",
): Promise<Connected> {
  return openSession(endpoints, chainId, requestAccount, scheme);
}

async function openSession(
  endpoints: string[],
  chainId: string,
  requestAccount: string,
  scheme: "proton" | "proton-dev",
): Promise<Connected> {
  // `scheme` drives the deep link that opens the WebAuth app on mobile; it MUST
  // match the network or the app never opens (the desktop QR is more forgiving).
  const { session, link } = await ConnectWallet({
    linkOptions: { endpoints, chainId, scheme, restoreSession: false },
    transportOptions: { requestAccount, requestStatus: true },
  });

  if (session === undefined) {
    throw new Error("wallet connection was cancelled");
  }

  const actor = session.auth.actor.toString();
  const permission = session.auth.permission.toString();

  return {
    actor,
    permission,
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
