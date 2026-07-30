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
  const { session, link } = await ConnectWallet({
    linkOptions: {
      endpoints: payload.endpoints,
      chainId: payload.chainId,
      restoreSession: false,
    },
    transportOptions: {
      requestAccount: payload.signboxContract,
      requestStatus: true,
    },
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
