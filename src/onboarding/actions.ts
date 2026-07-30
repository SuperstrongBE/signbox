/**
 * Builds the Antelope actions for agent onboarding (spec §10.2 step 7).
 *
 * Pure functions — no I/O — so the exact action set is unit-tested.
 *
 * Permission model (project decision):
 * - the agent account's `owner` and `active` are satisfied by the authority
 *   via an ACCOUNT permission (authority@active), so the authority controls
 *   the agent without SignBox ever holding the authority's key;
 * - the SignBox key lives on a dedicated permission, child of `active`;
 * - linkauth is OUT of scope here — the developer links the permission to the
 *   actions they want the key to sign. Until then the key is inert on-chain
 *   (a signed transaction is rejected at push), which is the intended
 *   deny-by-default posture.
 *
 * RAM: the superior authority pays (`buyrambytes` payer = authority). The XPR
 * resource model may require an adjustment here — flagged for the onboarding
 * spike; `ramBytes` is configurable and the action is omitted when 0.
 */

export interface Authorization {
  actor: string;
  permission: string;
}

export interface OnboardingAction {
  account: string;
  name: string;
  authorization: Authorization[];
  data: Record<string, unknown>;
}

export interface BuildActionsInput {
  authority: string;
  agent: string;
  permission: string;
  agentPublicKey: string;
  mode: "create" | "existing";
  signboxContract: string;
  emptyPolicyJson: string;
  emptyPolicyHash: string;
  ramBytes?: number;
}

/** An authority structure satisfied solely by `account@permission`. */
function accountAuthority(actor: string, permission = "active") {
  return {
    threshold: 1,
    keys: [],
    accounts: [{ permission: { actor, permission }, weight: 1 }],
    waits: [],
  };
}

/** An authority structure satisfied by a single public key. */
function keyAuthority(key: string) {
  return {
    threshold: 1,
    keys: [{ key, weight: 1 }],
    accounts: [],
    waits: [],
  };
}

export function buildOnboardingActions(input: BuildActionsInput): OnboardingAction[] {
  const actions: OnboardingAction[] = [];
  const byAuthority: Authorization[] = [{ actor: input.authority, permission: "active" }];

  if (input.mode === "create") {
    // Create the agent account with owner/active under the authority's control.
    actions.push({
      account: "eosio",
      name: "newaccount",
      authorization: byAuthority,
      data: {
        creator: input.authority,
        name: input.agent,
        owner: accountAuthority(input.authority),
        active: accountAuthority(input.authority),
      },
    });

    if ((input.ramBytes ?? 0) > 0) {
      actions.push({
        account: "eosio",
        name: "buyrambytes",
        authorization: byAuthority,
        data: { payer: input.authority, receiver: input.agent, bytes: input.ramBytes },
      });
    }
  }

  // TEMPORARILY DISABLED: XPR Network currently blacklists `eosio::updateauth`
  // in a signing request, so this action is commented out. As a result the
  // dedicated agent permission is NOT created during onboarding — the SignBox
  // key must be placed on the agent account by another mechanism for now
  // (e.g. WebAuth), and verifyLanded skips the permission check accordingly.
  //
  // // Create the dedicated agent permission holding the SignBox key, child of
  // // active. Authorized by agent@active (satisfied by the authority's key).
  // actions.push({
  //   account: "eosio",
  //   name: "updateauth",
  //   authorization: [{ actor: input.agent, permission: "active" }],
  //   data: {
  //     account: input.agent,
  //     permission: input.permission,
  //     parent: "active",
  //     auth: keyAuthority(input.agentPublicKey),
  //   },
  // });

  // Register the empty deny-all policy in the SignBox contract. RAM paid by
  // the authority (it signs and is the payer of the row).
  actions.push({
    account: input.signboxContract,
    name: "createpolicy",
    authorization: byAuthority,
    data: {
      agent: input.agent,
      authority: input.authority,
      agentperm: input.permission,
      version: 1,
      policyhash: input.emptyPolicyHash,
      policyjson: input.emptyPolicyJson,
    },
  });

  return actions;
}

export function summarizeActions(actions: OnboardingAction[]): {
  contract: string;
  action: string;
  detail: string;
}[] {
  return actions.map((a) => {
    let detail = "";
    switch (`${a.account}::${a.name}`) {
      case "eosio::newaccount":
        detail = `create account ${String(a.data["name"])} controlled by ${String(a.data["creator"])}`;
        break;
      case "eosio::buyrambytes":
        detail = `${String(a.data["payer"])} buys ${String(a.data["bytes"])} bytes of RAM for ${String(a.data["receiver"])}`;
        break;
      case "eosio::updateauth":
        detail = `add permission "${String(a.data["permission"])}" (SignBox key) to ${String(a.data["account"])}`;
        break;
      default:
        if (a.name === "createpolicy") {
          detail = `register empty deny-all policy for ${String(a.data["agent"])}`;
        } else {
          detail = `${a.account}::${a.name}`;
        }
    }
    return { contract: a.account, action: a.name, detail };
  });
}
