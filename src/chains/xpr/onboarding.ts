/**
 * XPR implementation of OnboardingBackend (spec §10, path 2 of §5.5).
 *
 * Builds the onboarding actions, encodes them as an ESR the authority scans
 * and signs in its own wallet (SignBox never signs here), and reads/verifies
 * the chain. Chain identity is pinned (INV-009).
 *
 * The RPC-facing methods need a live chain and are exercised end-to-end
 * against testnet, not in unit tests; the pure action/ESR shape is covered by
 * the actions and flow tests.
 */

import { JsonRpc, Numeric } from "@proton/js";
// The package is mis-packaged (type:module + CJS main, no exports map), so the
// bare specifier breaks under Node ESM; import the ESM build directly.
import { SigningRequest } from "@proton/signing-request/lib/proton-signing-request.m.js";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import { pinChainId } from "./adapter.js";
import { buildOnboardingActions, summarizeActions } from "./onboardingActions.js";
import type {
  BuiltRequest,
  OnboardingBackend,
  OnboardingInput,
  VerificationResult,
} from "../../onboarding/flow.js";

export interface XprOnboardingOptions {
  endpoints: string[];
  chainId: string;
  signboxContract: string;
  /**
   * Signing-request scheme. The XPR WebAuth wallet requires `proton`
   * (mainnet) or `proton-dev` (testnet); `esr` is the generic Anchor scheme.
   */
  scheme?: "esr" | "proton" | "proton-dev";
  pollIntervalMs?: number;
  /** Base URL of the companion web app that opens a wallet session and signs. */
  companionBaseUrl?: string;
}

const zlib = {
  deflateRaw: (data: Uint8Array): Uint8Array => deflateRawSync(data),
  inflateRaw: (data: Uint8Array): Uint8Array => inflateRawSync(data),
};

export class XprOnboardingBackend implements OnboardingBackend {
  private readonly opts: Required<XprOnboardingOptions>;

  constructor(options: XprOnboardingOptions) {
    this.opts = {
      scheme: "proton",
      pollIntervalMs: 3000,
      companionBaseUrl: "https://signbox.rockerone.io",
      ...options,
    };
  }

  private rpc(): JsonRpc {
    const rpc = new JsonRpc(this.opts.endpoints);
    pinChainId(rpc, this.opts.chainId);
    return rpc;
  }

  async authorityExists(authority: string): Promise<boolean> {
    return this.accountExists(authority);
  }

  async agentAccountExists(agent: string): Promise<boolean> {
    return this.accountExists(agent);
  }

  private async accountExists(account: string): Promise<boolean> {
    try {
      await this.rpc().get_account(account);
      return true;
    } catch {
      return false;
    }
  }

  async policyRowExists(agent: string): Promise<boolean> {
    const row = await this.readPolicyRow(agent);
    return row !== null;
  }

  private async readPolicyRow(agent: string): Promise<Record<string, unknown> | null> {
    try {
      const res = (await this.rpc().get_table_rows({
        code: this.opts.signboxContract,
        scope: this.opts.signboxContract,
        table: "policies",
        lower_bound: agent,
        upper_bound: agent,
        limit: 1,
        json: true,
      })) as { rows: unknown[] };
      const row = res.rows[0];
      if (row !== undefined && row !== null && (row as Record<string, unknown>)["agent"] === agent) {
        return row as Record<string, unknown>;
      }
      return null;
    } catch {
      return null;
    }
  }

  /** Resolve an account's `active` public key from chain (§10.1). */
  private async resolveActiveKey(account: string): Promise<string> {
    const info = (await this.rpc().get_account(account)) as {
      permissions?: { perm_name?: string; required_auth?: { keys?: { key?: string }[] } }[];
    };
    const active = (info.permissions ?? []).find((p) => p.perm_name === "active");
    const key = active?.required_auth?.keys?.[0]?.key;
    if (key === undefined) {
      throw new Error(`cannot resolve a public key for the authority's active permission`);
    }
    return key;
  }

  async buildRequest(args: {
    input: OnboardingInput;
    agentPublicKey: string;
    emptyPolicyJson: string;
    emptyPolicyHash: string;
  }): Promise<BuiltRequest> {
    // The new agent account's owner is the authority's own public key.
    const authorityPublicKey = await this.resolveActiveKey(args.input.authority);

    const actions = buildOnboardingActions({
      authority: args.input.authority,
      agent: args.input.agent,
      permission: args.input.permission,
      agentPublicKey: args.agentPublicKey,
      authorityPublicKey,
      signboxContract: this.opts.signboxContract,
      emptyPolicyJson: args.emptyPolicyJson,
      emptyPolicyHash: args.emptyPolicyHash,
      ...(args.input.ramBytes !== undefined ? { ramBytes: args.input.ramBytes } : {}),
    });

    const rpc = this.rpc();
    const abiCache = new Map<string, unknown>();
    const abiProvider = {
      getAbi: async (account: { toString(): string }): Promise<unknown> => {
        const name = account.toString();
        const cached = abiCache.get(name);
        if (cached !== undefined) return cached;
        const { abi } = (await rpc.get_abi(name)) as { abi: unknown };
        abiCache.set(name, abi);
        return abi;
      },
    };

    const request = await SigningRequest.create(
      { chainId: this.opts.chainId, actions, broadcast: true },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      { abiProvider: abiProvider as any, zlib, scheme: this.opts.scheme },
    );

    // Companion web link: the full actions travel in the URL hash fragment
    // (client-side only), so the web app signs EXACTLY these actions. Only
    // public data is included; the CLI still verifies the landed result
    // on-chain before activating the key.
    const payload = {
      v: 1,
      kind: "onboard",
      network: args.input.chain.network,
      chainId: this.opts.chainId,
      endpoints: this.opts.endpoints,
      signboxContract: this.opts.signboxContract,
      summary: {
        agent: args.input.agent,
        authority: args.input.authority,
        permission: args.input.permission,
        publicKey: args.agentPublicKey,
      },
      actions,
    };
    const fragment = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    const companionUrl = `${this.opts.companionBaseUrl.replace(/\/$/, "")}/#${fragment}`;

    return { esrUri: request.encode(), summary: summarizeActions(actions), companionUrl };
  }

  async waitForConfirmation(agent: string, deadlineMs: number): Promise<{ txid: string } | null> {
    // The onboarding succeeds when the policy row appears (createpolicy is the
    // last action). Poll until it does or the session window elapses.
    // Note: uses wall-clock; the flow enforces the same deadline for tests.
    for (;;) {
      const row = await this.readPolicyRow(agent);
      if (row !== null) return { txid: String(row["txid"] ?? "confirmed") };
      if (Date.now() >= deadlineMs) return null;
      await delay(this.opts.pollIntervalMs);
    }
  }

  async verifyLanded(args: {
    input: OnboardingInput;
    agentPublicKey: string;
    emptyPolicyHash: string;
  }): Promise<VerificationResult> {
    // The agent account must exist.
    if (!(await this.accountExists(args.input.agent))) {
      return { ok: false, reason: "agent account not found" };
    }

    // The agent's signing permission (active) must carry exactly the agent's
    // public key — proving the onboarding placed the key where the daemon
    // expects to sign.
    let account: { permissions?: unknown[] };
    try {
      account = (await this.rpc().get_account(args.input.agent)) as { permissions?: unknown[] };
    } catch {
      return { ok: false, reason: "cannot read agent account" };
    }
    const perm = (account.permissions ?? []).find(
      (p) => (p as { perm_name?: string }).perm_name === args.input.permission,
    ) as { required_auth?: { keys?: { key?: string }[] } } | undefined;
    if (perm === undefined) {
      return { ok: false, reason: `permission "${args.input.permission}" not found` };
    }
    const keys = perm.required_auth?.keys ?? [];
    if (!keys.some((k) => normalizeKey(k.key) === normalizeKey(args.agentPublicKey))) {
      return { ok: false, reason: "agent permission does not hold the agent key" };
    }

    // The policy row must exist with the expected authority, permission and
    // the empty-policy hash — proving the landed tx matches the request.
    const row = await this.readPolicyRow(args.input.agent);
    if (row === null) return { ok: false, reason: "policy row not found" };
    if (row["authority"] !== args.input.authority) {
      return { ok: false, reason: "policy authority mismatch" };
    }
    if (row["agentperm"] !== args.input.permission) {
      return { ok: false, reason: "policy permission mismatch" };
    }
    if (String(row["policyhash"]).toLowerCase() !== args.emptyPolicyHash) {
      return { ok: false, reason: "policy hash mismatch" };
    }
    return { ok: true };
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Canonicalize a public key so the legacy `EOS…` form and the modern
 * `PUB_K1_…` form of the SAME key compare equal. get_account may return either
 * representation; parsing to (type + raw bytes) makes the comparison
 * format-agnostic.
 */
function normalizeKey(key: string | undefined): string {
  const s = (key ?? "").trim();
  if (s === "") return "";
  try {
    const parsed = Numeric.stringToPublicKey(s);
    return `${parsed.type}:${Buffer.from(parsed.data).toString("hex")}`;
  } catch {
    return s;
  }
}
