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

import { JsonRpc } from "@proton/js";
// The package is mis-packaged (type:module + CJS main, no exports map), so the
// bare specifier breaks under Node ESM; import the ESM build directly.
import { SigningRequest } from "@proton/signing-request/lib/proton-signing-request.m.js";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import { pinChainId } from "../chains/xpr/adapter.js";
import { buildOnboardingActions, summarizeActions } from "./actions.js";
import type {
  BuiltRequest,
  OnboardingBackend,
  OnboardingInput,
  VerificationResult,
} from "./flow.js";

export interface XprOnboardingOptions {
  endpoints: string[];
  chainId: string;
  signboxContract: string;
  /** ESR scheme; "esr" is broadly compatible, "proton" targets WebAuth. */
  scheme?: "esr" | "proton";
  pollIntervalMs?: number;
}

const zlib = {
  deflateRaw: (data: Uint8Array): Uint8Array => deflateRawSync(data),
  inflateRaw: (data: Uint8Array): Uint8Array => inflateRawSync(data),
};

export class XprOnboardingBackend implements OnboardingBackend {
  private readonly opts: Required<XprOnboardingOptions>;

  constructor(options: XprOnboardingOptions) {
    this.opts = { scheme: "esr", pollIntervalMs: 3000, ...options };
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

  async buildRequest(args: {
    input: OnboardingInput;
    agentPublicKey: string;
    emptyPolicyJson: string;
    emptyPolicyHash: string;
  }): Promise<BuiltRequest> {
    const actions = buildOnboardingActions({
      authority: args.input.authority,
      agent: args.input.agent,
      permission: args.input.permission,
      agentPublicKey: args.agentPublicKey,
      mode: args.input.mode,
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

    return { esrUri: request.encode(), summary: summarizeActions(actions) };
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

    // The dedicated permission must carry exactly the agent's public key.
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
      return { ok: false, reason: "dedicated permission not found" };
    }
    const keys = perm.required_auth?.keys ?? [];
    if (!keys.some((k) => normalizeKey(k.key) === normalizeKey(args.agentPublicKey))) {
      return { ok: false, reason: "dedicated permission does not hold the agent key" };
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

/** Compare public keys ignoring the PUB_K1_/legacy EOS prefix distinction is
 * out of scope; a strict string compare is used, normalized to trimmed form. */
function normalizeKey(key: string | undefined): string {
  return (key ?? "").trim();
}
