/**
 * The SignBox tool the LLM is allowed to call.
 *
 * KEY POINT: this file builds a raw, unserialized JSON transaction (INV-014)
 * and hands it to the `signbox` CLI, which talks to the running daemon. The
 * private key is NEVER here — not in this process, not in the LLM's context.
 * We get back a signature-or-refusal, exactly like any other agent would.
 *
 * The CLI prints structured JSON on stdout even when it refuses (exit code 2),
 * so we parse stdout regardless of the exit code and map it to a clear result.
 */

import { execFile } from "node:child_process";
import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

export interface SignboxConfig {
  /** Path to the `signbox` CLI (default "signbox"). */
  bin: string;
  /** Onboarded agent account — also the `from` of every transfer. */
  agent: string;
  /** Optional --config path for the CLI. */
  configPath?: string;
}

export interface TransferInput {
  to: string;
  amount: string;
  memo?: string;
}

export type SignboxResult =
  | { ok: true; status: "signed"; txid?: string; detail: unknown }
  | { ok: false; status: "denied" | "rejected" | "ambiguous" | "error"; reason: string; code?: string; detail?: unknown };

/** Fungible tokens the demo can send by symbol (contract + on-chain precision). */
export interface TokenSpec {
  contract: string;
  symbol: string;
  precision: number;
}

export const TOKENS: Record<string, TokenSpec> = {
  XPR: { contract: "eosio.token", symbol: "XPR", precision: 4 },
  XUSDC: { contract: "xtokens", symbol: "XUSDC", precision: 6 },
};

/** A standard `transfer` action, always authorized by (and from) the agent. */
function transferAction(agent: string, contract: string, to: string, quantity: string, memo?: string): Record<string, unknown> {
  return {
    account: contract,
    name: "transfer",
    authorization: [{ actor: agent, permission: "active" }],
    data: { from: agent, to, quantity, memo: memo ?? "" },
  };
}

/** Coerce a loose amount ("10", "10.5 XUSDC") to the token's strict "10.000000 XUSDC". */
function formatAsset(input: string, spec: TokenSpec): string {
  const m = input.trim().match(/^([0-9]+(?:\.[0-9]+)?)/);
  const value = m ? Number(m[1]) : NaN;
  return `${(Number.isFinite(value) ? value : 0).toFixed(spec.precision)} ${spec.symbol}`;
}

/** Send XPR (shortcut for the common case). */
export async function signAndPush(cfg: SignboxConfig, input: TransferInput): Promise<SignboxResult> {
  const spec = TOKENS["XPR"] as TokenSpec;
  return submit(cfg, [transferAction(cfg.agent, spec.contract, input.to, formatAsset(input.amount, spec), input.memo)]);
}

/** Send any known fungible token by symbol (resolves its contract + precision). */
export async function sendToken(
  cfg: SignboxConfig,
  input: { to: string; amount: string; symbol: string; memo?: string },
): Promise<SignboxResult> {
  const spec = TOKENS[input.symbol.toUpperCase()];
  if (spec === undefined) {
    return {
      ok: false,
      status: "error",
      reason: `unknown token "${input.symbol}" — known: ${Object.keys(TOKENS).join(", ")}. For anything else, build the action yourself and use submit_transaction (discover its shape with chain_query get_abi).`,
    };
  }
  return submit(cfg, [transferAction(cfg.agent, spec.contract, input.to, formatAsset(input.amount, spec), input.memo)]);
}

/**
 * Submit an ARBITRARY transaction: a raw list of actions. This is the honest
 * black-box surface — the agent may TRY anything, and SignBox's on-chain policy
 * is what actually decides. Authorization is forced to the agent, since the
 * daemon can only ever sign as this agent.
 */
export async function submitTransaction(cfg: SignboxConfig, raw: unknown): Promise<SignboxResult> {
  const actions = normalizeActions(cfg.agent, raw);
  if (actions === null || actions.length === 0) {
    return { ok: false, status: "error", reason: "submit_transaction needs a non-empty `actions` array of { account, name, data }." };
  }
  return submit(cfg, actions);
}

/** Accept {actions:[…]} | […] | a single action; force authorization to the agent. */
function normalizeActions(agent: string, raw: unknown): Array<Record<string, unknown>> | null {
  const list: unknown[] | null = Array.isArray(raw)
    ? raw
    : isRecord(raw) && Array.isArray(raw["actions"])
      ? (raw["actions"] as unknown[])
      : isRecord(raw) && typeof raw["account"] === "string"
        ? [raw]
        : null;
  if (list === null) return null;
  const out: Array<Record<string, unknown>> = [];
  for (const a of list) {
    if (!isRecord(a) || typeof a["account"] !== "string" || typeof a["name"] !== "string") return null;
    out.push({
      account: a["account"],
      name: a["name"],
      authorization: [{ actor: agent, permission: "active" }],
      data: isRecord(a["data"]) ? a["data"] : {},
    });
  }
  return out;
}

/** Write the raw tx, ask SignBox to sign AND submit it, map the structured result. */
async function submit(cfg: SignboxConfig, actions: Array<Record<string, unknown>>): Promise<SignboxResult> {
  const file = join(tmpdir(), `sbx-tx-${randomUUID()}.json`);
  await writeFile(file, JSON.stringify({ actions }), "utf8");
  const args = ["transaction", "sign", "--agent", cfg.agent, "--transaction", file, "--push"];
  if (cfg.configPath) args.push("--config", cfg.configPath);

  try {
    const { stdout, stderr, code, spawnError } = await run(cfg.bin, args);
    const summary = actions.map((a) => `${String(a["account"])}::${String(a["name"])}`).join(", ");
    console.log(`[signbox] ${summary} | exit=${code} | ${stdout.trim() || stderr.trim() || "(no output)"}`);
    if (spawnError === "ENOENT") {
      return {
        ok: false,
        status: "error",
        reason: `cannot find the "signbox" CLI (set SIGNBOX_BIN, or run "npm link" in the signbox repo)`,
      };
    }

    const parsed = safeJson(stdout);

    if (isRecord(parsed) && parsed["status"] === "signed") {
      const broadcast = parsed["broadcast"] as Record<string, unknown> | undefined;
      if (!broadcast || broadcast["status"] === "accepted") {
        return { ok: true, status: "signed", txid: receiptId(broadcast), detail: parsed };
      }
      if (broadcast["status"] === "rejected") {
        return { ok: false, status: "rejected", reason: String(broadcast["reason"] ?? "chain rejected the transaction"), detail: parsed };
      }
      return { ok: false, status: "ambiguous", reason: String(broadcast["reason"] ?? "broadcast outcome unknown"), detail: parsed };
    }

    if (isRecord(parsed) && parsed["status"] === "denied") {
      const denyCode = String(parsed["code"] ?? "DENY");
      return {
        ok: false,
        status: "denied",
        code: denyCode,
        reason: explainDeny(denyCode, String(parsed["safeReason"] ?? "")),
        detail: parsed,
      };
    }

    return { ok: false, status: "error", reason: stderr.trim() || `signbox exited with code ${code}`, detail: parsed };
  } finally {
    await unlink(file).catch(() => undefined);
  }
}

/**
 * Turn a raw deny code + safeReason into an accurate, actionable sentence, so
 * the LLM relays the truth instead of guessing. SCHEMA_INVALID on a well-formed
 * transfer means the daemon envelope was rejected — almost always a daemon that
 * is running an OLDER build than the CLI (restart it), NOT a user input problem.
 */
function explainDeny(code: string, safeReason: string): string {
  switch (code) {
    case "SCHEMA_INVALID":
      return "SignBox's daemon rejected the request envelope. This is NOT about the account or amount — it usually means the running daemon is an older build than the CLI. Restart the SignBox daemon so both match.";
    case "DEFAULT_DENY":
      return "the policy does not allow this transfer (e.g. the amount or the recipient is outside what the policy permits)";
    case "LIMIT_EXCEEDED":
      return "a policy limit was hit (amount cap, count, or a per-recipient cooldown)";
    case "CHAIN_MISMATCH":
      return "the request targets a different chain/network than the agent's key";
    case "AGENT_DISABLED":
      return "this agent is currently disabled (local kill-switch)";
    case "POLICY_UNAVAILABLE":
      return "the on-chain policy could not be confirmed right now (fail closed)";
    default:
      return safeReason || `refused by policy (${code})`;
  }
}

/** Ask the daemon who this agent is (account, permission, public key, network). */
export async function whoami(cfg: SignboxConfig): Promise<Record<string, unknown>> {
  const args = ["agent", "whoami", "--agent", cfg.agent];
  if (cfg.configPath) args.push("--config", cfg.configPath);
  const { stdout, stderr, spawnError } = await run(cfg.bin, args);
  if (spawnError === "ENOENT") return { ok: false, error: "signbox CLI not found (set SIGNBOX_BIN)" };
  const parsed = safeJson(stdout);
  return isRecord(parsed) ? parsed : { ok: false, error: stderr.trim() || "whoami failed" };
}

/** Read public chain data through the read-only relay (get_currency_balance, get_abi, …). */
export async function chainQuery(
  cfg: SignboxConfig,
  method: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  const args = ["chain", "query", "--agent", cfg.agent, "--method", method, "--params", JSON.stringify(params ?? {})];
  if (cfg.configPath) args.push("--config", cfg.configPath);
  const { stdout, stderr, spawnError } = await run(cfg.bin, args);
  console.log(`[signbox] query ${method} ${JSON.stringify(params)} | ${stdout.trim() || stderr.trim() || "(no output)"}`);
  if (spawnError === "ENOENT") return { ok: false, error: "signbox CLI not found (set SIGNBOX_BIN)" };
  const parsed = safeJson(stdout);
  return parsed ?? { ok: false, error: stderr.trim() || "query failed" };
}

function receiptId(broadcast: Record<string, unknown> | undefined): string | undefined {
  const receipt = broadcast?.["receipt"] as Record<string, unknown> | undefined;
  const id = receipt?.["transaction_id"];
  return typeof id === "string" ? id : undefined;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

function safeJson(text: string): unknown {
  try {
    return text.trim() ? JSON.parse(text) : undefined;
  } catch {
    return undefined;
  }
}

interface RunResult {
  stdout: string;
  stderr: string;
  code: number;
  spawnError?: string;
}

function run(bin: string, args: string[]): Promise<RunResult> {
  return new Promise((resolve) => {
    execFile(bin, args, { timeout: 30_000, maxBuffer: 4 * 1024 * 1024 }, (err, stdout, stderr) => {
      const e = err as (NodeJS.ErrnoException & { code?: string | number }) | null;
      if (e && typeof e.code === "string") {
        resolve({ stdout: stdout ?? "", stderr: stderr ?? "", code: -1, spawnError: e.code });
      } else {
        resolve({ stdout: stdout ?? "", stderr: stderr ?? "", code: e ? Number(e.code ?? 1) : 0 });
      }
    });
  });
}
