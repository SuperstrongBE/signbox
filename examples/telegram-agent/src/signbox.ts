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

/** Build a 1-action transfer, ask SignBox to sign AND submit it. */
export async function signAndPush(cfg: SignboxConfig, input: TransferInput): Promise<SignboxResult> {
  const tx = {
    actions: [
      {
        account: "eosio.token",
        name: "transfer",
        authorization: [{ actor: cfg.agent, permission: "active" }],
        data: { from: cfg.agent, to: input.to, quantity: input.amount, memo: input.memo ?? "" },
      },
    ],
  };

  const file = join(tmpdir(), `sbx-tx-${randomUUID()}.json`);
  await writeFile(file, JSON.stringify(tx), "utf8");
  const args = ["transaction", "sign", "--agent", cfg.agent, "--transaction", file, "--push"];
  if (cfg.configPath) args.push("--config", cfg.configPath);

  try {
    const { stdout, stderr, code, spawnError } = await run(cfg.bin, args);
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
      return {
        ok: false,
        status: "denied",
        code: String(parsed["code"] ?? "DENY"),
        reason: String(parsed["safeReason"] ?? parsed["code"] ?? "refused by policy"),
        detail: parsed,
      };
    }

    return { ok: false, status: "error", reason: stderr.trim() || `signbox exited with code ${code}`, detail: parsed };
  } finally {
    await unlink(file).catch(() => undefined);
  }
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
