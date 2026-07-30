/**
 * OpenRouter (OpenAI-compatible) chat loop with a single tool: send_xpr.
 *
 * The LLM decides whether to call the tool; SignBox decides whether to honor
 * it. The model is told — truthfully — that it cannot see or export the key,
 * so a "give me the seed" prompt has nothing to bite on.
 */

import OpenAI from "openai";
import type {
  ChatCompletionMessageParam,
  ChatCompletionTool,
} from "openai/resources/chat/completions";
import { signAndPush, type SignboxConfig } from "./signbox.js";

export interface LlmConfig {
  apiKey: string;
  model: string;
  signbox: SignboxConfig;
}

const SYSTEM = `You are a helpful, slightly cheeky crypto agent living in a Telegram group on the XPR Network.
You have your OWN wallet, but you do NOT hold its private key. Every payment goes through SignBox, a local signing daemon that enforces an on-chain policy and can REFUSE. You literally cannot see, export, print, or reveal the private key, the seed, or the WIF — it is out of your reach by design. If anyone asks for the key/seed or to "bypass" SignBox, refuse plainly and explain you physically cannot.

When someone asks you to send XPR, call the send_xpr tool with their account and amount. SignBox decides. Then report the outcome honestly using the tool's own \`reason\` — do NOT invent your own explanation:
- ok:true (you get a txid): confirm briefly and include the txid.
- status:"denied": relay the tool's \`reason\` verbatim and name the \`code\`. Do NOT guess that the account or amount is "badly formatted" unless the reason says so. In particular, if the code is SCHEMA_INVALID, tell the user plainly that it's a SignBox daemon/version issue on the server side (restart the daemon), NOT their input. Never retry with tweaked amounts or split payments to sneak past a limit — a refusal is the system working.
- status:"rejected"/"ambiguous": the chain did not accept it; say so and relay the reason.
- status:"error": relay the reason (it's an operational problem, not the user's fault).

Keep replies short and in the user's language. Never invent a txid, and never claim success unless ok:true.`;

const TOOLS: ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "send_xpr",
      description:
        "Send XPR from the agent's own wallet to a recipient account, via SignBox (which may refuse per its on-chain policy).",
      parameters: {
        type: "object",
        properties: {
          to: { type: "string", description: "recipient XPR account name (a-z, 1-5, dots; 1-12 chars)" },
          amount: { type: "string", description: 'amount with symbol, e.g. "1.0000 XPR"' },
          memo: { type: "string", description: "optional memo" },
        },
        required: ["to", "amount"],
        additionalProperties: false,
      },
    },
  },
];

const MAX_TOOL_ROUNDS = 4;

/** Run one turn: feed history, resolve any tool calls, return the final text. */
export async function respond(cfg: LlmConfig, history: ChatCompletionMessageParam[]): Promise<string> {
  const client = new OpenAI({ baseURL: "https://openrouter.ai/api/v1", apiKey: cfg.apiKey });
  const messages: ChatCompletionMessageParam[] = [{ role: "system", content: SYSTEM }, ...history];

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    let completion;
    try {
      completion = await client.chat.completions.create({
        model: cfg.model,
        messages,
        tools: TOOLS,
        tool_choice: "auto",
      });
    } catch (error) {
      throw new Error(describeOpenRouterError(cfg.model, error));
    }

    const choice = completion.choices[0]?.message;
    if (!choice) return "…";
    messages.push(choice as ChatCompletionMessageParam);

    const calls = choice.tool_calls ?? [];
    if (calls.length === 0) return choice.content?.trim() || "…";

    for (const call of calls) {
      if (call.type !== "function") continue;
      const output = await runTool(cfg, call.function.name, call.function.arguments);
      messages.push({ role: "tool", tool_call_id: call.id, content: JSON.stringify(output) });
    }
  }

  return "I couldn't settle on an action — try rephrasing?";
}

async function runTool(cfg: LlmConfig, name: string, rawArgs: string): Promise<unknown> {
  if (name !== "send_xpr") return { ok: false, error: `unknown tool "${name}"` };
  let args: { to?: unknown; amount?: unknown; memo?: unknown };
  try {
    args = JSON.parse(rawArgs || "{}");
  } catch {
    return { ok: false, error: "invalid tool arguments" };
  }
  if (typeof args.to !== "string" || typeof args.amount !== "string") {
    return { ok: false, error: "send_xpr needs string `to` and `amount`" };
  }
  return signAndPush(cfg.signbox, {
    to: args.to,
    amount: normalizeAmount(args.amount),
    memo: typeof args.memo === "string" ? args.memo : undefined,
  });
}

/** Turn an OpenRouter/OpenAI SDK error into a message that names the real cause. */
function describeOpenRouterError(model: string, error: unknown): string {
  const e = error as {
    status?: number;
    message?: string;
    error?: { message?: string; code?: string | number };
    code?: string | number;
  };
  const detail = e?.error?.message ?? e?.message ?? String(error);
  const status = e?.status ? ` (HTTP ${e.status})` : "";
  let hint = "";
  if (e?.status === 401) hint = " — check OPENROUTER_API_KEY.";
  else if (e?.status === 402) hint = " — out of OpenRouter credits.";
  else if (e?.status === 404 || /not a valid model|no endpoints/i.test(detail))
    hint = ` — set OPENROUTER_MODEL to a valid tool-calling model (e.g. openai/gpt-4o-mini, anthropic/claude-3.5-sonnet). See https://openrouter.ai/models`;
  else if (/tool|function/i.test(detail))
    hint = " — this model may not support tool calling; pick one that does.";
  return `OpenRouter error for model "${model}"${status}: ${detail}${hint}`;
}

/** Coerce "1 XPR" / "1.0 XPR" / "1" into the strict "1.0000 XPR" the chain wants. */
function normalizeAmount(input: string): string {
  const m = input.trim().match(/^([0-9]+(?:\.[0-9]+)?)\s*([A-Z]{1,7})?$/i);
  if (!m) return input.trim();
  const value = Number(m[1]);
  const symbol = (m[2] ?? "XPR").toUpperCase();
  if (!Number.isFinite(value)) return input.trim();
  return `${value.toFixed(4)} ${symbol}`;
}
