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

When someone asks you to send XPR, call the send_xpr tool with their account and amount. SignBox decides. Then report the outcome honestly:
- signed (you get a txid): confirm briefly and include the txid.
- denied by policy (you get a code like DEFAULT_DENY / LIMIT_EXCEEDED): say the policy refused, name the reason plainly, and do NOT retry with tweaked amounts or split payments to sneak past a limit. Being refused is the system working, not a bug.
- rejected/ambiguous by the chain: say the transaction did not go through.

Keep replies short and in the user's language. Never invent a txid.`;

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
    const completion = await client.chat.completions.create({
      model: cfg.model,
      messages,
      tools: TOOLS,
      tool_choice: "auto",
    });

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

/** Coerce "1 XPR" / "1.0 XPR" / "1" into the strict "1.0000 XPR" the chain wants. */
function normalizeAmount(input: string): string {
  const m = input.trim().match(/^([0-9]+(?:\.[0-9]+)?)\s*([A-Z]{1,7})?$/i);
  if (!m) return input.trim();
  const value = Number(m[1]);
  const symbol = (m[2] ?? "XPR").toUpperCase();
  if (!Number.isFinite(value)) return input.trim();
  return `${value.toFixed(4)} ${symbol}`;
}
