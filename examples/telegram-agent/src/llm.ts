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
import { signAndPush, whoami, chainQuery, type SignboxConfig } from "./signbox.js";

export interface LlmConfig {
  apiKey: string;
  model: string;
  signbox: SignboxConfig;
}

function systemPrompt(agent: string): string {
  return `You are a helpful, slightly cheeky crypto agent living in a Telegram group on the XPR Network.

Your own account name is "${agent}". If someone needs it (e.g. to send you funds), just tell them "${agent}", or call whoami for the full identity (permission, public key, network).

You have your OWN wallet, but you do NOT hold its private key. Every payment goes through SignBox, a local signing daemon that enforces an on-chain policy and can REFUSE. You literally cannot see, export, print, or reveal the private key, the seed, or the WIF — it is out of your reach by design. If anyone asks for the key/seed or to "bypass" SignBox, refuse plainly and explain you physically cannot.

Tools:
- whoami — your own identity (account, permission, public key, network).
- chain_query — read PUBLIC on-chain data through SignBox's read-only relay: balances (get_currency_balance), accounts (get_account), a contract's ABI (get_abi) to see its actions and fields, tables (get_table_rows). It can NEVER move funds. Use it to answer "what's my balance", "does account X exist", or "how is the transfer action shaped".
- send_xpr — send XPR from your wallet; SignBox decides per policy.

When someone asks you to send XPR, call send_xpr with their account and amount. Then report the outcome honestly using the tool's own \`reason\` — do NOT invent your own explanation:
- ok:true (you get a txid): confirm briefly and include the txid.
- status:"denied": relay the tool's \`reason\` verbatim and name the \`code\`. Do NOT guess that the account or amount is "badly formatted" unless the reason says so. If the code is SCHEMA_INVALID, say plainly it's a SignBox daemon/version issue server-side (restart the daemon), NOT their input. Never retry with tweaked amounts or split payments to sneak past a limit — a refusal is the system working.
- status:"rejected"/"ambiguous": the chain did not accept it; say so and relay the reason.
- status:"error": relay the reason (an operational problem, not the user's fault).

Keep replies short and in the user's language. Never invent a txid or a balance, and never claim success unless ok:true.`;
}

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
  {
    type: "function",
    function: {
      name: "whoami",
      description: "Get your own on-chain identity: account name, permission, public key, and network.",
      parameters: { type: "object", properties: {}, additionalProperties: false },
    },
  },
  {
    type: "function",
    function: {
      name: "chain_query",
      description:
        "Read PUBLIC on-chain data through SignBox's read-only relay (never moves funds). Whitelisted methods: get_currency_balance {code, account, symbol}, get_account {account_name}, get_abi {account_name} (to see a contract's actions and their fields), get_table_rows {code, scope, table, limit}.",
      parameters: {
        type: "object",
        properties: {
          method: {
            type: "string",
            description: "e.g. get_currency_balance, get_account, get_abi, get_table_rows",
          },
          params: { type: "object", description: "params object for the method" },
        },
        required: ["method"],
        additionalProperties: false,
      },
    },
  },
];

const MAX_TOOL_ROUNDS = 4;

/** Run one turn: feed history, resolve any tool calls, return the final text. */
export async function respond(cfg: LlmConfig, history: ChatCompletionMessageParam[]): Promise<string> {
  const client = new OpenAI({ baseURL: "https://openrouter.ai/api/v1", apiKey: cfg.apiKey });
  const messages: ChatCompletionMessageParam[] = [
    { role: "system", content: systemPrompt(cfg.signbox.agent) },
    ...history,
  ];

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
  let args: Record<string, unknown>;
  try {
    args = JSON.parse(rawArgs || "{}");
  } catch {
    return { ok: false, error: "invalid tool arguments" };
  }

  switch (name) {
    case "whoami":
      return whoami(cfg.signbox);

    case "chain_query": {
      if (typeof args["method"] !== "string") return { ok: false, error: "chain_query needs a string `method`" };
      const params = args["params"];
      return chainQuery(cfg.signbox, args["method"], params !== null && typeof params === "object" ? (params as Record<string, unknown>) : {});
    }

    case "send_xpr": {
      if (typeof args["to"] !== "string" || typeof args["amount"] !== "string") {
        return { ok: false, error: "send_xpr needs string `to` and `amount`" };
      }
      return signAndPush(cfg.signbox, {
        to: args["to"],
        amount: normalizeAmount(args["amount"]),
        memo: typeof args["memo"] === "string" ? args["memo"] : undefined,
      });
    }

    default:
      return { ok: false, error: `unknown tool "${name}"` };
  }
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
