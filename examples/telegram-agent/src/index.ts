/**
 * A Telegram group agent that spends through SignBox.
 *
 * Add the bot to a group, mention it ("@bot send 1 XPR to alice"), and watch:
 * the LLM calls send_xpr, SignBox applies the on-chain policy, and the key
 * never leaves the daemon. Refusals are the system working as intended.
 *
 * Transport: long-polling (no public URL needed) — ideal for a VPS.
 */

import { Telegraf } from "telegraf";
import { message } from "telegraf/filters";
import type { ChatCompletionMessageParam } from "openai/resources/chat/completions";
import { respond, type LlmConfig } from "./llm.js";

function requireEnv(name: string, fallback?: string): string {
  const value = process.env[name] ?? fallback;
  if (value === undefined || value === "") {
    console.error(`Missing required env var: ${name}`);
    process.exit(1);
  }
  return value;
}

const cfg: LlmConfig = {
  apiKey: requireEnv("OPENROUTER_API_KEY"),
  model: requireEnv("OPENROUTER_MODEL", "anthropic/claude-3.5-sonnet"),
  signbox: {
    bin: requireEnv("SIGNBOX_BIN", "signbox"),
    agent: requireEnv("SIGNBOX_AGENT"),
    ...(process.env.SIGNBOX_CONFIG ? { configPath: process.env.SIGNBOX_CONFIG } : {}),
  },
};

// Optional: restrict the bot to a single group chat id.
const allowedChat = process.env.TELEGRAM_GROUP_ID;

const bot = new Telegraf(requireEnv("TELEGRAM_BOT_TOKEN"));
let botUsername = "";

/** Bounded short-term memory per chat, so the model has a little context. */
const HISTORY_LIMIT = 12;
const memory = new Map<number, ChatCompletionMessageParam[]>();
function remember(chatId: number, entry: ChatCompletionMessageParam): ChatCompletionMessageParam[] {
  const history = memory.get(chatId) ?? [];
  history.push(entry);
  while (history.length > HISTORY_LIMIT) history.shift();
  memory.set(chatId, history);
  return history;
}

bot.start((ctx) =>
  ctx.reply(
    "gm 👋 I'm a SignBox-guarded wallet agent. Ask me to send XPR — the on-chain policy decides, and I can't touch the private key.",
  ),
);

bot.help((ctx) =>
  ctx.reply(
    'Mention me and ask, e.g. "@bot send 1 XPR to alice". SignBox enforces the policy, so some requests get refused. I can\'t reveal or export the key — it lives in the daemon, not in me.',
  ),
);

bot.on(message("text"), async (ctx) => {
  const chatId = ctx.chat.id;
  if (allowedChat && String(chatId) !== allowedChat) return;

  const text = ctx.message.text;
  if (text.startsWith("/")) return; // let command handlers own slash-commands

  // Stay quiet in groups unless addressed (mention or reply), to avoid spam.
  const isPrivate = ctx.chat.type === "private";
  const lower = text.toLowerCase();
  const mentionsMe = botUsername !== "" && lower.includes(`@${botUsername.toLowerCase()}`);
  const repliesToMe =
    ctx.message.reply_to_message?.from?.username?.toLowerCase() === botUsername.toLowerCase();
  if (!isPrivate && !mentionsMe && !repliesToMe) return;

  const who = ctx.from?.username ? `@${ctx.from.username}` : ctx.from?.first_name ?? "someone";
  const history = remember(chatId, { role: "user", content: `[${who}] ${text}` });

  await ctx.sendChatAction("typing").catch(() => undefined);
  try {
    const reply = await respond(cfg, history);
    remember(chatId, { role: "assistant", content: reply });
    await ctx.reply(reply);
  } catch (error) {
    console.error("turn failed:", error);
    await ctx.reply(`⚠️ ${(error as Error).message}`);
  }
});

async function main(): Promise<void> {
  const me = await bot.telegram.getMe();
  botUsername = me.username ?? "";
  // launch() resolves only when the bot stops, so don't await it here.
  void bot.launch();
  console.log(`SignBox Telegram agent running as @${botUsername} (agent account: ${cfg.signbox.agent})`);
}

process.once("SIGINT", () => bot.stop("SIGINT"));
process.once("SIGTERM", () => bot.stop("SIGTERM"));

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
