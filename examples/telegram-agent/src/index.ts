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
  model: requireEnv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
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

// Diagnostic: log EVERY update the bot receives, before any handler. If you
// mention the bot in a group and NOTHING prints here, Telegram never delivered
// the message — that is Group Privacy (see README: disable it in BotFather AND
// re-add the bot, or make it admin).
bot.use((ctx, next) => {
  const msg = ctx.message as { text?: string } | undefined;
  console.log(`[update] type=${ctx.updateType} chat=${ctx.chat?.id ?? "?"} text=${msg?.text ?? ""}`);
  return next();
});

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

/** True when the message @mentions this bot (parsed from Telegram entities). */
function isMentionOfBot(msg: {
  text: string;
  entities?: readonly { type: string; offset: number; length: number }[];
}): boolean {
  if (botUsername === "") return false;
  const target = `@${botUsername.toLowerCase()}`;
  for (const e of msg.entities ?? []) {
    if (e.type === "mention" && msg.text.slice(e.offset, e.offset + e.length).toLowerCase() === target) {
      return true;
    }
  }
  // Fallback for clients that don't tag the mention as an entity.
  return msg.text.toLowerCase().includes(target);
}

/** Drop the bot's own @mention from the text so the LLM sees a clean request. */
function stripMention(text: string): string {
  if (botUsername === "") return text.trim();
  return text.replace(new RegExp(`@${botUsername}\\b`, "gi"), "").replace(/\s+/g, " ").trim();
}

bot.on(message("text"), async (ctx) => {
  const chatId = ctx.chat.id;
  const text = ctx.message.text;
  const isPrivate = ctx.chat.type === "private";
  const mentioned = isMentionOfBot(ctx.message);
  const repliesToMe =
    ctx.message.reply_to_message?.from?.username?.toLowerCase() === botUsername.toLowerCase();

  // Diagnostic: log EVERY text message the bot actually receives. If nothing
  // prints when you mention it, the bot isn't receiving the message at all —
  // that's Telegram Group Privacy (see README). Remove once it works.
  console.log(`[recv ${ctx.chat.type} ${chatId}] mention=${mentioned} reply=${repliesToMe}: ${text}`);

  if (allowedChat && String(chatId) !== allowedChat) {
    console.log(`  ↳ ignored: chat ${chatId} ≠ TELEGRAM_GROUP_ID ${allowedChat}`);
    return;
  }
  if (text.startsWith("/")) return; // let command handlers own slash-commands

  // Answer only when addressed: a private chat, an @mention of the bot, or a
  // reply to one of the bot's own messages. Stay quiet otherwise (no spam).
  if (!isPrivate && !mentioned && !repliesToMe) {
    console.log("  ↳ ignored: not addressed (mention the bot or reply to it)");
    return;
  }

  const request = stripMention(text) || text.trim();
  const who = ctx.from?.username ? `@${ctx.from.username}` : ctx.from?.first_name ?? "someone";
  console.log(`[${ctx.chat.type} ${chatId}] ${who}: ${request}`);
  const history = remember(chatId, { role: "user", content: `[${who}] ${request}` });

  await ctx.sendChatAction("typing").catch(() => undefined);
  try {
    const reply = await respond(cfg, history);
    remember(chatId, { role: "assistant", content: reply });
    await ctx.reply(reply, { reply_parameters: { message_id: ctx.message.message_id } });
  } catch (error) {
    console.error("turn failed:", error);
    await ctx.reply(`⚠️ ${(error as Error).message}`);
  }
});

async function main(): Promise<void> {
  const me = await bot.telegram.getMe();
  botUsername = me.username ?? "";
  // launch() resolves only when the bot stops, so don't await it here.
  void bot.launch({ dropPendingUpdates: true });
  console.log(`SignBox Telegram agent running as @${botUsername} (agent account: ${cfg.signbox.agent})`);
  if (me.can_read_all_group_messages) {
    console.log("Group Privacy: OFF — the bot reads all group messages ✅");
  } else {
    console.log(
      "Group Privacy: ON ⚠️  — the bot only receives @mentions, replies to it, and commands.\n" +
        "  If mentions still don't arrive: BotFather → /setprivacy → Disable, then REMOVE and RE-ADD the bot to the group (privacy changes need a re-add), or make it an admin.",
    );
  }
}

process.once("SIGINT", () => bot.stop("SIGINT"));
process.once("SIGTERM", () => bot.stop("SIGTERM"));

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
