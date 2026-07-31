/**
 * Interactive prompts for the CLI. Questions and echo go to stderr so stdout
 * stays reserved for structured JSON results (INV-002: never a secret here —
 * passphrases use the raw-TTY promptPassphrase instead).
 */

import { createInterface } from "node:readline/promises";
import { ValidationError } from "../core/errors.js";

export function isInteractive(): boolean {
  return process.stdin.isTTY === true && process.stderr.isTTY === true;
}

export async function promptText(
  question: string,
  opts: { default?: string; validate?: (value: string) => string | null } = {},
): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    for (;;) {
      const suffix = opts.default !== undefined ? ` [${opts.default}]` : "";
      const raw = (await rl.question(`${question}${suffix}: `)).trim();
      const value = raw === "" && opts.default !== undefined ? opts.default : raw;
      if (value === "") {
        process.stderr.write("  a value is required\n");
        continue;
      }
      const error = opts.validate?.(value);
      if (error !== null && error !== undefined) {
        process.stderr.write(`  ${error}\n`);
        continue;
      }
      return value;
    }
  } finally {
    rl.close();
  }
}

export interface Choice<T extends string> {
  value: T;
  label: string;
}

export async function promptChoice<T extends string>(
  question: string,
  choices: Choice<T>[],
  opts: { default?: T } = {},
): Promise<T> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    for (;;) {
      process.stderr.write(`${question}\n`);
      choices.forEach((c, i) => {
        const marker = c.value === opts.default ? " (default)" : "";
        process.stderr.write(`  ${i + 1}) ${c.label}${marker}\n`);
      });
      const raw = (await rl.question("  choice: ")).trim();
      if (raw === "" && opts.default !== undefined) return opts.default;
      const index = Number(raw) - 1;
      if (Number.isInteger(index) && index >= 0 && index < choices.length) {
        return choices[index]!.value;
      }
      const byValue = choices.find((c) => c.value === raw);
      if (byValue !== undefined) return byValue.value;
      process.stderr.write("  invalid choice\n");
    }
  } finally {
    rl.close();
  }
}

/**
 * Arrow-key radio select. Renders the choices with a `❯` marker on the
 * highlighted row; Up/Down (or j/k, or a number key) move, Enter confirms,
 * Ctrl-C aborts. Writes to stderr so stdout stays reserved for the result.
 * Only call this on a real TTY (guard with isInteractive()).
 */
export async function promptSelect<T extends string>(
  question: string,
  choices: Choice<T>[],
  opts: { default?: T } = {},
): Promise<T> {
  const stdin = process.stdin;
  const out = process.stderr;
  let index = choices.findIndex((c) => c.value === opts.default);
  if (index < 0) index = 0;

  out.write(`${question}\n`);
  const render = (first: boolean): void => {
    if (!first) out.write(`\x1b[${choices.length}A`);
    for (const [i, c] of choices.entries()) {
      const on = i === index;
      out.write(`\x1b[2K\r  ${on ? "\x1b[1m❯ " : "  "}${c.label}\x1b[0m\n`);
    }
  };
  render(true);

  return new Promise<T>((resolve, reject) => {
    stdin.setRawMode?.(true);
    stdin.resume();
    out.write("\x1b[?25l"); // hide cursor
    const cleanup = (): void => {
      stdin.removeListener("data", onData);
      stdin.setRawMode?.(false);
      stdin.pause();
      out.write("\x1b[?25h"); // show cursor
    };
    const onData = (buf: Buffer): void => {
      const s = buf.toString();
      if (s === "\x03") {
        cleanup();
        reject(new ValidationError("selection aborted"));
      } else if (s === "\r" || s === "\n") {
        cleanup();
        resolve(choices[index]!.value);
      } else if (s === "\x1b[A" || s === "\x1bOA" || s === "k") {
        index = (index - 1 + choices.length) % choices.length;
        render(false);
      } else if (s === "\x1b[B" || s === "\x1bOB" || s === "j") {
        index = (index + 1) % choices.length;
        render(false);
      } else if (/^[1-9]$/.test(s) && Number(s) <= choices.length) {
        index = Number(s) - 1;
        render(false);
      }
    };
    stdin.on("data", onData);
  });
}

/** Antelope account name validator, for interactive text prompts. */
export function validateAccountName(value: string): string | null {
  return /^[a-z1-5.]{1,12}$/.test(value)
    ? null
    : "must be 1-12 chars of a-z, 1-5 or dots";
}
