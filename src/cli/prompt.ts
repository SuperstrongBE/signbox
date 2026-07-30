/**
 * Interactive prompts for the CLI. Questions and echo go to stderr so stdout
 * stays reserved for structured JSON results (INV-002: never a secret here —
 * passphrases use the raw-TTY promptPassphrase instead).
 */

import { createInterface } from "node:readline/promises";

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

/** Antelope account name validator, for interactive text prompts. */
export function validateAccountName(value: string): string | null {
  return /^[a-z1-5.]{1,12}$/.test(value)
    ? null
    : "must be 1-12 chars of a-z, 1-5 or dots";
}
