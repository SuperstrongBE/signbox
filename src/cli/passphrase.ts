/**
 * Passphrase input (spec §9.4).
 *
 * Interactive TTY prompt with echo disabled, or a line read from a piped
 * stdin (secret-manager integration). NEVER from argv or environment
 * variables — those leak through process listings and shells.
 */

import { ValidationError } from "../core/errors.js";

export async function promptPassphrase(prompt: string): Promise<Buffer> {
  if (!process.stdin.isTTY) {
    return readLineFromStdin();
  }
  process.stderr.write(prompt);
  const stdin = process.stdin;
  stdin.setRawMode(true);
  stdin.resume();
  return new Promise<Buffer>((resolve, reject) => {
    const chars: number[] = [];
    const onData = (chunk: Buffer): void => {
      for (const byte of chunk) {
        if (byte === 0x03) {
          // Ctrl-C
          cleanup();
          reject(new ValidationError("passphrase entry aborted"));
          return;
        }
        if (byte === 0x0d || byte === 0x0a) {
          cleanup();
          process.stderr.write("\n");
          resolve(Buffer.from(chars));
          chars.fill(0);
          return;
        }
        if (byte === 0x7f || byte === 0x08) {
          chars.pop();
          continue;
        }
        chars.push(byte);
      }
    };
    const cleanup = (): void => {
      stdin.removeListener("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
    };
    stdin.on("data", onData);
  });
}

/**
 * Piped stdin may carry SEVERAL passphrase lines (e.g. passphrase +
 * confirmation for `key generate`): stdin is read once and served line
 * by line across successive prompts.
 */
let stdinLines: Buffer[] | undefined;

async function readLineFromStdin(): Promise<Buffer> {
  if (stdinLines === undefined) {
    const all = await new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = [];
      process.stdin.on("data", (chunk: Buffer) => chunks.push(chunk));
      process.stdin.on("end", () => resolve(Buffer.concat(chunks)));
      process.stdin.on("error", () =>
        reject(new ValidationError("cannot read passphrase from stdin")),
      );
    });
    stdinLines = [];
    let start = 0;
    for (let i = 0; i <= all.length; i++) {
      if (i === all.length || all[i] === 0x0a) {
        if (i > start) stdinLines.push(Buffer.from(all.subarray(start, i)));
        start = i + 1;
      }
    }
  }
  const line = stdinLines.shift();
  if (line === undefined) {
    throw new ValidationError("no more passphrase lines available on stdin");
  }
  return line;
}
