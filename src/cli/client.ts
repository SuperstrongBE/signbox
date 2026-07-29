/**
 * Socket clients for the CLI: the agent-side sign client (§11.6) and the
 * admin client (§14.6). The CLI is a CLIENT of the running daemon — it
 * holds no key and evaluates no policy when signing.
 */

import { connect } from "node:net";
import { randomUUID, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { SignBoxError, ValidationError } from "../core/errors.js";
import type { SignResponseJson } from "../daemon/protocol.js";
import type { AdminCommand, AdminResponse } from "../daemon/server.js";
import type { ChainContext } from "../core/types.js";

export function sendLine(socketPath: string, line: string, timeoutMs = 15_000): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const socket = connect(socketPath);
    let buffered = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new SignBoxError("daemon did not answer in time"));
    }, timeoutMs);
    socket.setEncoding("utf8");
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(new SignBoxError(`cannot reach daemon socket: ${error.message}`));
    });
    socket.on("data", (chunk: string) => {
      buffered += chunk;
      const newline = buffered.indexOf("\n");
      if (newline !== -1) {
        clearTimeout(timer);
        socket.end();
        resolve(buffered.slice(0, newline));
      }
    });
    socket.write(line + "\n");
  });
}

export interface SignViaDaemonOptions {
  socketPath: string;
  agent: string;
  context: ChainContext;
  transaction: unknown;
  token: string;
  /** Request validity window; must stay within the daemon's maximum. */
  ttlMs?: number;
}

export async function signViaDaemon(options: SignViaDaemonOptions): Promise<SignResponseJson> {
  const now = Date.now();
  const request = {
    requestId: randomUUID(),
    agent: options.agent,
    chain: options.context.chain,
    network: options.context.network,
    chainId: options.context.chainId,
    transaction: options.transaction,
    requestedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + (options.ttlMs ?? 60_000)).toISOString(),
    nonce: randomBytes(24).toString("base64url"),
    token: options.token,
  };
  const answer = await sendLine(options.socketPath, JSON.stringify(request));
  return JSON.parse(answer) as SignResponseJson;
}

export async function adminCommand(
  adminSocketPath: string,
  command: AdminCommand,
): Promise<AdminResponse> {
  const answer = await sendLine(adminSocketPath, JSON.stringify(command));
  return JSON.parse(answer) as AdminResponse;
}

/** Read an agent token file, trimming a trailing newline. */
export function readToken(tokenPath: string): string {
  try {
    return readFileSync(tokenPath, "utf8").trim();
  } catch {
    throw new ValidationError(`cannot read token file: ${tokenPath}`);
  }
}
