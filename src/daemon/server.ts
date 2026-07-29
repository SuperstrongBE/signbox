/**
 * SignBox daemon (spec §5, §12, §13).
 *
 * Unix domain socket server implementing the decision pipeline. Every request
 * walks the same gauntlet, and any failure at any step is a refusal
 * (INV-010) — the transport never sees an exception, the signer is never
 * reached by a refused transaction (§17.2).
 *
 * Local authentication (spec §12.3):
 * - the socket lives in a directory only reachable by the daemon user and
 *   the agent group (OS isolation, §5.1);
 * - the socket file itself is chmod-restricted at start;
 * - each request carries the agent's rotating local token, compared in
 *   constant time. The token file on disk is readable only by the agent's
 *   OS user: possession proves identity at the same granularity as peer
 *   credentials, without native bindings. A native SO_PEERCRED/getpeereid
 *   check is planned as an additional layer (Phase 2 hardening);
 * - nonce anti-replay + strict expiry.
 *
 * The kill-switch (§14.6) is `disableAgent()`: local, immediate, no
 * on-chain round-trip.
 */

import { createServer, type Server, type Socket } from "node:net";
import { timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, unlinkSync } from "node:fs";
import type {
  ChainContext,
  DecodedTransaction,
  DenyCode,
  KeyHandle,
  TransactionSigner,
} from "../core/types.js";
import type { Policy } from "../core/policy/schema.js";
import { evaluatePolicy } from "../core/policy/engine.js";
import { ValidationError } from "../core/errors.js";
import { parseSignRequest, type SignRequestJson, type SignResponseJson } from "./protocol.js";
import { NonceCache } from "./nonceCache.js";
import type { QuotaJournal } from "./quotaJournal.js";

export interface AgentRuntime {
  agent: string;
  permission: string;
  chain: ChainContext;
  policy: Policy;
  policyVersion: number;
  enabled: boolean;
  /** Rotating local token (§12.3). Stored as a Buffer for constant-time compare. */
  token: Buffer;
  key: KeyHandle;
}

export interface DaemonConfig {
  socketPath: string;
  /** Socket file mode. 0600 (same-user dev) by default; 0660 with a dedicated group in production. */
  socketMode?: number;
  /** Maximum accepted request line size. */
  maxRequestBytes?: number;
  /** Maximum tolerated requestedAt→expiresAt window. */
  maxRequestTtlMs?: number;
  /** Tolerated clock skew for requestedAt in the future. */
  maxClockSkewMs?: number;
}

export interface DaemonDependencies {
  /** ChainAdapter decode seam (INV-014 enforcement lives there). */
  decode: (input: unknown, context: ChainContext) => DecodedTransaction;
  /** Path-1 signing seam (§5.5). Called only after an allow decision. */
  signer: TransactionSigner;
  /**
   * Stateful quota journal (§8.5). Without it, any policy demanding
   * stateful limits refuses with QUOTA_UNAVAILABLE — fail closed.
   */
  quotas?: QuotaJournal;
  /** Injectable clock for tests. */
  now?: () => number;
}

const DEFAULTS = {
  socketMode: 0o600,
  maxRequestBytes: 64 * 1024,
  maxRequestTtlMs: 120_000,
  maxClockSkewMs: 5_000,
} as const;

export class SignBoxDaemon {
  private readonly agents = new Map<string, AgentRuntime>();
  private readonly nonces = new NonceCache();
  private readonly cfg: Required<DaemonConfig>;
  private readonly now: () => number;
  private server: Server | undefined;

  constructor(
    config: DaemonConfig,
    private readonly deps: DaemonDependencies,
  ) {
    this.cfg = { ...DEFAULTS, ...config };
    this.now = deps.now ?? Date.now;
  }

  registerAgent(runtime: AgentRuntime): void {
    if (this.agents.has(runtime.agent)) {
      throw new ValidationError(`agent already registered: ${runtime.agent}`);
    }
    this.agents.set(runtime.agent, runtime);
  }

  /** Local kill-switch (§14.6): immediate, no on-chain round-trip. */
  disableAgent(agent: string): void {
    const runtime = this.agents.get(agent);
    if (runtime !== undefined) runtime.enabled = false;
  }

  enableAgent(agent: string): void {
    const runtime = this.agents.get(agent);
    if (runtime !== undefined) runtime.enabled = true;
  }

  async start(): Promise<void> {
    if (this.server !== undefined) return;
    if (existsSync(this.cfg.socketPath)) {
      // Fail closed rather than silently hijacking another daemon's socket.
      throw new ValidationError(
        `socket path already exists: ${this.cfg.socketPath} (is another daemon running?)`,
      );
    }
    const server = createServer((socket) => this.handleConnection(socket));
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.cfg.socketPath, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    chmodSync(this.cfg.socketPath, this.cfg.socketMode);
    this.server = server;
  }

  async stop(): Promise<void> {
    const server = this.server;
    if (server === undefined) return;
    this.server = undefined;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    try {
      unlinkSync(this.cfg.socketPath);
    } catch {
      /* already gone */
    }
  }

  private handleConnection(socket: Socket): void {
    let buffered = "";
    socket.setEncoding("utf8");
    socket.on("error", () => socket.destroy());
    socket.on("data", (chunk: string) => {
      buffered += chunk;
      if (Buffer.byteLength(buffered, "utf8") > this.cfg.maxRequestBytes) {
        // Oversized input: refuse and drop the connection (fail closed).
        socket.destroy();
        return;
      }
      let newlineIndex = buffered.indexOf("\n");
      while (newlineIndex !== -1) {
        const line = buffered.slice(0, newlineIndex);
        buffered = buffered.slice(newlineIndex + 1);
        if (line.trim().length > 0) {
          void this.handleLine(line, socket);
        }
        newlineIndex = buffered.indexOf("\n");
      }
    });
  }

  private async handleLine(line: string, socket: Socket): Promise<void> {
    const response = await this.handleRequest(line);
    if (!socket.destroyed) {
      socket.write(JSON.stringify(response) + "\n");
    }
  }

  /**
   * The decision pipeline (§13). Exposed for direct testing.
   * NEVER throws: every failure maps to a denied response.
   */
  async handleRequest(line: string): Promise<SignResponseJson> {
    let request: SignRequestJson;
    try {
      request = parseSignRequest(line);
    } catch {
      return {
        requestId: "unknown",
        status: "denied",
        code: "SCHEMA_INVALID",
        safeReason: "request does not match the expected schema",
      };
    }

    const deny = (code: DenyCode, safeReason: string, policyVersion?: number): SignResponseJson =>
      policyVersion === undefined
        ? { requestId: request.requestId, status: "denied", code, safeReason }
        : { requestId: request.requestId, status: "denied", code, safeReason, policyVersion };

    try {
      // Authenticate caller. Unknown agents and bad tokens get the same
      // response: the daemon does not reveal which agents exist.
      const runtime = this.agents.get(request.agent);
      if (runtime === undefined || !constantTimeEquals(runtime.token, request.token)) {
        return deny("UNAUTHENTICATED", "request could not be authenticated");
      }

      if (!runtime.enabled) {
        return deny("AGENT_DISABLED", "agent is disabled");
      }

      // Validate the request window.
      const now = this.now();
      const requestedAt = Date.parse(request.requestedAt);
      const expiresAt = Date.parse(request.expiresAt);
      if (
        expiresAt <= now ||
        requestedAt > now + this.cfg.maxClockSkewMs ||
        expiresAt <= requestedAt ||
        expiresAt - requestedAt > this.cfg.maxRequestTtlMs
      ) {
        return deny("REQUEST_EXPIRED", "request window is invalid or expired");
      }

      // Anti-replay.
      const nonceState = this.nonces.register(request.nonce, expiresAt, now);
      if (nonceState !== "ok") {
        return deny("NONCE_REUSED", "nonce was already used or cannot be registered");
      }

      // Explicit chain identity (INV-013).
      const { chain } = runtime;
      if (
        request.chain !== chain.chain ||
        request.network !== chain.network ||
        request.chainId !== chain.chainId
      ) {
        return deny("CHAIN_MISMATCH", "request chain does not match the agent configuration");
      }

      // Decode: INV-014/INV-003 enforcement lives in the ChainAdapter.
      let decoded: DecodedTransaction;
      try {
        decoded = this.deps.decode(request.transaction, chain);
      } catch {
        return deny("SCHEMA_INVALID", "transaction could not be fully decoded");
      }

      // Deterministic policy evaluation.
      const { decision, quotaDemands } = evaluatePolicy(decoded, runtime.policy, {
        agent: runtime.agent,
        agentPermission: runtime.permission,
        chainId: chain.chainId,
        policyVersion: runtime.policyVersion,
      });

      if (decision.effect === "deny") {
        return deny(decision.code, decision.safeReason, decision.policyVersion);
      }

      // Stateful limits: reserve atomically BEFORE signing (§13, §15.6).
      // Without a journal, any demand refuses — fail closed (§8.5).
      let reservationId: string | undefined;
      if (quotaDemands.length > 0) {
        const quotas = this.deps.quotas;
        if (quotas === undefined) {
          return deny(
            "QUOTA_UNAVAILABLE",
            "policy requires stateful limits that are not available",
            decision.policyVersion,
          );
        }
        const reserved = quotas.reserve(runtime.agent, quotaDemands, now);
        if (!reserved.ok) {
          return deny(
            reserved.reason === "ambiguous" ? "AMBIGUOUS_VALUE" : "LIMIT_EXCEEDED",
            "a stateful policy limit refuses this transaction",
            decision.policyVersion,
          );
        }
        reservationId = reserved.reservationId;
      }

      // Sign exactly what was validated (INV-014: nothing mutated in between).
      // A failed signing releases the reservation: unused quota is returned.
      let signed;
      try {
        signed = await this.deps.signer.sign(decoded, runtime.key);
      } catch (error) {
        if (reservationId !== undefined) {
          this.deps.quotas?.release(reservationId);
        }
        throw error;
      }
      if (reservationId !== undefined) {
        this.deps.quotas?.commit(reservationId, runtime.agent, signed.transactionDigest);
      }

      const response: SignResponseJson = {
        requestId: request.requestId,
        status: "signed",
        signature: signed.signature,
        transactionDigest: signed.transactionDigest,
        policyVersion: decision.policyVersion,
      };
      if (signed.signedTransaction !== undefined) {
        response.signedTransaction = signed.signedTransaction;
      }
      return response;
    } catch {
      // INV-010: no exception escapes as anything but a refusal.
      return deny("INTERNAL_ERROR", "request processing failed");
    }
  }
}

function constantTimeEquals(expected: Buffer, provided: string): boolean {
  const providedBuffer = Buffer.from(provided, "utf8");
  if (providedBuffer.length !== expected.length) return false;
  return timingSafeEqual(expected, providedBuffer);
}
