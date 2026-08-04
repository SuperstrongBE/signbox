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
import { evaluatePolicy, collectProviderQueries } from "../core/policy/engine.js";
import { resolveProviders } from "./providerResolver.js";
import { ValidationError } from "../core/errors.js";
import {
  parseSignRequest,
  parseReadRequest,
  peekOp,
  type BroadcastReport,
  type ReadResponseJson,
  type SignRequestJson,
  type SignResponseJson,
} from "./protocol.js";
import type { TransactionBroadcaster } from "./broadcaster.js";
import type { ChainReadRelay } from "./chainRelay.js";
import { NonceCache } from "./nonceCache.js";
import type { QuotaJournal } from "./quotaJournal.js";
import type { PolicyCache } from "./policyCache.js";
import type { AuditLog, AuditEntryInput } from "./auditLog.js";

/** Mutable context populated during a decision, then written to the audit log. */
interface AuditContext {
  agent: string;
  contracts: string[];
  ruleIds?: string[];
}

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
  /**
   * Administration socket (§12.3): distinct from the request socket, always
   * 0600 (daemon user only). Carries the kill-switch and status commands
   * (§14.6). Omit to disable remote administration entirely.
   */
  adminSocketPath?: string;
  /** Socket file mode. 0600 (same-user dev) by default; 0660 with a dedicated group in production. */
  socketMode?: number;
  /** Maximum accepted request line size. */
  maxRequestBytes?: number;
  /** Maximum tolerated requestedAt→expiresAt window. */
  maxRequestTtlMs?: number;
  /** Tolerated clock skew for requestedAt in the future. */
  maxClockSkewMs?: number;
}

export type AdminCommand =
  | { command: "status" }
  | { command: "disable"; agent: string }
  | { command: "enable"; agent: string };

export type AdminResponse =
  | { ok: true; agents?: { agent: string; enabled: boolean; policyVersion: number }[] }
  | { ok: false; error: string };

export interface DaemonDependencies {
  /** ChainAdapter decode seam (INV-014 enforcement lives there). */
  decode: (input: unknown, context: ChainContext) => DecodedTransaction;
  /** Path-1 signing seam (§5.5). Called only after an allow decision. */
  signer: TransactionSigner;
  /**
   * Broadcast seam (§5.5, §13). Present when the daemon may submit on the
   * agent's behalf (request `broadcast: true`): the signature never leaves the
   * daemon and the reserved quota is committed only if the tx lands. Absent in
   * unit tests and sign-only deployments — a broadcast request then degrades to
   * a plain signing (the signature is returned for the caller to submit).
   */
  broadcaster?: TransactionBroadcaster;
  /**
   * Read-only chain relay (agent convenience). Present when the agent may read
   * public chain data (its balance, an account, a table) through the daemon.
   * It is a strict read-only allow-list — never a path to submit — so it is
   * outside the signing trust boundary. Absent → `query` returns an error.
   */
  relay?: ChainReadRelay;
  /**
   * Stateful quota journal (§8.5). Without it, any policy demanding
   * stateful limits refuses with QUOTA_UNAVAILABLE — fail closed.
   */
  quotas?: QuotaJournal;
  /**
   * On-chain policy cache (§14). When present it is the source of truth:
   * the daemon evaluates the cached on-chain policy, not the statically
   * registered one, and refuses when it cannot be confirmed. Absent in
   * unit tests and offline dev, where the registered policy is used.
   */
  policyCache?: PolicyCache;
  /** Hash-chained audit log (§16). Every decision is recorded when present. */
  audit?: AuditLog;
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
  private readonly cfg: Required<Omit<DaemonConfig, "adminSocketPath">> &
    Pick<DaemonConfig, "adminSocketPath">;
  private readonly now: () => number;
  private server: Server | undefined;
  private adminServer: Server | undefined;

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
    // Unix socket paths are limited to ~104 bytes (macOS) / ~108 (Linux);
    // beyond that the kernel may bind a TRUNCATED path. Fail loudly instead.
    for (const path of [this.cfg.socketPath, this.cfg.adminSocketPath]) {
      if (path !== undefined && Buffer.byteLength(path, "utf8") > 100) {
        throw new ValidationError(
          `socket path exceeds the safe unix socket length (100 bytes): ${path}`,
        );
      }
    }
    if (existsSync(this.cfg.socketPath)) {
      // Fail closed rather than silently hijacking another daemon's socket.
      throw new ValidationError(
        `socket path already exists: ${this.cfg.socketPath} (is another daemon running?)`,
      );
    }
    const server = createServer((socket) => this.handleConnection(socket));
    // Create the socket under a restrictive umask so it is born with (at most)
    // socketMode — closing the window in which listen() creates a world-
    // reachable socket before chmod tightens it (TOCTOU). chmod below then
    // pins the exact mode as belt-and-suspenders.
    await this.listenWithMode(server, this.cfg.socketPath, this.cfg.socketMode);
    chmodSync(this.cfg.socketPath, this.cfg.socketMode);
    this.server = server;

    const adminPath = this.cfg.adminSocketPath;
    if (adminPath !== undefined) {
      if (existsSync(adminPath)) {
        await this.stop();
        throw new ValidationError(`admin socket path already exists: ${adminPath}`);
      }
      const adminServer = createServer((socket) => this.handleAdminConnection(socket));
      // The admin socket is ALWAYS restricted to the daemon user (§12.3): it
      // carries the kill-switch, never agent traffic. Born 0600 under the
      // umask, with no pre-chmod window.
      await this.listenWithMode(adminServer, adminPath, 0o600);
      chmodSync(adminPath, 0o600);
      this.adminServer = adminServer;
    }
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
    const adminServer = this.adminServer;
    if (adminServer !== undefined) {
      this.adminServer = undefined;
      await new Promise<void>((resolve) => adminServer.close(() => resolve()));
      try {
        if (this.cfg.adminSocketPath !== undefined) unlinkSync(this.cfg.adminSocketPath);
      } catch {
        /* already gone */
      }
    }
  }

  /**
   * Bind a unix socket with a restrictive umask so the socket file is created
   * with at most `mode`, eliminating the TOCTOU window between listen() and
   * chmod. The umask is process-global; this runs only on the sequential
   * startup path, and the previous umask is always restored.
   */
  private async listenWithMode(server: Server, path: string, mode: number): Promise<void> {
    const prevUmask = process.umask(0o777 & ~mode);
    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(path, () => {
          server.removeListener("error", reject);
          resolve();
        });
      });
    } finally {
      process.umask(prevUmask);
    }
  }

  private handleAdminConnection(socket: Socket): void {
    let buffered = "";
    socket.setEncoding("utf8");
    socket.on("error", () => socket.destroy());
    socket.on("data", (chunk: string) => {
      buffered += chunk;
      if (Buffer.byteLength(buffered, "utf8") > 4096) {
        socket.destroy();
        return;
      }
      let newlineIndex = buffered.indexOf("\n");
      while (newlineIndex !== -1) {
        const line = buffered.slice(0, newlineIndex);
        buffered = buffered.slice(newlineIndex + 1);
        if (line.trim().length > 0) {
          const response = this.handleAdminCommand(line);
          if (!socket.destroyed) socket.write(JSON.stringify(response) + "\n");
        }
        newlineIndex = buffered.indexOf("\n");
      }
    });
  }

  /** Administration commands (§14.6). Exposed for direct testing. */
  handleAdminCommand(line: string): AdminResponse {
    let parsed: AdminCommand;
    try {
      parsed = JSON.parse(line) as AdminCommand;
    } catch {
      return { ok: false, error: "invalid admin command" };
    }
    switch (parsed.command) {
      case "status":
        return {
          ok: true,
          agents: [...this.agents.values()].map((runtime) => ({
            agent: runtime.agent,
            enabled: runtime.enabled,
            policyVersion: runtime.policyVersion,
          })),
        };
      case "disable":
        if (!this.agents.has(parsed.agent)) return { ok: false, error: "unknown agent" };
        this.disableAgent(parsed.agent);
        return { ok: true };
      case "enable":
        if (!this.agents.has(parsed.agent)) return { ok: false, error: "unknown agent" };
        this.enableAgent(parsed.agent);
        return { ok: true };
      default:
        return { ok: false, error: "unsupported admin command" };
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
   * Public entry: run the decision, then record it to the audit log (§16).
   * NEVER throws: every failure maps to a denied response; an audit failure
   * never fails a decision.
   */
  async handleRequest(line: string): Promise<SignResponseJson | ReadResponseJson> {
    // Read-only ops (whoami/query) share the socket and token auth but never
    // touch policy, quota, or the signer. Dispatch them before the sign path.
    const op = peekOp(line);
    if (op !== "sign") return this.handleReadRequest(line);

    const auditCtx: AuditContext = { agent: "unknown", contracts: [] };
    const response = await this.runDecision(line, auditCtx);
    this.recordAudit(response, auditCtx);
    return response;
  }

  /**
   * Handle a read-only request: identity (`whoami`) or a whitelisted chain read
   * (`query`). Authenticated by the same rotating token; NEVER reaches the
   * signer or the policy, and cannot submit a transaction (INV-011).
   */
  private async handleReadRequest(line: string): Promise<ReadResponseJson> {
    let request;
    try {
      request = parseReadRequest(line);
    } catch {
      return { requestId: "unknown", status: "error", op: "query", error: "request does not match the expected schema" };
    }
    const err = (message: string): ReadResponseJson => ({
      requestId: request.requestId,
      status: "error",
      op: request.op,
      error: message,
    });

    try {
      // Same authentication as signing: unknown agent and bad token are
      // indistinguishable (the daemon never reveals which agents exist).
      const runtime = this.agents.get(request.agent);
      if (runtime === undefined || !constantTimeEquals(runtime.token, request.token)) {
        return err("request could not be authenticated");
      }
      if (!runtime.enabled) return err("agent is disabled");

      const now = this.now();
      const requestedAt = Date.parse(request.requestedAt);
      const expiresAt = Date.parse(request.expiresAt);
      if (
        expiresAt <= now ||
        requestedAt > now + this.cfg.maxClockSkewMs ||
        expiresAt <= requestedAt ||
        expiresAt - requestedAt > this.cfg.maxRequestTtlMs
      ) {
        return err("request window is invalid or expired");
      }

      if (request.op === "whoami") {
        // Public identity only — never the key material.
        return {
          requestId: request.requestId,
          status: "ok",
          op: "whoami",
          agent: runtime.agent,
          permission: runtime.permission,
          publicKey: runtime.key.publicKey,
          chain: runtime.chain.chain,
          network: runtime.chain.network,
          chainId: runtime.chain.chainId,
        };
      }

      // op === "query": read-only chain relay.
      if (this.deps.relay === undefined) return err("chain relay is not available");
      if (request.method === undefined) return err("query requires a method");
      const result = await this.deps.relay.call(request.method, request.params ?? {});
      return { requestId: request.requestId, status: "ok", op: "query", method: request.method, result };
    } catch (error) {
      // Fail closed and never leak internals (INV-010).
      return err(error instanceof Error ? error.message : "read request failed");
    }
  }

  private recordAudit(response: SignResponseJson, auditCtx: AuditContext): void {
    const audit = this.deps.audit;
    if (audit === undefined) return;
    try {
      const entry: AuditEntryInput = {
        requestId: response.requestId,
        agent: auditCtx.agent,
        decision: response.status === "signed" ? "signed" : "denied",
        contracts: auditCtx.contracts,
        timestampMs: this.now(),
      };
      if (response.status === "signed") {
        entry.digest = response.transactionDigest;
        entry.policyVersion = response.policyVersion;
        if (auditCtx.ruleIds !== undefined) entry.ruleIds = auditCtx.ruleIds;
      } else {
        entry.code = response.code;
        if (response.policyVersion !== undefined) entry.policyVersion = response.policyVersion;
      }
      audit.append(entry);
    } catch {
      /* auditing must never fail a decision */
    }
  }

  /**
   * The decision pipeline (§13). NEVER throws: every failure maps to a denied
   * response. Populates `auditCtx` as the decision unfolds.
   */
  private async runDecision(line: string, auditCtx: AuditContext): Promise<SignResponseJson> {
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
    auditCtx.agent = request.agent;

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

      // Anti-replay, namespaced per agent so one agent cannot exhaust another's
      // nonce budget (cross-agent DoS on anti-replay).
      const nonceState = this.nonces.register(runtime.agent, request.nonce, expiresAt, now);
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

      // Load the active policy. With a cache configured, the on-chain policy
      // is the source of truth (§14.1): anti-rollback + freshness apply, and
      // an unconfirmable policy fails closed. Without one (tests/dev), the
      // statically registered policy is used.
      let activePolicy = runtime.policy;
      let activeVersion = runtime.policyVersion;
      if (this.deps.policyCache !== undefined) {
        const cached = await this.deps.policyCache.get(runtime.agent, now);
        if ("unavailable" in cached) {
          return deny("POLICY_UNAVAILABLE", "policy could not be confirmed on-chain");
        }
        // On-chain disable is a second, canonical kill-switch alongside the
        // local one already checked above (§14.6).
        if (!cached.enabled) {
          return deny("AGENT_DISABLED", "agent is disabled on-chain");
        }
        activePolicy = cached.policy;
        activeVersion = cached.version;
      }

      // Decode: INV-014/INV-003 enforcement lives in the ChainAdapter.
      let decoded: DecodedTransaction;
      try {
        decoded = this.deps.decode(request.transaction, chain);
      } catch {
        return deny("SCHEMA_INVALID", "transaction could not be fully decoded");
      }
      // Contract::action names only — never the data values (§16).
      auditCtx.contracts = decoded.actions.map((a) => `${a.contract}::${a.action}`);

      // Resolve any deterministic async providers (§8.4) BEFORE evaluation, so
      // the engine stays pure: list the queries, read them through the relay
      // (fail closed), and inject the evidence. No providers → no I/O.
      const baseCtx = {
        agent: runtime.agent,
        agentPermission: runtime.permission,
        chainId: chain.chainId,
        policyVersion: activeVersion,
      };
      const queries = collectProviderQueries(decoded, activePolicy, baseCtx);
      const evidence =
        queries.length > 0 ? await resolveProviders(queries, this.deps.relay) : undefined;

      // Deterministic policy evaluation.
      const { decision, quotaDemands } = evaluatePolicy(
        decoded,
        activePolicy,
        evidence !== undefined ? { ...baseCtx, evidence } : baseCtx,
      );

      if (decision.effect === "deny") {
        return deny(decision.code, decision.safeReason, decision.policyVersion);
      }
      auditCtx.ruleIds = decision.ruleIds;

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

      const commit = (): void => {
        if (reservationId !== undefined) {
          this.deps.quotas?.commit(reservationId, runtime.agent, signed.transactionDigest);
        }
      };
      const release = (): void => {
        if (reservationId !== undefined) this.deps.quotas?.release(reservationId);
      };
      const quotaState = (fate: "committed" | "released"): "committed" | "released" | "none" =>
        reservationId === undefined ? "none" : fate;

      // Daemon-owned submit path (§13): SignBox broadcasts and the signature
      // never leaves. The reserved quota follows the CHAIN outcome, not the
      // mere fact of signing — so a tx rejected on-chain frees its quota.
      if (request.broadcast === true && this.deps.broadcaster !== undefined) {
        const outcome = await this.deps.broadcaster.broadcast(signed.signedTransaction);
        let report: BroadcastReport;
        if (outcome.status === "accepted") {
          commit();
          report = { status: "accepted", receipt: outcome.receipt, quota: quotaState("committed") };
        } else if (outcome.status === "rejected") {
          // Deterministic rejection: tx did not land, bytes discarded here →
          // releasing the reservation cannot enable a replay/double-spend.
          release();
          report = { status: "rejected", reason: outcome.reason, quota: quotaState("released") };
        } else {
          // Ambiguous: it may have landed → keep the quota (fail closed).
          commit();
          report = { status: "ambiguous", reason: outcome.reason, quota: quotaState("committed") };
        }
        // The signed bytes are NEVER returned on the submit path.
        return {
          requestId: request.requestId,
          status: "signed",
          signature: signed.signature,
          transactionDigest: signed.transactionDigest,
          policyVersion: decision.policyVersion,
          broadcast: report,
        };
      }

      // Plain sign (or no broadcaster available): the signature becomes a
      // bearer credential the moment it is returned, so it commits on signing.
      commit();
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
