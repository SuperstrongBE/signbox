/**
 * Official SignBox MCP server (spec §11.7).
 *
 * Exposes the MINIMAL, safe surface to an LLM agent: inspect, explain, sign,
 * list/info, and (only when explicitly enabled) push. It deliberately does
 * NOT expose administrative creation, key export, policy modification or
 * rotation — those are the authority's, via an external wallet (INV-005).
 *
 * The server is a CLIENT of the running daemon for signing (it holds no key
 * and evaluates no policy on the sign path); inspect decodes locally, explain
 * evaluates the on-chain policy as a dry run (no signing, no quota reserve).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { join } from "node:path";
import { getChain } from "../chains/index.js";
import { validatePolicy } from "../core/policy/schema.js";
import { evaluatePolicy } from "../core/policy/engine.js";
import { canonicalize } from "../core/canonical/jcs.js";
import { readKeystoreMetadata } from "../keystore/encryptedFile.js";
import { signViaDaemon, broadcastViaDaemon, readToken } from "../cli/client.js";
import { discoverKeystores } from "../cli/daemonRunner.js";
import { chainContextOf, type SignBoxConfig } from "../cli/config.js";
import { createHash } from "node:crypto";

interface ToolResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
  [key: string]: unknown;
}

function ok(value: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

function err(message: string): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify({ error: message }, null, 2) }], isError: true };
}

export interface McpOptions {
  /** Broadcasting is off by default (§11.7, open question #1). */
  enablePush: boolean;
}

export function buildMcpServer(config: SignBoxConfig, options: McpOptions): McpServer {
  const server = new McpServer({ name: "signbox", version: "0.1.0" });
  const context = chainContextOf(config);
  // Chain implementations resolve through the registry (issue #44).
  const chainModule = getChain(config.chain);
  const wiring = { endpoints: config.endpoints, chainId: config.chainId };

  server.registerTool(
    "signbox_agent_list",
    {
      description:
        "List the agents this SignBox daemon can sign for. Public metadata only; never a secret.",
      inputSchema: {},
    },
    async (): Promise<ToolResult> => {
      const agents = discoverKeystores(config.keystoreDir).map((path) => {
        const meta = readKeystoreMetadata(path);
        return {
          agent: meta.agent,
          permission: meta.permission,
          publicKey: meta.publicKey,
          chain: meta.chain.chain,
          network: meta.chain.network,
        };
      });
      return ok({ agents });
    },
  );

  server.registerTool(
    "signbox_agent_info",
    {
      description: "Public info for one agent (permission, public key, chain). Never a secret.",
      inputSchema: { agent: z.string() },
    },
    async ({ agent }): Promise<ToolResult> => {
      const path = discoverKeystores(config.keystoreDir).find(
        (p) => readKeystoreMetadata(p).agent === agent,
      );
      if (path === undefined) return err(`unknown agent: ${agent}`);
      const meta = readKeystoreMetadata(path);
      return ok({
        agent: meta.agent,
        permission: meta.permission,
        publicKey: meta.publicKey,
        chain: meta.chain,
        exportPolicy: meta.exportPolicy,
      });
    },
  );

  server.registerTool(
    "signbox_transaction_inspect",
    {
      description:
        "Decode a raw unserialized JSON transaction into its actions. No policy, no signature.",
      inputSchema: { transaction: z.unknown() },
    },
    async ({ transaction }): Promise<ToolResult> => {
      try {
        const decoded = chainModule.decode(transaction, context);
        return ok({ context: decoded.context, actions: decoded.actions });
      } catch (error) {
        return err((error as Error).message);
      }
    },
  );

  server.registerTool(
    "signbox_transaction_explain",
    {
      description:
        "Evaluate an agent's on-chain policy against a transaction WITHOUT signing. Stateful " +
        "quota limits are not checked here — sign is authoritative.",
      inputSchema: { agent: z.string(), transaction: z.unknown() },
    },
    async ({ agent, transaction }): Promise<ToolResult> => {
      try {
        const meta = agentMeta(config, agent);
        if (meta === undefined) return err(`unknown agent: ${agent}`);
        const reader = chainModule.createPolicyReader(wiring, config.signboxContract);
        const row = await reader.read(agent);
        if (row === null) return ok({ decision: { effect: "deny", code: "POLICY_UNAVAILABLE" } });
        const computed = createHash("sha256").update(Buffer.from(row.policyjson, "utf8")).digest("hex");
        if (computed !== row.policyhash || canonicalize(JSON.parse(row.policyjson)) !== row.policyjson) {
          return ok({ decision: { effect: "deny", code: "POLICY_UNAVAILABLE" } });
        }
        const policy = validatePolicy(JSON.parse(row.policyjson), chainModule.dialect);
        const decoded = chainModule.decode(transaction, context);
        const { decision } = evaluatePolicy(decoded, policy, {
          agent,
          agentPermission: meta.permission,
          chainId: config.chainId,
          policyVersion: row.version,
          dialect: chainModule.dialect,
        });
        return ok({ decision, note: "dry run — stateful quotas are enforced at sign time" });
      } catch (error) {
        return err((error as Error).message);
      }
    },
  );

  server.registerTool(
    "signbox_transaction_sign",
    {
      description:
        "Ask the running SignBox daemon to sign a transaction for an agent. Returns a signed " +
        "transaction or a refusal. Never broadcasts.",
      inputSchema: { agent: z.string(), transaction: z.unknown() },
    },
    async ({ agent, transaction }): Promise<ToolResult> => {
      try {
        const token = readToken(join(config.tokenDir, `${agent}.token`));
        const response = await signViaDaemon({
          socketPath: config.socketPath,
          agent,
          context,
          transaction,
          token,
        });
        return ok(response);
      } catch (error) {
        return err((error as Error).message);
      }
    },
  );

  if (options.enablePush) {
    server.registerTool(
      "signbox_transaction_push",
      {
        description:
          "Ask the running SignBox daemon to submit an already-signed transaction. Requires the " +
          "agent's broadcast capability; never signs. Returns the submission outcome or a refusal.",
        inputSchema: { agent: z.string(), signedTransaction: z.unknown() },
      },
      async ({ agent, signedTransaction }): Promise<ToolResult> => {
        try {
          const token = readToken(join(config.tokenDir, `${agent}.token`));
          const response = await broadcastViaDaemon({
            socketPath: config.socketPath,
            agent,
            context,
            signedTransaction,
            token,
          });
          return ok(response);
        } catch (error) {
          return err((error as Error).message);
        }
      },
    );
  }

  return server;
}

function agentMeta(config: SignBoxConfig, agent: string) {
  const path = discoverKeystores(config.keystoreDir).find(
    (p) => readKeystoreMetadata(p).agent === agent,
  );
  return path === undefined ? undefined : readKeystoreMetadata(path);
}
