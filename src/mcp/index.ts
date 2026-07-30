#!/usr/bin/env node
/**
 * SignBox MCP server entry point (stdio transport).
 *
 * MCP speaks JSON-RPC over stdio, so NOTHING may be written to stdout except
 * the protocol. All diagnostics go to stderr.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildMcpServer } from "./server.js";
import { loadConfig, DEFAULT_CONFIG_PATH } from "../cli/config.js";

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const configFlag = args.indexOf("--config");
  const configPath = configFlag !== -1 ? args[configFlag + 1] ?? DEFAULT_CONFIG_PATH : DEFAULT_CONFIG_PATH;
  const enablePush = args.includes("--enable-push") || process.env["SIGNBOX_MCP_ENABLE_PUSH"] === "1";

  const config = loadConfig(configPath);
  const server = buildMcpServer(config, { enablePush });

  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(
    `signbox MCP server ready (network=${config.network}, push=${enablePush ? "enabled" : "disabled"})\n`,
  );
}

main().catch((error: unknown) => {
  process.stderr.write(`signbox-mcp fatal: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
