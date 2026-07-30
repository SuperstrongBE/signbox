import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildMcpServer } from "../src/mcp/server.js";
import { generateK1KeyPair } from "../src/chains/xpr/keygen.js";
import { createKeystoreFile } from "../src/keystore/encryptedFile.js";
import type { SignBoxConfig } from "../src/cli/config.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";

let dir: string;
let config: SignBoxConfig;
let client: Client;
let publicKey: string;

async function connectClient(enablePush = false): Promise<Client> {
  const server = buildMcpServer(config, { enablePush });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const c = new Client({ name: "test", version: "0" });
  await Promise.all([server.connect(serverTransport), c.connect(clientTransport)]);
  return c;
}

/** Extract the JSON text a SignBox tool returns. */
function payload(result: unknown): unknown {
  const content = (result as { content: { type: string; text: string }[] }).content;
  return JSON.parse(content[0]!.text);
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "signbox-mcp-"));
  const keystoreDir = join(dir, "keystores");
  mkdirSync(keystoreDir, { recursive: true });
  const pair = await generateK1KeyPair();
  publicKey = pair.publicKey;
  const secret = Buffer.from(pair.wif, "utf8");
  createKeystoreFile(join(keystoreDir, "superagent.keystore.json"), secret, Buffer.from("pw"), {
    publicKey: pair.publicKey,
    exportPolicy: "non-exportable",
    chain: { chain: "XPR", network: "testnet", chainId: CHAIN_ID },
    agent: "superagent",
    permission: "xp2vr3",
    createdAt: "2026-07-30T00:00:00.000Z",
  });
  secret.fill(0);

  config = {
    chain: "XPR",
    network: "testnet",
    chainId: CHAIN_ID,
    endpoints: ["http://127.0.0.1:1"],
    signboxContract: "signbox",
    baseDir: dir,
    keystoreDir,
    tokenDir: join(dir, "tokens"),
    socketPath: join(dir, "s.sock"),
    adminSocketPath: join(dir, "s.admin.sock"),
    stateDbPath: join(dir, "state.db"),
  };
});

afterEach(async () => {
  await client?.close();
});

describe("SignBox MCP server", () => {
  it("exposes the minimal safe tool surface (no admin/export/rotate)", async () => {
    client = await connectClient();
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([
      "signbox_agent_info",
      "signbox_agent_list",
      "signbox_transaction_explain",
      "signbox_transaction_inspect",
      "signbox_transaction_sign",
    ]);
    // Never these:
    expect(names).not.toContain("signbox_transaction_push");
    expect(names.some((n) => /create|rotate|export|policy_set|admin/.test(n))).toBe(false);
  });

  it("lists agents from keystores without any secret", async () => {
    client = await connectClient();
    const result = await client.callTool({ name: "signbox_agent_list", arguments: {} });
    const data = payload(result) as { agents: { agent: string; publicKey: string }[] };
    expect(data.agents).toHaveLength(1);
    expect(data.agents[0]).toMatchObject({ agent: "superagent", publicKey });
    expect(JSON.stringify(data)).not.toMatch(/PVT_|passphrase/);
  });

  it("inspects a transaction (decode only)", async () => {
    client = await connectClient();
    const result = await client.callTool({
      name: "signbox_transaction_inspect",
      arguments: {
        transaction: {
          actions: [
            {
              account: "eosio.token",
              name: "transfer",
              authorization: [{ actor: "superagent", permission: "xp2vr3" }],
              data: { from: "superagent", to: "alice", quantity: "1.0000 XPR", memo: "" },
            },
          ],
        },
      },
    });
    const data = payload(result) as { actions: { contract: string }[] };
    expect(data.actions[0]!.contract).toBe("eosio.token");
  });

  it("rejects a packed-transaction inspect (INV-014) as a tool error", async () => {
    client = await connectClient();
    const result = await client.callTool({
      name: "signbox_transaction_inspect",
      arguments: { transaction: "aabbcc001122" },
    });
    expect((result as { isError?: boolean }).isError).toBe(true);
  });

  it("registers the push tool only when explicitly enabled", async () => {
    client = await connectClient(true);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toContain("signbox_transaction_push");
  });
});
