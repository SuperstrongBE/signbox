/**
 * Config resolution (§11) — chain-generalized since #44 A.3: the `chain`
 * field resolves through the registry, and chain-specific value shapes
 * (chain id, registry locator) are validated by the chain module's patterns.
 */

import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, DEFAULT_CHAIN } from "../src/cli/config.js";
import { ValidationError } from "../src/core/errors.js";

const XPR_TESTNET_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";

function writeConfig(value: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "signbox-config-"));
  const path = join(dir, "config.json");
  writeFileSync(path, JSON.stringify(value));
  return path;
}

describe("loadConfig — chain resolution through the registry", () => {
  it("defaults to XPR testnet with the pinned chain id (zero-config)", () => {
    const config = loadConfig(writeConfig({}));
    expect(config.chain).toBe(DEFAULT_CHAIN);
    expect(config.network).toBe("testnet");
    expect(config.chainId).toBe(XPR_TESTNET_ID);
    expect(config.endpoints.length).toBeGreaterThan(0);
    expect(config.signboxContract).toBe("signbox");
  });

  it("accepts an explicit registered chain", () => {
    const config = loadConfig(writeConfig({ chain: "XPR" }));
    expect(config.chain).toBe("XPR");
  });

  it("refuses an unregistered chain, naming the registered ones", () => {
    expect(() => loadConfig(writeConfig({ chain: "SUI" }))).toThrowError(
      /unsupported chain "SUI".*registered: XPR/,
    );
  });

  it("refuses a chainId that does not match the module's format", () => {
    expect(() => loadConfig(writeConfig({ chainId: "0xabc" }))).toThrowError(
      /chain-id format/,
    );
    // Valid 64-hex passes even when it isn't a known network's id (explicit pin).
    const config = loadConfig(writeConfig({ chainId: "a".repeat(64) }));
    expect(config.chainId).toBe("a".repeat(64));
  });

  it("refuses a registry locator that does not match the module's format", () => {
    expect(() => loadConfig(writeConfig({ signboxContract: "NotAnAntelopeName" }))).toThrowError(
      /registry-locator format/,
    );
  });

  it("still refuses unknown config keys (strict schema)", () => {
    expect(() => loadConfig(writeConfig({ agents: [] }))).toThrowError(ValidationError);
  });

  it("refuses an unknown network with no explicit chainId", () => {
    expect(() => loadConfig(writeConfig({ network: "devnet" }))).toThrowError(
      /unknown network "devnet"/,
    );
  });
});
