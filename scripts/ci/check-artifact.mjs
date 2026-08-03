#!/usr/bin/env node
/**
 * Release-artifact gate (see .github/workflows/security.yml).
 *
 * Runs `npm pack --dry-run --json` and verifies the tarball that would be
 * published:
 *  - every file matches the ALLOWLIST (the package.json `files` whitelist,
 *    plus npm's always-included package.json),
 *  - no file matches the FORBIDDEN patterns (keys, tokens, env, fixtures),
 *  - the two CLI entrypoints are actually present.
 *
 * Fails loudly with the offending paths; exits 0 when clean.
 */

import { execFileSync } from "node:child_process";

const ALLOWED = [
  /^dist\//,
  /^README\.md$/,
  /^llms\.txt$/,
  /^llms-full\.txt$/,
  /^package\.json$/,
];

const FORBIDDEN = [
  /\.env(\.|$)/i,
  /\.keystore\.json$/i, // sealed key containers — never code under dist/keystore/
  /\.token$/i,
  /\.pem$/i,
  /id_(rsa|ed25519|ecdsa)/i,
  /\.signbox/i,
  /^test\//,
  /\.(spec|test)\.[cm]?[jt]s$/,
];

const REQUIRED = ["dist/cli/index.js", "dist/mcp/index.js"];

const raw = execFileSync("npm", ["pack", "--dry-run", "--json"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"], // keep prepack build noise off stdout
});
const [report] = JSON.parse(raw);
const files = report.files.map((f) => f.path);

const notAllowed = files.filter((p) => !ALLOWED.some((re) => re.test(p)));
const forbidden = files.filter((p) => FORBIDDEN.some((re) => re.test(p)));
const missing = REQUIRED.filter((p) => !files.includes(p));

let failed = false;
if (notAllowed.length > 0) {
  failed = true;
  console.error(`✗ files outside the allowlist:\n  ${notAllowed.join("\n  ")}`);
}
if (forbidden.length > 0) {
  failed = true;
  console.error(`✗ forbidden files in the tarball:\n  ${forbidden.join("\n  ")}`);
}
if (missing.length > 0) {
  failed = true;
  console.error(`✗ required entrypoints missing:\n  ${missing.join("\n  ")}`);
}

if (failed) process.exit(1);
console.log(`✓ artifact clean — ${files.length} files, all allowlisted, entrypoints present`);
