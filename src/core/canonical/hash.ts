/**
 * Canonical hashing (spec §8.6) — Node side of ./jcs.ts. Split out so the
 * pure canonicalizer stays importable by the web editor (no node:crypto).
 */

import { createHash } from "node:crypto";
import { canonicalize } from "./jcs.js";

/** SHA-256 of the canonical UTF-8 bytes, lowercase hex (used for policyHash). */
export function canonicalSha256Hex(value: unknown): string {
  return createHash("sha256").update(Buffer.from(canonicalize(value), "utf8")).digest("hex");
}
