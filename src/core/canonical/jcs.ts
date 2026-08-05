/**
 * RFC 8785 — JSON Canonicalization Scheme (JCS) (spec §8.6).
 *
 * Properties relied upon by SignBox:
 * - object keys sorted by UTF-16 code units (Array.prototype.sort default);
 * - string escaping identical to JSON.stringify (RFC 8785 mandates the
 *   ECMAScript JSON.stringify serialization);
 * - numbers serialized with the ECMAScript Number-to-string algorithm
 *   (JSON.stringify on a finite number);
 * - no whitespace.
 *
 * Any canonicalization divergence produces a hash mismatch, hence a refusal
 * (fail closed) — never a tolerance.
 *
 * PURE module (no Node APIs): it is imported by the web editor too, so the
 * daemon and the companion canonicalize with the SAME function — parity by
 * construction, not by hand-kept copies (#45). Hashing lives in ./hash.ts.
 */

import { CanonicalizationError } from "../errors.js";

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new CanonicalizationError("non-finite numbers cannot be canonicalized");
      }
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object": {
      if (Array.isArray(value)) {
        return `[${value.map((item) => canonicalize(item === undefined ? null : item)).join(",")}]`;
      }
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort();
      const members: string[] = [];
      for (const key of keys) {
        const member = record[key];
        // JSON.stringify drops undefined members; JCS canonicalizes the
        // stringified form, so we do the same.
        if (member === undefined) continue;
        members.push(`${JSON.stringify(key)}:${canonicalize(member)}`);
      }
      return `{${members.join(",")}}`;
    }
    default:
      throw new CanonicalizationError(`unsupported type: ${typeof value}`);
  }
}
