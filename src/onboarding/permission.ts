/**
 * Generates a valid, dedicated Antelope permission name for an agent
 * (spec §10.2 step 5). Antelope names use a-z, 1-5 and dots, ≤ 12 chars.
 * We use a "sbx" prefix + random suffix from the name alphabet.
 */

import { randomInt } from "node:crypto";

const NAME_ALPHABET = "abcdefghijklmnopqrstuvwxyz12345";

export function generatePermissionName(): string {
  let suffix = "";
  for (let i = 0; i < 6; i++) {
    suffix += NAME_ALPHABET[randomInt(NAME_ALPHABET.length)];
  }
  return `sbx${suffix}`;
}
