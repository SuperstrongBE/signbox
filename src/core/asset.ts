/**
 * Asset amounts as integers of minimal units (spec §8.6).
 *
 * A money amount is NEVER a JavaScript number. Every amount is
 * (units: bigint, symbol, precision), and two amounts are only comparable
 * when their symbol AND precision match exactly. Any mismatch is an
 * ambiguity, and ambiguity means refusal (INV-010).
 *
 * Symbol identity at the policy level is the (contract, symbol, precision)
 * triplet; contract matching is enforced by the rule's `contract` field,
 * symbol and precision are enforced here.
 */

import { AssetError } from "./errors.js";

/** Antelope max asset amount: 2^62 - 1 minimal units. */
export const MAX_ASSET_UNITS = 2n ** 62n - 1n;

/** Antelope symbol code: 1-7 uppercase ASCII letters. Nothing else. */
const SYMBOL_RE = /^[A-Z]{1,7}$/;

/** Strict asset string: "<digits>[.<digits>] <SYMBOL>", single space, no sign. */
const ASSET_RE = /^(\d+)(?:\.(\d+))? ([A-Z]{1,7})$/;

/** Strict bare amount string: "<digits>[.<digits>]", no sign, no symbol. */
const BARE_AMOUNT_RE = /^(\d+)(?:\.(\d+))?$/;

export const MAX_PRECISION = 18;

export interface AssetAmount {
  units: bigint;
  symbol: string;
  precision: number;
}

export interface BareAmount {
  units: bigint;
  precision: number;
}

function toUnits(intPart: string, fracPart: string | undefined, context: string): BareAmount {
  const precision = fracPart?.length ?? 0;
  if (precision > MAX_PRECISION) {
    throw new AssetError(`${context}: precision ${precision} exceeds maximum ${MAX_PRECISION}`);
  }
  const units = BigInt(intPart + (fracPart ?? ""));
  if (units > MAX_ASSET_UNITS) {
    throw new AssetError(`${context}: amount exceeds maximum representable value`);
  }
  return { units, precision };
}

/**
 * Parse a strict asset string such as "1000.0000 XPR".
 * Rejects: signs, homograph/non-ASCII symbols, lowercase, multiple spaces,
 * missing symbol, overflow. Precision is defined by the written decimals.
 */
export function parseAsset(input: string): AssetAmount {
  const match = ASSET_RE.exec(input);
  if (match === null) {
    throw new AssetError("invalid asset string");
  }
  const [, intPart, fracPart, symbol] = match;
  if (intPart === undefined || symbol === undefined || !SYMBOL_RE.test(symbol)) {
    throw new AssetError("invalid asset string");
  }
  const { units, precision } = toUnits(intPart, fracPart, "asset");
  return { units, symbol, precision };
}

/** Parse a bare amount string such as "1000.0000" (no symbol). */
export function parseBareAmount(input: string): BareAmount {
  const match = BARE_AMOUNT_RE.exec(input);
  if (match === null) {
    throw new AssetError("invalid amount string");
  }
  const [, intPart, fracPart] = match;
  if (intPart === undefined) {
    throw new AssetError("invalid amount string");
  }
  return toUnits(intPart, fracPart, "amount");
}

export function formatAsset(asset: AssetAmount): string {
  return `${formatBareAmount(asset)} ${asset.symbol}`;
}

export function formatBareAmount(amount: BareAmount): string {
  const digits = amount.units.toString().padStart(amount.precision + 1, "0");
  if (amount.precision === 0) return digits;
  const split = digits.length - amount.precision;
  return `${digits.slice(0, split)}.${digits.slice(split)}`;
}

/**
 * Compare two amounts of the SAME precision. A precision mismatch is an
 * ambiguity, not a coercion — the caller must treat the thrown AssetError
 * as a refusal.
 */
export function compareBareAmounts(a: BareAmount, b: BareAmount): -1 | 0 | 1 {
  if (a.precision !== b.precision) {
    throw new AssetError(`precision mismatch: ${a.precision} vs ${b.precision}`);
  }
  if (a.units < b.units) return -1;
  if (a.units > b.units) return 1;
  return 0;
}

/**
 * Compare two assets. Symbol or precision mismatch throws — comparing
 * "1.0000 XPR" with "1.000000 XUSDC" (or even "1.000 XPR") is meaningless
 * and must refuse, never coerce.
 */
export function compareAssets(a: AssetAmount, b: AssetAmount): -1 | 0 | 1 {
  if (a.symbol !== b.symbol) {
    throw new AssetError(`symbol mismatch: ${a.symbol} vs ${b.symbol}`);
  }
  return compareBareAmounts(a, b);
}
