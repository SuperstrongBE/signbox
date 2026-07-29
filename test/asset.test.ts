import { describe, expect, it } from "vitest";
import {
  MAX_ASSET_UNITS,
  compareAssets,
  compareBareAmounts,
  formatAsset,
  parseAsset,
  parseBareAmount,
} from "../src/core/asset.js";
import { AssetError } from "../src/core/errors.js";

describe("asset parsing", () => {
  it("parses a strict asset string into integer minimal units", () => {
    expect(parseAsset("1000.0000 XPR")).toEqual({ units: 10_000_000n, symbol: "XPR", precision: 4 });
    expect(parseAsset("0.0001 XPR")).toEqual({ units: 1n, symbol: "XPR", precision: 4 });
    expect(parseAsset("5 FOO")).toEqual({ units: 5n, symbol: "FOO", precision: 0 });
  });

  it("round-trips through formatting", () => {
    for (const s of ["1000.0000 XPR", "0.0001 XPR", "5 FOO", "0.000000 XUSDC"]) {
      expect(formatAsset(parseAsset(s))).toBe(s);
    }
  });

  it("rejects negative amounts", () => {
    expect(() => parseAsset("-1.0000 XPR")).toThrow(AssetError);
  });

  it("rejects malformed strings", () => {
    expect(() => parseAsset("1.0000XPR")).toThrow(AssetError); // missing space
    expect(() => parseAsset("1.0000  XPR")).toThrow(AssetError); // double space
    expect(() => parseAsset("1,0000 XPR")).toThrow(AssetError); // comma
    expect(() => parseAsset(".5 XPR")).toThrow(AssetError); // no integer part
    expect(() => parseAsset("1.0000 xpr")).toThrow(AssetError); // lowercase
    expect(() => parseAsset("1.0000")).toThrow(AssetError); // no symbol
    expect(() => parseAsset("1e4 XPR")).toThrow(AssetError); // exponent
    expect(() => parseAsset("+1.0000 XPR")).toThrow(AssetError); // sign
  });

  it("rejects homograph symbols (§17.4)", () => {
    // "ХРR" uses Cyrillic Kha and Er — visually identical to "XPR".
    expect(() => parseAsset("1.0000 ХРR")).toThrow(AssetError);
  });

  it("rejects overflow beyond 2^62-1 minimal units", () => {
    expect(() => parseAsset(`${MAX_ASSET_UNITS + 1n} FOO`)).toThrow(AssetError);
    expect(parseAsset(`${MAX_ASSET_UNITS} FOO`).units).toBe(MAX_ASSET_UNITS);
  });

  it("rejects excessive precision", () => {
    expect(() => parseAsset("1.0000000000000000000 XPR")).toThrow(AssetError);
  });
});

describe("asset comparison", () => {
  it("compares only when symbol AND precision match", () => {
    expect(compareAssets(parseAsset("1.0000 XPR"), parseAsset("2.0000 XPR"))).toBe(-1);
    expect(compareAssets(parseAsset("2.0000 XPR"), parseAsset("2.0000 XPR"))).toBe(0);
  });

  it("throws on symbol mismatch — never coerces", () => {
    expect(() => compareAssets(parseAsset("1.0000 XPR"), parseAsset("1.0000 XUSDC"))).toThrow(
      AssetError,
    );
  });

  it("throws on precision mismatch — incorrect decimals attack (§17.4)", () => {
    expect(() => compareAssets(parseAsset("1.0000 XPR"), parseAsset("1.000 XPR"))).toThrow(
      AssetError,
    );
    expect(() =>
      compareBareAmounts(parseBareAmount("1000.00000"), parseBareAmount("1000.0000")),
    ).toThrow(AssetError);
  });

  it("never uses floating point (precision beyond double)", () => {
    // 0.30000000000000004-style artifacts are impossible with bigint units.
    const a = parseBareAmount("9007199254740993"); // 2^53 + 1: not representable as a double
    expect(a.units).toBe(9007199254740993n);
  });
});
