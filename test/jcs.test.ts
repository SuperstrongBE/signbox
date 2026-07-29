import { describe, expect, it } from "vitest";
import { canonicalize, canonicalSha256Hex } from "../src/core/canonical/jcs.js";
import { CanonicalizationError } from "../src/core/errors.js";

describe("RFC 8785 canonicalization", () => {
  it("sorts object keys by UTF-16 code units", () => {
    expect(canonicalize({ b: 1, a: 2, A: 3 })).toBe('{"A":3,"a":2,"b":1}');
  });

  it("produces the same output regardless of key insertion order", () => {
    const a = { from: "x", quantity: "1.0000 XPR", to: "y" };
    const b = { to: "y", from: "x", quantity: "1.0000 XPR" };
    expect(canonicalize(a)).toBe(canonicalize(b));
    expect(canonicalSha256Hex(a)).toBe(canonicalSha256Hex(b));
  });

  it("emits no whitespace and canonical primitives", () => {
    expect(canonicalize({ n: 1, s: "a", t: true, z: null, arr: [1, 2] })).toBe(
      '{"arr":[1,2],"n":1,"s":"a","t":true,"z":null}',
    );
  });

  it("serializes numbers with the ECMAScript algorithm", () => {
    expect(canonicalize(1000000000000000000000)).toBe("1e+21");
    expect(canonicalize(0.000001)).toBe("0.000001");
    expect(canonicalize(10)).toBe("10");
  });

  it("escapes strings like JSON.stringify", () => {
    expect(canonicalize("a\nb\"c\\")).toBe('"a\\nb\\"c\\\\"');
    expect(canonicalize("")).toBe('"\\u0007"');
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalize(Number.NaN)).toThrow(CanonicalizationError);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(CanonicalizationError);
  });

  it("rejects functions and bigints", () => {
    expect(() => canonicalize(() => 1)).toThrow(CanonicalizationError);
    expect(() => canonicalize(1n)).toThrow(CanonicalizationError);
  });

  it("drops undefined object members and nullifies undefined array items", () => {
    expect(canonicalize({ a: undefined, b: 1 })).toBe('{"b":1}');
    expect(canonicalize([undefined, 1])).toBe("[null,1]");
  });
});
