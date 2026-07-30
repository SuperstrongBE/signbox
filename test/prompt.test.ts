import { describe, expect, it } from "vitest";
import { isInteractive, validateAccountName } from "../src/cli/prompt.js";

describe("account name validation", () => {
  it("accepts valid Antelope names", () => {
    for (const name of ["superdev", "superagent", "a", "xp2vr3", "eosio.token", "12345"]) {
      expect(validateAccountName(name)).toBeNull();
    }
  });

  it("rejects invalid names", () => {
    for (const name of ["", "UPPER", "waytoolongname12", "with space", "with-dash", "with_underscore", "abc6"]) {
      expect(validateAccountName(name)).not.toBeNull();
    }
  });
});

describe("isInteractive", () => {
  it("is false when stdin is not a TTY (e.g. test runner / piped input)", () => {
    // In the test runner stdin is not a TTY, so onboarding falls back to
    // flags/defaults and never blocks on a prompt.
    expect(isInteractive()).toBe(false);
  });
});
