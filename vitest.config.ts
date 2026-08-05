import { defineConfig } from "vitest/config";

/**
 * The root test runner covers the TypeScript daemon only (test/*.test.ts).
 * The on-chain contract is a separate sub-project with its own toolchain and
 * test runner (contract/, mocha + @proton/vert): its *.spec.ts must never be
 * picked up here — its deps and built WASM live under contract/, not at root.
 */
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["**/node_modules/**", "dist/**", "contract/**"],
    // The keystore suites derive Argon2id MODERATE keys (256 MiB, ~1-2s each)
    // by design; under full-suite parallelism they overrun the 5s default.
    testTimeout: 60_000,
  },
});
