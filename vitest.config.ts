import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

/**
 * The root test runner covers the TypeScript daemon only (test/*.test.ts).
 * The on-chain contract is a separate sub-project with its own toolchain and
 * test runner (contract/, mocha + @proton/vert): its *.spec.ts must never be
 * picked up here — its deps and built WASM live under contract/, not at root.
 *
 * The `@sbx-core` alias mirrors web/vite.config.ts so a root test can exercise
 * the shared policy-core the web editor imports (e.g. the lossless-load guard,
 * test/editor-roundtrip.test.ts, imports web editor modules that use it).
 */
export default defineConfig({
  resolve: {
    alias: {
      "@sbx-core": fileURLToPath(new URL("./src/core", import.meta.url)),
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["**/node_modules/**", "dist/**", "contract/**"],
    // The keystore suites derive Argon2id MODERATE keys (256 MiB, ~1-2s each)
    // by design; under full-suite parallelism they overrun the 5s default.
    testTimeout: 60_000,
  },
});
