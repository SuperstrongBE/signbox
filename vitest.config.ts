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
  },
});
