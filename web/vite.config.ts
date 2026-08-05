import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// The daemon's PURE core modules (canonicalize, policy vocabulary) are
// imported directly by the editor — same source, parity by construction (#45).
const coreDir = fileURLToPath(new URL("../src/core", import.meta.url));

// @proton/link expects a few Node globals in the browser; provide them.
export default defineConfig({
  plugins: [react()],
  define: { global: "globalThis" },
  server: { port: 5173, fs: { allow: [".", "../src/core"] } },
  resolve: { alias: { buffer: "buffer", "@sbx-core": coreDir } },
});
