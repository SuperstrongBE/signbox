import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// @proton/link expects a few Node globals in the browser; provide them.
export default defineConfig({
  plugins: [react()],
  define: { global: "globalThis" },
  server: { port: 5173 },
  resolve: { alias: { buffer: "buffer" } },
});
