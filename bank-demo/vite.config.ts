import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@fixtures": fileURLToPath(new URL("../fixtures/api", import.meta.url)) } },
  server: { port: 5174, fs: { allow: [".."] } },
});
