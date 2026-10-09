import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@fixtures": fileURLToPath(new URL("../fixtures/api", import.meta.url)) } },
  // /v1 proxy: `npm run dev:3d` serves the console on :5175 and reaches the API through this same origin, so the
  // running stack's CORS list does not need :5175. The normal :5173 build calls the API directly and ignores it.
  server: { port: 5173, fs: { allow: [".."] }, proxy: { "/v1": { target: "http://localhost:8000", ws: true } } },
});
