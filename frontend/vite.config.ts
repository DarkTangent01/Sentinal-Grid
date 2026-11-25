import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// npm run build:grid / build:nms (VITE_PRODUCT + mode) builds one product's app into dist-grid / dist-nms;
// the default mode builds today's combined app into dist (docs/architecture/FRONTEND_SEPARATION.md).
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": { target: "http://127.0.0.1:8000", ws: true } } },
  build: { outDir: mode === "grid" || mode === "nms" ? `dist-${mode}` : "dist", sourcemap: false, chunkSizeWarningLimit: 1500 },
}));
