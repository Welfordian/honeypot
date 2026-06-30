import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { defineConfig } from "vite";

const pagesProxy = process.env.VITE_PAGES_PROXY_TARGET;
const liveStreamProxy = process.env.VITE_LIVE_STREAM_PROXY_TARGET ?? pagesProxy ?? "";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src")
    }
  },
  server: {
    host: "127.0.0.1",
    port: Number(process.env.VITE_PORT ?? 5173),
    ...(pagesProxy
      ? {
          proxy: {
            "/api/live-stream": {
              target: liveStreamProxy,
              changeOrigin: true,
              ws: true
            },
            "/api": {
              target: pagesProxy,
              changeOrigin: true
            }
          }
        }
      : {})
  }
});
