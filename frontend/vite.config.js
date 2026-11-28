import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/health": "http://127.0.0.1:8010",
      "/auth": "http://127.0.0.1:8010",
      "/copilot": "http://127.0.0.1:8010",
      "/approvals": "http://127.0.0.1:8010",
      "/reports": "http://127.0.0.1:8010",
    },
  },
});
