import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/api/web/dist",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("node_modules/cytoscape")) {
            return "graph";
          }
          if (id.includes("node_modules/recharts")) {
            return "charts";
          }
          return undefined;
        }
      }
    }
  }
});
