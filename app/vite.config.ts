import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Tauri erwartet einen festen Port im Entwicklungsmodus
export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  // fs.allow: die Anleitung unter ../docs wird in die Hilfe eingebunden
  server: { port: 1420, strictPort: true, fs: { allow: [".."] } },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    target: "es2022",
    chunkSizeWarningLimit: 1500,
  },
});
