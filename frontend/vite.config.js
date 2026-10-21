import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy /api vers l'API FastAPI locale (backend/api_server.py, port 8000) pour éviter
// tout souci de CORS en dev — le backend autorise déjà CORS_ORIGIN en secours.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  // Config Vitest (revue de code frontend, 💡 suggestion #11) : tests unitaires pour les
  // fonctions pures de theme.js (calculs de risque, regroupements, camemberts). Pas besoin
  // de jsdom ici, aucun test ne touche au DOM/React pour l'instant.
  test: {
    environment: "node",
    include: ["src/**/*.test.js"],
  },
});
