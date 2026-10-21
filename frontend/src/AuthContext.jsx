import { createContext, useContext } from "react";

/**
 * Contexte d'authentification (2026-09-07) — posé par AuthGate.jsx (le seul composant qui
 * connaît l'état de session), consommé par Dashboard.jsx (nom d'utilisateur, "Se déconnecter")
 * et par les pages/composants Vanitas qui masquent leurs capacités les plus sensibles pour un
 * compte non-admin (VanitasSidebar.jsx, VanitasDeviceDetail.jsx) — l'application RÉELLE de la
 * règle admin/viewer reste toujours côté serveur (`backend/auth/require_admin`), ce contexte
 * ne sert qu'à adapter l'affichage, jamais la seule protection.
 */
const AuthContext = createContext(null);

export const AuthProvider = AuthContext.Provider;

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth() doit être appelé sous <AuthGate>.");
  }
  return ctx;
}
