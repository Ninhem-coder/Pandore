import AuthGate from "./AuthGate.jsx";
import Dashboard from "./pages/Dashboard.jsx";

/**
 * Le masthead, le shell app-shell/sidebar et le footer sont désormais gérés dans
 * Dashboard.jsx (leur contenu dépend de l'onglet actif de la sidebar) — App.jsx ne fait
 * plus que monter le composant racine.
 *
 * `AuthGate` (2026-09-07, authentification multi-comptes) enveloppe `Dashboard` — aucune page
 * du dashboard ne monte, donc aucun appel Intune/Defender/Vanitas ne part, tant qu'une session
 * valide n'existe pas.
 */
export default function App() {
  return (
    <AuthGate>
      <Dashboard />
    </AuthGate>
  );
}
