import { useEffect, useState } from "react";
import { api } from "./api.js";
import { AuthProvider } from "./AuthContext.jsx";
import { clearAllCache } from "./cache.js";
import LoginForm from "./LoginForm.jsx";
import { tr } from "./i18n/core.js";

/**
 * Gate d'authentification (2026-09-07, demande de Nicolas — multi-comptes, admin/lecture
 * seule) — enveloppe TOUT le dashboard (voir App.jsx). Interroge `GET /api/auth/me` au
 * montage : une session valide (cookie posé par un login précédent, encore dans la fenêtre de
 * `SESSION_TTL_HOURS` côté backend) laisse l'app démarrer directement ; sinon `LoginForm`
 * s'affiche et RIEN d'autre du dashboard ne monte tant que la connexion n'a pas réussi — aucun
 * composant enfant, donc aucun appel Intune/Defender/Vanitas déclenché avant authentification.
 */
export default function AuthGate({ children }) {
  const [state, setState] = useState({ status: "loading", user: null });

  useEffect(() => {
    let cancelled = false;
    api.auth
      .me()
      .then((user) => {
        if (!cancelled) setState({ status: "ready", user });
      })
      .catch(() => {
        if (!cancelled) setState({ status: "anonymous", user: null });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleLogin(username, password) {
    const user = await api.auth.login(username, password);
    // Revue de sécurité du 2026-09-07 : `cache.js` vit au niveau MODULE, indépendant du cycle
    // de vie React ET de l'état d'auth — sans ce vidage, un compte qui se connecte sur le même
    // onglet dans les 2h suivant la déconnexion d'un AUTRE compte recevrait en mémoire des
    // réponses mises en cache PAR ce premier compte (ex. le catalogue complet de règles de
    // conformité, admin-only), sans jamais repasser par le serveur pour revalider ses droits.
    clearAllCache();
    setState({ status: "ready", user });
  }

  async function handleLogout() {
    try {
      await api.auth.logout();
    } finally {
      clearAllCache();
      setState({ status: "anonymous", user: null });
    }
  }

  // Page "Paramètres" (2026-09-08) — après un changement d'identifiant/mot de passe en
  // self-service, `Dashboard.jsx`/`VanitasSidebar.jsx`/etc. affichent `user.username`/
  // `user.role` depuis CE contexte : sans ce setter, le masthead resterait figé sur l'ancien
  // identifiant jusqu'au prochain rechargement de page complet.
  function updateUser(patch) {
    setState((prev) => ({ ...prev, user: { ...prev.user, ...patch } }));
  }

  if (state.status === "loading") {
    return <div className="auth-boot">{tr("common.loading")}</div>;
  }

  if (state.status === "anonymous") {
    return <LoginForm onLogin={handleLogin} />;
  }

  return (
    <AuthProvider value={{ user: state.user, logout: handleLogout, updateUser }}>{children}</AuthProvider>
  );
}
