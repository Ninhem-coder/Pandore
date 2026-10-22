import { useState } from "react";
import { tr } from "./i18n/core.js";

/** Pictogramme bouclier + serrure — repris à l'identique de `Design/pandore-icon.svg` (charte
 * graphique Pandore & Vanitas), même tracé/dégradé que `LogoMark` dans `Sidebar.jsx`. Dupliqué
 * ici plutôt que partagé (petit SVG statique sans état, même convention que le reste de ce
 * dashboard pour ce genre d'icône — voir CLAUDE.md) : cet écran de connexion n'a jamais
 * utilisé le logo avant ce jour, retour de Nicolas après le reskin de la charte ("les logos tu
 * les as pas utilisé ?"). */
function LoginMark() {
  return (
    <svg className="login-mark" viewBox="0 0 60 62" width="34" height="35" aria-hidden="true">
      <defs>
        <linearGradient id="loginLogoIcon" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#F6B27E" />
          <stop offset="100%" stopColor="#EE9A5C" />
        </linearGradient>
      </defs>
      <path
        d="M30 0 C42 6 52 8 60 8 C60 34 52 52 30 62 C8 52 0 34 0 8 C8 8 18 6 30 0 Z"
        fill="url(#loginLogoIcon)"
      />
      <circle cx="30" cy="28" r="7" fill="#0A0E1A" />
      <path d="M26.5 32 L33.5 32 L31 44 L29 44 Z" fill="#0A0E1A" />
    </svg>
  );
}

/**
 * Écran de connexion (2026-09-07) — page pleine largeur centrée, PAS une modale : c'est
 * l'unique état possible avant tout accès au dashboard (voir AuthGate.jsx), contrairement à
 * `DeployAppWizard.jsx` qui se ferme sur une page déjà utilisable. Tokens `styles.css`
 * existants (design system "dossier sombre"), aucun nouveau système de couleurs.
 */
export default function LoginForm({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    if (!username.trim() || !password || busy) return;
    setBusy(true);
    setError("");
    try {
      await onLogin(username.trim(), password);
    } catch {
      // postJSON (api.js) lève sur tout HTTP non-2xx, y compris le 401 "identifiants
      // incorrects" — un seul message générique, ne jamais préciser si c'est l'identifiant
      // ou le mot de passe qui est faux (éviter de confirmer l'existence d'un compte).
      setError(tr("login.failed"));
      setBusy(false);
    }
  }

  return (
    <div className="login-screen">
      <form className="login-card" onSubmit={handleSubmit}>
        <LoginMark />
        <p className="login-brand">Pandore</p>
        <h1>{tr("login.title")}</h1>
        <label className="login-field">
          {tr("login.username")}
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
            autoComplete="username"
            disabled={busy}
          />
        </label>
        <label className="login-field">
          {tr("login.password")}
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            disabled={busy}
          />
        </label>
        {error ? <p className="login-error">{error}</p> : null}
        <button type="submit" className="login-submit" disabled={busy}>
          {busy ? tr("login.signingIn") : tr("login.submit")}
        </button>
      </form>
    </div>
  );
}
