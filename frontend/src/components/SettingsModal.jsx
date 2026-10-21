import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { api } from "../api.js";
import { useAuth } from "../AuthContext.jsx";
import { IconSettings } from "./icons.jsx";

/**
 * Page "Paramètres" (2026-09-08, demande de Nicolas — "changer le nom d'utilisateur / mot de
 * passe... tout ce qui concerne le compte") — même chrome que les autres popups du dashboard
 * (`.wizard-overlay`/`.wizard-shell`, fermeture Échap/clic en dehors, copié à l'identique de
 * `EditAppModal`/`DeployAppWizard.jsx` — pas un 3e mécanisme de popup). Ouverte depuis un
 * bouton dédié dans le masthead (`Dashboard.jsx`), pas depuis l'un des deux arbres de
 * navigation (Sidebar/VanitasSidebar) : ce n'est ni une page Intune ni une page Vanitas, c'est
 * une propriété du COMPTE connecté, orthogonale aux deux.
 *
 * Ne garde plus que "Mon compte" (self-service, tout rôle confondu — identifiant/mot de passe
 * de SON PROPRE compte) — la "Gestion des comptes" (créer/supprimer/changer le rôle d'un AUTRE
 * compte, l'assigner à un profil Vanitas) a été DÉPLACÉE le 2026-09-10 vers Vanitas >
 * Administration > "Profils" (demande de Nicolas — "gérer les comptes direct de la page plutôt
 * que les paramètres"), qui gère maintenant à la fois les profils ET les comptes eux-mêmes.
 * `manage_users.py` (CLI) reste disponible pour une intervention hors-ligne (compte verrouillé,
 * accès direct au serveur).
 */
export default function SettingsModal({ onClose }) {
  const { user, updateUser } = useAuth();
  const shellRef = useRef(null);

  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === "Escape") onClose();
    }
    function handlePointerDown(e) {
      if (shellRef.current && !shellRef.current.contains(e.target)) onClose();
    }
    document.addEventListener("keydown", handleKeyDown);
    document.addEventListener("pointerdown", handlePointerDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("pointerdown", handlePointerDown);
    };
  }, [onClose]);

  // `createPortal` (2026-09-08) — sans lui, ce modal rendu depuis `Dashboard.jsx` hérite du
  // `<header className="masthead">` ancêtre comme containing block pour son `.wizard-overlay`
  // (`position: fixed`) : `.masthead` porte un `transform` (animation d'entrée `riseIn`), et
  // N'IMPORTE QUEL `transform` sur un ancêtre — même la matrice identité qu'une animation déjà
  // terminée laisse en place — fait qu'un descendant `position: fixed` se positionne relatif à
  // CET ANCÊTRE plutôt qu'au viewport (règle CSS standard, pas un bug de ce dashboard). Repéré
  // en mesurant les rects réels (`overlay.top: 36, overlay.height: 154` au lieu de couvrir tout
  // l'écran) avant de corriger — même précédent déjà en place ailleurs dans ce dashboard
  // (`WidgetsTestTab.jsx`, seul autre portail de l'app) pour la même classe de problème.
  return createPortal(
    <div className="wizard-overlay">
      <div className="wizard-shell" ref={shellRef} role="dialog" aria-modal="true" aria-label="Paramètres du compte">
        <div className="wizard-header">
          <span className="wizard-header-icon">
            <IconSettings />
          </span>
          <div className="wizard-header-text">
            <h2>Paramètres</h2>
            <p className="card-note">
              Connecté en tant que <b>{user.username}</b> ({user.role === "admin" ? "administrateur" : "lecture seule"})
            </p>
          </div>
          <button type="button" className="deployed-detail-close" onClick={onClose} aria-label="Fermer les paramètres">
            <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </div>
        <div className="wizard-step-body settings-body">
          <AccountSection user={user} updateUser={updateUser} />
          {user.role === "admin" && (
            <p className="cve-small" style={{ marginTop: "-8px" }}>
              La gestion des comptes et des profils Vanitas vit maintenant dans{" "}
              <b>Vanitas → Administration → Profils</b>.
            </p>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
}

function AccountSection({ user, updateUser }) {
  const [username, setUsername] = useState(user.username);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSuccess("");

    const usernameChanged = username.trim().toLowerCase() !== user.username.toLowerCase();
    if (!usernameChanged && !newPassword) {
      setError("Aucune modification à enregistrer.");
      return;
    }
    if (newPassword && newPassword !== confirmPassword) {
      setError("Les deux mots de passe ne correspondent pas.");
      return;
    }
    if (!currentPassword) {
      setError("Le mot de passe actuel est requis pour confirmer une modification.");
      return;
    }

    setBusy(true);
    try {
      const body = { current_password: currentPassword };
      if (usernameChanged) body.new_username = username.trim();
      if (newPassword) body.new_password = newPassword;
      const result = await api.auth.updateMe(body);
      updateUser(result);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setSuccess("Modifications enregistrées.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card settings-card">
      <div className="card-head">
        <h2>Mon compte</h2>
      </div>
      <form className="settings-form" onSubmit={handleSubmit}>
        <label className="settings-field">
          Identifiant
          <input
            type="text"
            className="filter-input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
          />
        </label>
        <label className="settings-field">
          Nouveau mot de passe (laisser vide pour ne pas changer)
          <input
            type="password"
            className="filter-input"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        <label className="settings-field">
          Confirmer le nouveau mot de passe
          <input
            type="password"
            className="filter-input"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        <label className="settings-field">
          Mot de passe actuel (requis pour confirmer)
          <input
            type="password"
            className="filter-input"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        {error && <p className="error-note">{error}</p>}
        {success && <p className="card-note">{success}</p>}
        <div className="wizard-actions">
          <button type="submit" className="wizard-primary-btn" disabled={busy}>
            {busy ? "Enregistrement…" : "Enregistrer les modifications"}
          </button>
        </div>
      </form>
    </div>
  );
}

