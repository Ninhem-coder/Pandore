import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { useAuth } from "../AuthContext.jsx";
import { isErrorPayload, useVanitasProfiles } from "../hooks/useDashboardData.js";
import { ConfirmButton, VanitasWizardShell, VANITAS_MODULES, fmtDate } from "./vanitasShared.jsx";
import { IconKey, IconLaptop, IconTerminal, IconUpload, IconShield, IconLayers, IconRadar } from "../components/icons.jsx";
import { localizedTable, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

const LEVEL_LABELS = localizedTable("vpr.level", ["none", "read", "write"]);

/** Icône + description + "ce que l'écriture débloque en plus" par module — même contenu que
 * la maquette validée (artefact "Profils Vanitas"), jamais dans `VANITAS_MODULES`
 * (vanitasShared.jsx) lui-même : ce fichier reste la liste minimale {key,label} partagée par
 * TOUT le dashboard (nav, catalogue, résolution de permission), la description détaillée n'a
 * de sens que dans CETTE page (textes : vpr.mod.<key>.desc / .rw). Icônes réutilisées telles quelles depuis `VanitasSidebar.jsx`
 * (même module → même pictogramme, jamais réinventé). */
const MODULE_META = {
  postes: {
    icon: <IconLaptop />,
    get desc() {
      return tr("vpr.mod.postes.desc");
    },
    get rw() {
      return tr("vpr.mod.postes.rw");
    },
  },
  terminal: {
    icon: <IconTerminal />,
    get desc() {
      return tr("vpr.mod.terminal.desc");
    },
    get rw() {
      return tr("vpr.mod.terminal.rw");
    },
  },
  applications: {
    icon: <IconUpload />,
    get desc() {
      return tr("vpr.mod.applications.desc");
    },
    get rw() {
      return tr("vpr.mod.applications.rw");
    },
  },
  conformite: {
    icon: <IconShield />,
    get desc() {
      return tr("vpr.mod.conformite.desc");
    },
    get rw() {
      return tr("vpr.mod.conformite.rw");
    },
  },
  groupes: {
    icon: <IconLayers />,
    get desc() {
      return tr("vpr.mod.groupes.desc");
    },
    get rw() {
      return tr("vpr.mod.groupes.rw");
    },
  },
  // Activités suspectes (jalon "détection d'activités suspectes sur les postes", 2026-09-14).
  activites_suspectes: {
    icon: <IconRadar />,
    get desc() {
      return tr("vpr.mod.activites_suspectes.desc");
    },
    get rw() {
      return tr("vpr.mod.activites_suspectes.rw");
    },
  },
};

function emptyPerms() {
  return Object.fromEntries(VANITAS_MODULES.map((m) => [m.key, "none"]));
}

function levelDotClass(level) {
  return level === "write" ? "rw" : level === "read" ? "ro" : "none";
}

function initials(name) {
  const cleaned = name.replace(/^[._]/, "");
  const parts = cleaned.split(/[._]/).filter(Boolean);
  return (parts.length ? parts : [cleaned]).map((p) => p[0]).join("").slice(0, 2).toUpperCase();
}

/** Matrice de permissions réutilisée par la création ET le panneau de détail d'un profil — 5
 * lignes (VANITAS_MODULES), icône + description + "ce que Lecture-écriture débloque en plus"
 * (MODULE_META), 3 pastilles cliquables. `none`=neutre, `read`=teal (--hud-accent, l'accent de
 * marque), `write`=magenta (--hud-accent2) : vert/ambre/rouge restent réservés aux statuts
 * sémantiques (conforme/sévérité) ailleurs dans ce dashboard, jamais réutilisés ici pour une
 * simple catégorisation de permission. */
function PermsMatrix({ perms, onChange }) {
  return (
    <div className="vanitas-perm-matrix">
      {VANITAS_MODULES.map((m) => {
        const meta = MODULE_META[m.key];
        return (
          <div className="vanitas-perm-row" key={m.key}>
            <div className="vanitas-perm-row-info">
              <span className="vanitas-perm-row-icon">{meta.icon}</span>
              <div>
                <p className="vanitas-perm-row-name">{m.label}</p>
                <p className="vanitas-perm-row-desc">
                  {meta.desc}
                  <span className="vanitas-perm-row-rw-hint">{tr("vpr.writeHint", { text: meta.rw })}</span>
                </p>
              </div>
            </div>
            <div className="vanitas-perm-pills">
              {["none", "read", "write"].map((level) => (
                <button
                  key={level}
                  type="button"
                  className={`vanitas-perm-pill ${level}${perms[m.key] === level ? " selected" : ""}`}
                  onClick={() => onChange(m.key, level)}
                >
                  <span className="led" />
                  {LEVEL_LABELS[level]}
                </button>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

/** Popup de CRÉATION seule (2026-09-10, alignement sur la maquette validée — voir la demande
 * de Nicolas : "les profils à gauche et un autre bloc à droite quand je sélectionne un profil
 * avec les rôles à modifier"). La MODIFICATION d'un profil existant ne passe plus par cette
 * popup — elle se fait directement dans `ProfileDetailPanel` ci-dessous (panneau de droite du
 * layout maître-détail), plus jamais besoin de rouvrir une modale pour éditer un profil déjà
 * sélectionné. */
function CreateProfileModal({ onClose, onCreated }) {
  const [name, setName] = useState("");
  const [perms, setPerms] = useState(emptyPerms());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit() {
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.createProfile(name.trim(), perms);
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        onCreated(payload.id);
        onClose();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <VanitasWizardShell onClose={onClose}>
      <div className="vanitas-wiz-header">
        <span className="vanitas-wiz-header-icon">
          <IconKey />
        </span>
        <div className="vanitas-wiz-header-text">
          <h2>{tr("vpr.createProfile")}</h2>
          <p>{tr("vpr.createProfileSub")}</p>
        </div>
      </div>
      <div className="vanitas-wiz-body">
        <input
          type="text"
          className="filter-input"
          style={{ width: "100%", marginBottom: "16px" }}
          placeholder={tr("vpr.profileName")}
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={busy}
          autoFocus
        />
        <PermsMatrix perms={perms} onChange={(key, level) => setPerms((prev) => ({ ...prev, [key]: level }))} />
        {error && <p className="error-note" style={{ marginTop: "12px" }}>{error}</p>}
        <div className="wizard-actions" style={{ marginTop: "18px" }}>
          <button type="button" className="vanitas-ghost-btn" onClick={onClose} disabled={busy}>
            {tr("vpr.cancel")}
          </button>
          <button type="button" className="vanitas-wiz-primary-btn" onClick={handleSubmit} disabled={busy || !name.trim()}>
            {busy ? tr("vpr.creating") : tr("vpr.createProfileBtn")}
          </button>
        </div>
      </div>
    </VanitasWizardShell>
  );
}

/** Carte de la liste de gauche (layout maître-détail) — nom, résumé des modules accordés
 * (pastille colorée par niveau, modules à "none" omis) et nombre de comptes assignés. Toute la
 * carte est cliquable (`<button>` plein, pas un `<div role="button">` — pas de contrôle
 * interactif imbriqué à l'intérieur, contrairement à d'autres cartes du dashboard). */
function ProfileCard({ profile, active, accountCount, onSelect }) {
  const granted = VANITAS_MODULES.filter((m) => (profile.perms?.[m.key] ?? "none") !== "none");
  return (
    <button type="button" className={`vanitas-profile-card${active ? " active" : ""}`} onClick={onSelect}>
      <span className="vanitas-profile-card-name">{profile.name}</span>
      <div className="vanitas-profile-card-meta">
        {granted.length === 0 ? (
          <span className="vanitas-profile-card-meta-empty">{tr("vpr.noPermission")}</span>
        ) : (
          granted.map((m) => (
            <span key={m.key}>
              <span className={`vanitas-profile-chip-dot ${levelDotClass(profile.perms[m.key])}`} />
              {m.label}
            </span>
          ))
        )}
      </div>
      <div className="vanitas-profile-card-accounts">
        {tr("vpr.assigned", { count: accountCount })}
      </div>
    </button>
  );
}

/** Panneau de droite du layout maître-détail — nom éditable inline, matrice de permissions
 * complète (éditable), liste des comptes qui utilisent ce profil, actions Enregistrer/
 * Supprimer directement ici (plus de popup pour modifier un profil existant, voir
 * `CreateProfileModal` ci-dessus). `key={profile.id}` posé par l'appelant (`ProfilesPane`)
 * remonte ce composant à chaque changement de sélection — repart proprement de l'état du
 * profil actif plutôt que de porter la charge de resynchroniser un state périmé à la main. */
function ProfileDetailPanel({ profile, accountNames, onSaved, onDeleted }) {
  const [name, setName] = useState(profile.name);
  const [perms, setPerms] = useState(profile.perms ?? emptyPerms());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const dirty = name !== profile.name || JSON.stringify(perms) !== JSON.stringify(profile.perms ?? emptyPerms());

  async function handleSave() {
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.updateProfile(profile.id, { name: name.trim(), perms });
      if (isErrorPayload(payload)) setError(payload.message);
      else onSaved();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    setError(null);
    try {
      const payload = await api.vanitas.deleteProfile(profile.id);
      if (isErrorPayload(payload)) setError(payload.message);
      else onDeleted();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="vanitas-hud-frame vanitas-profile-detail">
      <div className="vanitas-profile-detail-head">
        <div className="vanitas-profile-detail-title-wrap">
          <input
            className="vanitas-profile-name-input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={busy}
          />
          <p className="vanitas-profile-detail-sub">{tr("vpr.detailSub")}</p>
        </div>
        <ConfirmButton
          label={tr("vpr.delete")}
          confirmLabel={tr("v.confirm")}
          className="vanitas-danger-btn"
          disabled={accountNames.length > 0}
          title={accountNames.length > 0 ? tr("vpr.reassignFirst") : undefined}
          onConfirm={handleDelete}
        />
      </div>

      <p className="filter-chip-group-label" style={{ margin: "22px 0 12px" }}>
        {tr("vpr.permsPerFeature")}
      </p>
      <PermsMatrix perms={perms} onChange={(key, level) => setPerms((prev) => ({ ...prev, [key]: level }))} />

      <div className="vanitas-profile-assigned-card">
        <p className="filter-chip-group-label" style={{ marginBottom: "10px" }}>
          {tr("vpr.accountsUsing")}
        </p>
        {accountNames.length === 0 ? (
          <p className="vanitas-hud-empty-note" style={{ padding: 0 }}>
            {tr("vpr.noAccountUsing")}
          </p>
        ) : (
          accountNames.map((username) => (
            <div className="vanitas-profile-account-row" key={username}>
              <span className="vanitas-profile-avatar">{initials(username)}</span>
              {username}
            </div>
          ))
        )}
      </div>

      {error && <p className="error-note" style={{ marginTop: "12px" }}>{error}</p>}

      <div className="wizard-actions" style={{ marginTop: "24px", justifyContent: "flex-end" }}>
        <button
          type="button"
          className="vanitas-wiz-primary-btn"
          onClick={handleSave}
          disabled={busy || !name.trim() || !dirty}
        >
          {busy ? tr("vpr.saving") : tr("vpr.saveChanges")}
        </button>
      </div>
    </div>
  );
}

/**
 * Layout maître-détail (2026-09-10, alignement sur la maquette validée — demande de Nicolas :
 * "les profils à gauche et un autre bloc à droite quand je sélectionne un profil avec les
 * rôles à modifier"). Remplace l'ancien tableau plat + popup "Modifier" par une liste de
 * profils cliquables à gauche et un panneau de détail éditable à droite — plus jamais de popup
 * pour modifier un profil EXISTANT (`CreateProfileModal` ne sert plus qu'à la création).
 */
function ProfilesPane({ profiles, accountsByProfile }) {
  const [showCreate, setShowCreate] = useState(false);
  const [selectedId, setSelectedId] = useState(null);

  const list = profiles.state.data;

  // Le profil sélectionné peut disparaître (suppression, ou changement de compte connecté qui
  // recharge la liste) — retombe sur le premier profil disponible plutôt que de laisser le
  // panneau de détail pointer vers un id qui n'existe plus.
  useEffect(() => {
    if (list.length === 0) {
      if (selectedId !== null) setSelectedId(null);
      return;
    }
    if (!list.some((p) => p.id === selectedId)) setSelectedId(list[0].id);
  }, [list, selectedId]);

  const selected = list.find((p) => p.id === selectedId) ?? null;

  return (
    <div>
      {profiles.state.error && <p className="vanitas-hud-error">{profiles.state.error}</p>}
      {profiles.state.status === "loading" ? (
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      ) : list.length === 0 ? (
        <div className="vanitas-hud-card vanitas-hud-frame vanitas-hud-empty-cta">
          <p className="vanitas-hud-empty-note">
            {tr("vpr.noProfile")}
          </p>
          <button type="button" className="vanitas-queue-btn" onClick={() => setShowCreate(true)}>
            {tr("vpr.addProfile")}
          </button>
        </div>
      ) : (
        <div className="vanitas-profiles-layout">
          <div>
            <div className="vanitas-profile-list-head">
              <h2>
                {tr("vpr.profiles", { count: list.length })}
              </h2>
            </div>
            <div className="vanitas-profile-list">
              {list.map((p) => (
                <ProfileCard
                  key={p.id}
                  profile={p}
                  active={p.id === selectedId}
                  accountCount={accountsByProfile[p.id]?.length ?? 0}
                  onSelect={() => setSelectedId(p.id)}
                />
              ))}
            </div>
            <button
              type="button"
              className="vanitas-queue-btn"
              style={{ width: "100%", justifyContent: "center", marginTop: "12px" }}
              onClick={() => setShowCreate(true)}
            >
              {tr("vpr.addProfile")}
            </button>
          </div>

          {selected && (
            <ProfileDetailPanel
              key={selected.id}
              profile={selected}
              accountNames={accountsByProfile[selected.id] ?? []}
              onSaved={profiles.refresh}
              onDeleted={profiles.refresh}
            />
          )}
        </div>
      )}

      {showCreate && (
        <CreateProfileModal
          onClose={() => setShowCreate(false)}
          onCreated={(newId) => {
            profiles.refresh();
            setSelectedId(newId);
          }}
        />
      )}
    </div>
  );
}

function CreateAccountWizard({ profiles, onClose, onCreated }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [profileId, setProfileId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit() {
    if (!username.trim() || password.length < 8) return;
    setBusy(true);
    setError(null);
    try {
      const payload = await api.auth.createUser({
        username: username.trim(),
        password,
        role,
        profile_id: role === "admin" ? null : profileId || null,
      });
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        onCreated();
        onClose();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <VanitasWizardShell onClose={onClose}>
      <div className="vanitas-wiz-header">
        <span className="vanitas-wiz-header-icon">
          <IconKey />
        </span>
        <div className="vanitas-wiz-header-text">
          <h2>{tr("vpr.createAccount")}</h2>
          <p>{tr("vpr.createAccountSub")}</p>
        </div>
      </div>
      <div className="vanitas-wiz-body">
        <input
          type="text"
          className="filter-input"
          style={{ width: "100%", marginBottom: "12px" }}
          placeholder={tr("vpr.username")}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={busy}
          autoComplete="off"
        />
        <input
          type="password"
          className="filter-input"
          style={{ width: "100%", marginBottom: "12px" }}
          placeholder={tr("vpr.password")}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={busy}
          autoComplete="new-password"
        />
        <div className="vanitas-hud-chips" style={{ marginBottom: "12px" }}>
          <button
            type="button"
            className={`vanitas-hud-chip${role === "viewer" ? " active" : ""}`}
            onClick={() => setRole("viewer")}
          >
            <span className="led" />
            {tr("vpr.chip.viewer")}
          </button>
          <button
            type="button"
            className={`vanitas-hud-chip tone-warn${role === "admin" ? " active" : ""}`}
            onClick={() => setRole("admin")}
          >
            <span className="led" />ADMIN
          </button>
        </div>
        {role === "viewer" && (
          <select
            className="filter-input"
            style={{ width: "100%", marginBottom: "12px" }}
            value={profileId}
            onChange={(e) => setProfileId(e.target.value)}
            disabled={busy}
          >
            <option value="">{tr("vpr.noAccessDefault")}</option>
            {profiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        )}
        {error && <p className="error-note">{error}</p>}
        <div className="wizard-actions" style={{ marginTop: "10px" }}>
          <button type="button" className="vanitas-ghost-btn" onClick={onClose} disabled={busy}>
            {tr("vpr.cancel")}
          </button>
          <button
            type="button"
            className="vanitas-wiz-primary-btn"
            onClick={handleSubmit}
            disabled={busy || !username.trim() || password.length < 8}
          >
            {busy ? tr("vpr.creating") : tr("vpr.createAccountBtn")}
          </button>
        </div>
      </div>
    </VanitasWizardShell>
  );
}

function AccountsPane({ profiles, accountsState, reloadAccounts }) {
  const { user: currentUser } = useAuth();
  const [error, setError] = useState(null);
  const [showCreate, setShowCreate] = useState(false);
  const state = accountsState;

  async function handleRoleChange(username, role) {
    setError(null);
    try {
      // Repasser un compte en admin retire son profil côté serveur (auth_store.set_role) —
      // repasser en viewer laisse `profile_id` tel quel (souvent `null` si le compte était
      // admin) : "aucun accès" par défaut, jamais un profil hérité par surprise.
      await api.auth.updateUser(username, { role });
      reloadAccounts();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleProfileChange(username, profileId) {
    setError(null);
    try {
      if (profileId) {
        await api.auth.updateUser(username, { profile_id: profileId });
      } else {
        await api.auth.updateUser(username, { clear_profile: true });
      }
      reloadAccounts();
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleResetPassword(username) {
    const pw = window.prompt(tr("vpr.resetPrompt", { username }));
    if (!pw) return;
    setError(null);
    try {
      await api.auth.updateUser(username, { new_password: pw });
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleDelete(username) {
    setError(null);
    try {
      await api.auth.deleteUser(username);
      reloadAccounts();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div>
      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>
            {tr("vpr.accounts", { count: state.users.length })}
          </h2>
          <button type="button" className="vanitas-queue-btn" onClick={() => setShowCreate(true)}>
            {tr("vpr.addAccount")}
          </button>
        </div>
        {error && <p className="vanitas-hud-error">{error}</p>}
        {state.status === "loading" ? (
          <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
        ) : (
          <div className="vanitas-hud-table-wrap">
            <table className="vanitas-hud-table">
              <thead>
                <tr>
                  <th>{tr("vpr.col.account")}</th>
                  <th>{tr("vpr.col.role")}</th>
                  <th>{tr("vpr.col.profile")}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {state.users.map((u) => {
                  const isSelf = u.username.toLowerCase() === currentUser.username.toLowerCase();
                  const isAdmin = u.role === "admin";
                  return (
                    <tr key={u.id}>
                      <td className="vanitas-hud-host">
                        <span className="name">
                          {u.username}
                          {isSelf ? tr("vpr.you") : ""}
                        </span>
                        <span className="id">{tr("vpr.createdOn", { date: fmtDate(u.created_at) })}</span>
                      </td>
                      <td>
                        <select
                          className="filter-input"
                          style={{ width: "150px" }}
                          value={u.role}
                          onChange={(e) => handleRoleChange(u.username, e.target.value)}
                          disabled={isSelf}
                        >
                          <option value="admin">{tr("vpr.role.admin")}</option>
                          <option value="viewer">{tr("vpr.role.viewer")}</option>
                        </select>
                      </td>
                      <td>
                        <select
                          className="filter-input"
                          style={{ width: "180px" }}
                          value={u.profile_id ?? ""}
                          onChange={(e) => handleProfileChange(u.username, e.target.value)}
                          disabled={isAdmin}
                        >
                          <option value="">{isAdmin ? tr("vpr.fullAccess") : tr("vpr.level.none")}</option>
                          {profiles.map((p) => (
                            <option key={p.id} value={p.id}>
                              {p.name}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td style={{ display: "flex", gap: "8px", justifyContent: "flex-end" }}>
                        <button
                          type="button"
                          className="vanitas-ghost-btn"
                          onClick={() => handleResetPassword(u.username)}
                          disabled={isSelf}
                          title={isSelf ? tr("vpr.selfPassword") : undefined}
                        >
                          {tr("vpr.resetPassword")}
                        </button>
                        <ConfirmButton
                          label={tr("vpr.delete")}
                          confirmLabel={tr("v.confirm")}
                          className="vanitas-danger-btn"
                          disabled={isSelf}
                          title={isSelf ? tr("vpr.selfDelete") : undefined}
                          onConfirm={() => handleDelete(u.username)}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreate && (
        <CreateAccountWizard profiles={profiles} onClose={() => setShowCreate(false)} onCreated={reloadAccounts} />
      )}
    </div>
  );
}

/**
 * "Vanitas" > Administration > Profils (2026-09-10, demande de Nicolas — "des rôles comme dans
 * Intune... un read pour voir et un read-write pour lecture-écriture", puis "gérer les comptes
 * direct de la page plutôt que les paramètres"). Deux sous-onglets :
 * - "Profils" : catalogue de profils nommés réutilisables, chacun une matrice
 *   {postes/terminal/applications/conformite/groupes: none|read|write} — voir
 *   `backend/auth/vanitas_profiles.py` pour le modèle complet et `AuthContext.jsx`/
 *   `vanitasShared.jsx::hasVanitasAccess` pour l'application côté frontend (confort d'UI, la
 *   RÉELLE protection est `require_vanitas_read/write` côté serveur).
 * - "Comptes" : gestion complète des comptes (créer/rôle/profil/réinitialiser/supprimer),
 *   déplacée depuis Paramètres > Gestion des comptes (qui ne garde plus que "Mon compte").
 *
 * Page admin-only (masquée pour un compte viewer, voir VanitasSidebar.jsx) — les 4 routes
 * `/api/vanitas/profiles*` ET les routes `/api/auth/users*` sont `require_admin` côté serveur,
 * jamais `require_vanitas_write` : gérer QUI a accès à quoi est une action d'administration
 * Pandore, pas une capacité Vanitas parmi d'autres (voir api_server.py).
 */
export default function VanitasProfilesTab() {
  const profiles = useVanitasProfiles();
  const [tab, setTab] = useState("profiles");
  // Liste des comptes levée ICI (pas dans AccountsPane) — une SEULE source de vérité partagée
  // par les deux sous-onglets : la carte "Profils" (décompte "comptes assignés" par profil,
  // garde-fou de suppression) ET le sous-onglet "Comptes" lui-même. Un `reloadAccounts` recharge
  // les deux vues d'un coup après une mutation (créer/changer le rôle/assigner un profil/
  // supprimer) — bug réel corrigé en testant : une 2e copie locale dans `AccountsPane` seule
  // laissait le décompte de "Profils" périmé après une assignation faite depuis "Comptes".
  const [accountsState, setAccountsState] = useState({ status: "loading", users: [] });

  const reloadAccounts = useCallback(async () => {
    try {
      const users = await api.auth.listUsers();
      setAccountsState({ status: "done", users: Array.isArray(users) ? users : [] });
    } catch {
      setAccountsState({ status: "error", users: [] });
    }
  }, []);

  useEffect(() => {
    profiles.ensureLoaded();
    reloadAccounts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const accountsByProfile = {};
  for (const u of accountsState.users) {
    if (u.profile_id) (accountsByProfile[u.profile_id] ??= []).push(u.username);
  }

  return (
    <div className="vanitas-hud">
      <div className="vanitas-hud-card vanitas-hud-frame" style={{ marginBottom: "20px" }}>
        <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
          {trRich("vpr.intro", {
            profile: <b>{tr("vpr.intro.profile")}</b>,
            admin: <b>admin</b>,
            viewer: <b>{tr("vpr.intro.viewer")}</b>,
          })}
        </p>
      </div>

      <div className="vanitas-hud-chips" style={{ marginBottom: "20px" }}>
        <button type="button" className={`vanitas-hud-chip${tab === "profiles" ? " active" : ""}`} onClick={() => setTab("profiles")}>
          <span className="led" />
          {tr("vpr.tab.profiles")}
        </button>
        <button type="button" className={`vanitas-hud-chip${tab === "accounts" ? " active" : ""}`} onClick={() => setTab("accounts")}>
          <span className="led" />
          {tr("vpr.tab.accounts")}
        </button>
      </div>

      {tab === "profiles" ? (
        <ProfilesPane profiles={profiles} accountsByProfile={accountsByProfile} />
      ) : (
        <AccountsPane profiles={profiles.state.data} accountsState={accountsState} reloadAccounts={reloadAccounts} />
      )}
    </div>
  );
}
