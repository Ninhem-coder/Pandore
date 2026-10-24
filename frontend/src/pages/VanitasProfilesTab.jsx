import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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

function initials(name) {
  const cleaned = name.replace(/^[._]/, "");
  const parts = cleaned.split(/[._\s()]/).filter(Boolean);
  return (parts.length ? parts : [cleaned]).map((p) => p[0]).join("").slice(0, 2).toUpperCase();
}

const LEVEL_COLOR = { read: "var(--hud-accent)", write: "var(--hud-accent2)" };

/** Matrice de permissions réutilisée par la création ET le panneau de détail d'un profil — une
 * ligne par module (VANITAS_MODULES), icône + description + "ce que Lecture-écriture débloque en
 * plus" (MODULE_META), sélecteur à 3 niveaux. `none`=neutre, `read`=teal (--hud-accent),
 * `write`=magenta (--hud-accent2) : vert/ambre/rouge restent réservés aux statuts sémantiques
 * ailleurs dans ce dashboard. Refonte 2026-10-24 : sélecteur segmenté (`.vpr-lvseg`) au lieu de
 * 3 pastilles séparées, même logique. */
function PermsMatrix({ perms, onChange, disabled }) {
  return (
    <div className="vpr-matrix">
      {VANITAS_MODULES.map((m) => {
        const meta = MODULE_META[m.key];
        const level = perms[m.key] ?? "none";
        return (
          <div className="vpr-mrow" key={m.key}>
            <span className="vpr-mico" aria-hidden="true">
              {meta.icon}
            </span>
            <span className="vpr-mname">{m.label}</span>
            <span className="vpr-lvseg" role="radiogroup" aria-label={m.label}>
              {["none", "read", "write"].map((lv) => (
                <button
                  key={lv}
                  type="button"
                  role="radio"
                  aria-checked={level === lv}
                  className={`${lv}${level === lv ? " on" : ""}`}
                  onClick={() => onChange(m.key, lv)}
                  disabled={disabled}
                >
                  {LEVEL_LABELS[lv]}
                </button>
              ))}
            </span>
            <span className="vpr-mdesc">
              {meta.desc}
              {level !== "write" && <span className="vpr-rw-hint"> {tr("vpr.writeHint", { text: meta.rw })}</span>}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function LevelDots({ perms }) {
  const granted = VANITAS_MODULES.filter((m) => (perms?.[m.key] ?? "none") !== "none");
  if (granted.length === 0) return <span>{tr("vpr.noPermission")}</span>;
  return granted.map((m) => (
    <span key={m.key} className="vpr-lv">
      <i style={{ background: LEVEL_COLOR[perms[m.key]] }} />
      {m.label}
    </span>
  ));
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

/** Panneau de détail d'un profil — nom éditable, matrice (éditable), comptes qui l'utilisent,
 * Enregistrer (actif seulement si modifié) / Supprimer (bloqué tant qu'un compte l'utilise).
 * `key={profile.id}` posé par l'appelant : repart proprement de l'état du profil sélectionné. */
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
    <aside className="vpr-card vpr-detail" aria-label={tr("vpr.profileAria")}>
      <div className="vpr-detail-title">
        <input className="vpr-input vpr-name-input" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} aria-label={tr("vpr.profileName")} />
        <span className="vpr-sub">{tr("vpr.detailSub")}</span>
      </div>

      <PermsMatrix perms={perms} onChange={(key, level) => setPerms((prev) => ({ ...prev, [key]: level }))} disabled={busy} />

      <div className="vpr-box">
        <span className="vpr-lbl">{tr("vpr.accountsUsingN", { count: accountNames.length })}</span>
        {accountNames.length === 0 ? (
          <span className="vpr-sub">{tr("vpr.noAccountUsing")}</span>
        ) : (
          <div className="vpr-accs">
            {accountNames.map((username) => (
              <span className="vpr-acc" key={username}>
                <span className="vpr-acc-av">{initials(username)}</span>
                {username}
              </span>
            ))}
          </div>
        )}
      </div>

      {error && <p className="error-note" style={{ margin: 0 }}>{error}</p>}
      <div className="vpr-foot">
        <ConfirmButton
          label={tr("vpr.delete")}
          confirmLabel={tr("v.confirm")}
          className="vanitas-danger-btn"
          disabled={accountNames.length > 0}
          title={accountNames.length > 0 ? tr("vpr.reassignFirst") : undefined}
          onConfirm={handleDelete}
        />
        <div className="vpr-foot-right">
          {dirty && <span className="vpr-sub vpr-warn">{tr("vpr.unsaved")}</span>}
          <button type="button" className="vanitas-wiz-primary-btn" onClick={handleSave} disabled={busy || !name.trim() || !dirty}>
            {busy ? tr("vpr.saving") : tr("vpr.saveChanges")}
          </button>
        </div>
      </div>
    </aside>
  );
}

/** Panneau de détail d'un compte (refonte 2026-10-24 — remplace la ligne du tableau "Comptes") :
 * rôle, profil, accès effectifs, réinitialisation du mot de passe EN PLACE (saisie masquée +
 * confirmation, 8 caractères min. comme à la création — remplace `window.prompt`, qui affichait
 * le mot de passe en clair sans confirmation), suppression. Son propre compte reste verrouillé
 * (rôle, mot de passe, suppression : Paramètres > Mon compte), comme avant. */
function AccountPanel({ account, profiles, isSelf, onChanged, onDeleted }) {
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [pwDone, setPwDone] = useState(false);
  const isAdmin = account.role === "admin";
  const profile = profiles.find((p) => p.id === account.profile_id) ?? null;
  const pwMismatch = pw2.length > 0 && pw !== pw2;

  async function update(body, after) {
    setBusy(true);
    setError(null);
    try {
      const payload = await api.auth.updateUser(account.username, body);
      if (isErrorPayload(payload)) {
        setError(payload.message);
        return;
      }
      after?.();
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  // Repasser un compte en admin retire son profil côté serveur (auth_store.set_role) —
  // repasser en viewer laisse `profile_id` tel quel (souvent `null`) : "aucun accès" par défaut.
  const setRole = (role) => role !== account.role && update({ role });
  const setProfile = (profileId) => update(profileId ? { profile_id: profileId } : { clear_profile: true });

  async function handlePassword(e) {
    e.preventDefault();
    if (pw.length < 8 || pw !== pw2) return;
    setPwDone(false);
    await update({ new_password: pw }, () => {
      setPw("");
      setPw2("");
      setPwDone(true);
    });
  }

  async function handleDelete() {
    setError(null);
    try {
      const payload = await api.auth.deleteUser(account.username);
      if (isErrorPayload(payload)) setError(payload.message);
      else onDeleted();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <aside className="vpr-card vpr-detail" aria-label={tr("vpr.accountAria")}>
      <div className="vpr-detail-head">
        <span className="vpr-av lg" aria-hidden="true">
          {initials(account.username)}
        </span>
        <div className="vpr-detail-name">
          <h2>
            {account.username}
            {isSelf ? tr("vpr.you") : ""}
          </h2>
          <span className="vpr-sub">{tr("vpr.createdOn", { date: fmtDate(account.created_at) })}</span>
        </div>
      </div>
      {isSelf && <div className="vpr-box vpr-sub">{tr("vpr.selfNote")}</div>}

      <div className="vpr-block">
        <span className="vpr-lbl">{tr("vpr.col.role")}</span>
        <span className="vpr-rolesel" role="radiogroup" aria-label={tr("vpr.col.role")}>
          <button type="button" role="radio" aria-checked={!isAdmin} className={!isAdmin ? "on" : ""} onClick={() => setRole("viewer")} disabled={isSelf || busy}>
            {tr("vpr.role.viewer")}
          </button>
          <button type="button" role="radio" aria-checked={isAdmin} className={`adm${isAdmin ? " on" : ""}`} onClick={() => setRole("admin")} disabled={isSelf || busy}>
            {tr("vpr.role.admin")}
          </button>
        </span>
      </div>

      {isAdmin ? (
        <div className="vpr-box vpr-sub">{tr("vpr.adminAccess")}</div>
      ) : (
        <>
          <div className="vpr-block">
            <span className="vpr-lbl">{tr("vpr.col.profile")}</span>
            <select className="vpr-input" value={account.profile_id ?? ""} onChange={(e) => setProfile(e.target.value)} disabled={busy} aria-label={tr("vpr.col.profile")}>
              <option value="">{tr("vpr.level.none")}</option>
              {profiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>
          <div className="vpr-box">
            <span className="vpr-lbl">{tr("vpr.effective")}</span>
            {profile ? (
              <span className="vpr-eff">
                {VANITAS_MODULES.filter((m) => (profile.perms?.[m.key] ?? "none") !== "none").map((m) => (
                  <span key={m.key} className="vpr-eff-chip">
                    <i style={{ background: LEVEL_COLOR[profile.perms[m.key]] }} />
                    {m.label} · {LEVEL_LABELS[profile.perms[m.key]].toLowerCase()}
                  </span>
                ))}
                {VANITAS_MODULES.every((m) => (profile.perms?.[m.key] ?? "none") === "none") && <span className="vpr-sub">{tr("vpr.noPermission")}</span>}
              </span>
            ) : (
              <span className="vpr-sub vpr-warn">{tr("vpr.noAccessNote")}</span>
            )}
          </div>
        </>
      )}

      {!isSelf && (
        <form className="vpr-box" onSubmit={handlePassword}>
          <span className="vpr-lbl">{tr("vpr.resetPassword")}</span>
          <input
            type="password"
            className="vpr-input"
            placeholder={tr("vpr.newPassword")}
            aria-label={tr("vpr.newPassword")}
            value={pw}
            onChange={(e) => {
              setPw(e.target.value);
              setPwDone(false);
            }}
            autoComplete="new-password"
            disabled={busy}
          />
          <input
            type="password"
            className="vpr-input"
            placeholder={tr("vpr.confirmPassword")}
            aria-label={tr("vpr.confirmPassword")}
            value={pw2}
            onChange={(e) => setPw2(e.target.value)}
            autoComplete="new-password"
            disabled={busy}
          />
          {pwMismatch && <span className="vpr-sub vpr-warn">{tr("vpr.pwMismatch")}</span>}
          {pwDone && <span className="vpr-sub vpr-ok">{tr("vpr.pwDone")}</span>}
          <button type="submit" className="vanitas-queue-btn vpr-self-start" disabled={busy || pw.length < 8 || pw !== pw2}>
            {tr("vpr.setPassword")}
          </button>
        </form>
      )}

      {error && <p className="error-note" style={{ margin: 0 }}>{error}</p>}
      {!isSelf && (
        <div className="vpr-foot">
          <ConfirmButton label={tr("vpr.deleteAccount")} confirmLabel={tr("v.confirm")} className="vanitas-danger-btn" onConfirm={handleDelete} />
        </div>
      )}
    </aside>
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

/**
 * "Vanitas" > Administration > Profils (2026-09-10, demande de Nicolas — "des rôles comme dans
 * Intune... un read pour voir et un read-write pour lecture-écriture", puis "gérer les comptes
 * direct de la page plutôt que les paramètres"). Deux vues :
 * - "Profils" : catalogue de profils nommés réutilisables, chacun une matrice
 *   {module: none|read|write} — voir `backend/auth/vanitas_profiles.py` pour le modèle complet et
 *   `AuthContext.jsx`/`vanitasShared.jsx::hasVanitasAccess` pour l'application côté frontend
 *   (confort d'UI, la RÉELLE protection est `require_vanitas_read/write` côté serveur).
 * - "Comptes" : gestion complète des comptes (créer/rôle/profil/réinitialiser/supprimer),
 *   déplacée depuis Paramètres > Gestion des comptes (qui ne garde plus que "Mon compte").
 *
 * Page admin-only (masquée pour un compte viewer, voir VanitasSidebar.jsx) — les routes
 * `/api/vanitas/profiles*` ET `/api/auth/users*` sont `require_admin` côté serveur : gérer QUI a
 * accès à quoi est une action d'administration Pandore (voir api_server.py).
 *
 * Refonte liste + détail (2026-10-24, maquette canvas validée par Nicolas) : bandeau de synthèse
 * (comptes admin/lecteurs, lecteurs avec profil / sans aucun accès — lien vers le premier —,
 * profils inutilisés, comptes non-admin en écriture sur le terminal), bascule "Profils /
 * Comptes" (même motif que Mises à jour / Applications), matrice en sélecteurs segmentés, et
 * l'onglet Comptes passe d'un tableau à une liste + `AccountPanel` (accès effectifs, mot de
 * passe en place). Classes `.vpr-*`.
 */
export default function VanitasProfilesTab() {
  const { user: currentUser } = useAuth();
  const profiles = useVanitasProfiles();
  const [mode, setMode] = useState("profiles");
  const [query, setQuery] = useState("");
  const [selectedProfileId, setSelectedProfileId] = useState(null);
  const [selectedAccount, setSelectedAccount] = useState(null);
  const [showCreateProfile, setShowCreateProfile] = useState(false);
  const [showCreateAccount, setShowCreateAccount] = useState(false);
  const detailRef = useRef(null);
  // Liste des comptes levée ICI — une SEULE source de vérité pour les deux vues (décompte des
  // comptes par profil, garde-fou de suppression, liste des comptes). Bug réel corrigé en
  // septembre : une 2e copie locale laissait le décompte de "Profils" périmé après une
  // assignation faite depuis "Comptes".
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

  const profileList = profiles.state.data;
  const users = accountsState.users;
  const accountsByProfile = useMemo(() => {
    const m = {};
    for (const u of users) if (u.profile_id && u.role !== "admin") (m[u.profile_id] ??= []).push(u.username);
    return m;
  }, [users]);

  const viewers = users.filter((u) => u.role !== "admin");
  const noAccess = viewers.filter((u) => !u.profile_id);
  const unusedProfiles = profileList.filter((p) => !(accountsByProfile[p.id]?.length));
  const profileById = useMemo(() => new Map(profileList.map((p) => [p.id, p])), [profileList]);
  const terminalWriters = viewers.filter((u) => profileById.get(u.profile_id)?.perms?.terminal === "write").length;
  const isSelf = (u) => u.username.toLowerCase() === currentUser?.username?.toLowerCase();

  const q = query.trim().toLowerCase();
  const visibleProfiles = profileList.filter((p) => !q || p.name.toLowerCase().includes(q));
  const visibleAccounts = users.filter((u) => !q || u.username.toLowerCase().includes(q));
  const selectedProfile = visibleProfiles.find((p) => p.id === selectedProfileId) ?? visibleProfiles[0] ?? null;
  const account = visibleAccounts.find((u) => u.username === selectedAccount) ?? visibleAccounts[0] ?? null;

  function select(setter, value) {
    setter(value);
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function switchMode(next) {
    setMode(next);
    setQuery("");
  }

  return (
    <div className="vanitas-hud vpr">
      {profiles.state.error && <p className="vanitas-hud-error">{profiles.state.error}</p>}
      {accountsState.status === "error" && <p className="vanitas-hud-error">{tr("vpr.accountsError")}</p>}

      <section className="vpr-card vpr-sum" aria-label={tr("vpr.sumAria")}>
        <div className="vpr-col">
          <span className="vpr-lbl">{tr("vpr.sum.accounts")}</span>
          <span className="vpr-val accent">{users.length}</span>
          <span className="vpr-sub vpr-small">{tr("vpr.sum.split", { admins: users.length - viewers.length, viewers: viewers.length })}</span>
        </div>
        <div className="vpr-sum-state">
          <span className="vpr-lbl">{tr("vpr.sum.viewerAccess")}</span>
          <span className="vpr-bar" role="img" aria-label={`${tr("vpr.sum.withProfile", { count: viewers.length - noAccess.length })}, ${tr("vpr.sum.noAccess", { count: noAccess.length })}`}>
            {viewers.length - noAccess.length > 0 && <i style={{ flex: viewers.length - noAccess.length, background: "var(--hud-accent)" }} />}
            {noAccess.length > 0 && <i style={{ flex: noAccess.length, background: "var(--hud-warn)" }} />}
          </span>
          <div className="vpr-legend">
            <span className="vpr-leg static">
              <i style={{ background: "var(--hud-accent)" }} />
              {tr("vpr.sum.withProfile", { count: viewers.length - noAccess.length })}
            </span>
            {noAccess.length > 0 ? (
              <button
                type="button"
                className="vpr-leg"
                onClick={() => {
                  switchMode("accounts");
                  select(setSelectedAccount, noAccess[0].username);
                }}
              >
                <i style={{ background: "var(--hud-warn)" }} />
                {tr("vpr.sum.noAccessLink", { count: noAccess.length })}
              </button>
            ) : (
              <span className="vpr-leg static">
                <i style={{ background: "var(--hud-warn)" }} />
                {tr("vpr.sum.noAccess", { count: 0 })}
              </span>
            )}
          </div>
        </div>
        <div className="vpr-col vpr-sum-third">
          <span className="vpr-lbl">{tr("vpr.sum.profiles")}</span>
          <span className="vpr-val">{profileList.length}</span>
          <span className="vpr-sub vpr-small">{tr("vpr.sum.unused", { count: unusedProfiles.length })}</span>
        </div>
        <div className="vpr-col vpr-sum-fourth">
          <span className="vpr-lbl">{tr("vpr.sum.terminal")}</span>
          <span className="vpr-val" style={terminalWriters ? { color: "var(--hud-accent2)" } : undefined}>
            {terminalWriters}
          </span>
          <span className="vpr-sub vpr-small">{tr("vpr.sum.terminalSub")}</span>
        </div>
      </section>

      <p className="vpr-sub vpr-intro">
        {trRich("vpr.intro", { profile: <b>{tr("vpr.intro.profile")}</b>, admin: <b>admin</b>, viewer: <b>{tr("vpr.intro.viewer")}</b> })}
      </p>

      <div className="vpr-split">
        <section className="vpr-card vpr-list" aria-label={tr("vpr.listAria")}>
          <div className="vpr-list-head">
            <span className="vpr-seg" role="tablist" aria-label={tr("vpr.listAria")}>
              <button type="button" role="tab" aria-selected={mode === "profiles"} className={mode === "profiles" ? "on" : ""} onClick={() => switchMode("profiles")}>
                {tr("vpr.tab.profiles")}
              </button>
              <button type="button" role="tab" aria-selected={mode === "accounts"} className={mode === "accounts" ? "on" : ""} onClick={() => switchMode("accounts")}>
                {tr("vpr.tab.accounts")}
              </button>
            </span>
            <button type="button" className="vanitas-wiz-primary-btn" onClick={() => (mode === "profiles" ? setShowCreateProfile(true) : setShowCreateAccount(true))}>
              {mode === "profiles" ? tr("vpr.addProfile") : tr("vpr.addAccount")}
            </button>
          </div>
          <label className="vpr-search-wrap">
            <span className="vpr-sr">{tr(mode === "profiles" ? "vpr.searchProfile" : "vpr.searchAccount")}</span>
            <input
              type="search"
              className="vpr-input"
              placeholder={tr(mode === "profiles" ? "vpr.searchProfile" : "vpr.searchAccount")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoComplete="off"
            />
          </label>

          {mode === "profiles" ? (
            profiles.state.status === "loading" ? (
              <p className="vpr-empty">{tr("v.loading")}</p>
            ) : profileList.length === 0 ? (
              <p className="vpr-empty">{tr("vpr.noProfile")}</p>
            ) : (
              <>
                <div className="vpr-rows">
                  {visibleProfiles.map((p) => {
                    const isSel = selectedProfile?.id === p.id;
                    return (
                      <button key={p.id} type="button" className={`vpr-it${isSel ? " sel" : ""}`} aria-pressed={isSel} onClick={() => select(setSelectedProfileId, p.id)}>
                        <span className="vpr-av sq" aria-hidden="true">
                          {initials(p.name)}
                        </span>
                        <span className="vpr-name">{p.name}</span>
                        <span className="vpr-sub vpr-small">{tr("vpr.assigned", { count: accountsByProfile[p.id]?.length ?? 0 })}</span>
                        <span className="vpr-meta">
                          <LevelDots perms={p.perms} />
                        </span>
                      </button>
                    );
                  })}
                </div>
                <span className="vpr-sub vpr-small vpr-key">
                  <span className="vpr-lv">
                    <i style={{ background: LEVEL_COLOR.read }} />
                    {LEVEL_LABELS.read}
                  </span>
                  <span className="vpr-lv">
                    <i style={{ background: LEVEL_COLOR.write }} />
                    {LEVEL_LABELS.write}
                  </span>
                </span>
              </>
            )
          ) : accountsState.status === "loading" ? (
            <p className="vpr-empty">{tr("v.loading")}</p>
          ) : (
            <div className="vpr-rows">
              {visibleAccounts.map((u) => {
                const isSel = account?.username === u.username;
                const admin = u.role === "admin";
                const prof = profileById.get(u.profile_id);
                return (
                  <button key={u.id ?? u.username} type="button" className={`vpr-it${isSel ? " sel" : ""}`} aria-pressed={isSel} onClick={() => select(setSelectedAccount, u.username)}>
                    <span className="vpr-av" aria-hidden="true">
                      {initials(u.username)}
                    </span>
                    <span className="vpr-name">
                      {u.username}
                      {isSelf(u) && <span className="vpr-sub vpr-normal">{tr("vpr.you")}</span>}
                    </span>
                    <span className="vpr-pill" style={{ "--c": admin ? "var(--hud-warn)" : "var(--hud-accent)" }}>
                      {tr(admin ? "vpr.roleShort.admin" : "vpr.roleShort.viewer")}
                    </span>
                    <span className="vpr-meta">
                      <span className={!admin && !prof ? "vpr-warn" : ""}>{admin ? tr("vpr.fullAccess") : prof ? prof.name : tr("vpr.level.none")}</span>
                      <span>·</span>
                      <span>{tr("vpr.createdOn", { date: fmtDate(u.created_at) })}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        <div ref={detailRef} className="vpr-detail-slot">
          {mode === "profiles" ? (
            selectedProfile ? (
              <ProfileDetailPanel
                key={selectedProfile.id}
                profile={selectedProfile}
                accountNames={accountsByProfile[selectedProfile.id] ?? []}
                onSaved={profiles.refresh}
                onDeleted={() => {
                  setSelectedProfileId(null);
                  profiles.refresh();
                }}
              />
            ) : (
              <div className="vpr-card vpr-empty-panel">
                <p className="vpr-sub">{tr("vpr.pickProfile")}</p>
              </div>
            )
          ) : account ? (
            <AccountPanel
              key={account.username}
              account={account}
              profiles={profileList}
              isSelf={isSelf(account)}
              onChanged={reloadAccounts}
              onDeleted={() => {
                setSelectedAccount(null);
                reloadAccounts();
              }}
            />
          ) : (
            <div className="vpr-card vpr-empty-panel">
              <p className="vpr-sub">{tr("vpr.pickAccount")}</p>
            </div>
          )}
        </div>
      </div>

      {showCreateProfile && (
        <CreateProfileModal
          onClose={() => setShowCreateProfile(false)}
          onCreated={(newId) => {
            profiles.refresh();
            setSelectedProfileId(newId);
          }}
        />
      )}
      {showCreateAccount && <CreateAccountWizard profiles={profileList} onClose={() => setShowCreateAccount(false)} onCreated={reloadAccounts} />}
    </div>
  );
}
