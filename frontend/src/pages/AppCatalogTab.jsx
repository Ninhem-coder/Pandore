import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { isErrorPayload } from "../hooks/useDashboardData.js";
import CopyButton from "../components/CopyButton.jsx";
import SummaryCard from "../components/SummaryCard.jsx";
import { GENERIC_PALETTE } from "../theme.js";
import { IconBookmark, IconDownload, IconLibrary, IconPackage, IconSearch } from "../components/icons.jsx";

/**
 * Onglet "Application" > Administration > "Catalogue d'application" (2026-08-26, demande de
 * Nicolas — "deux onglets différents pour l'ajout d'application et le catalogue des
 * applications... dans un sous-onglet Administration en dessous d'Inventaire").
 *
 * ── Historique ──────────────────────────────────────────────────────────────────────────
 * Créé le 2026-08-25 comme catalogue des applications DÉTECTÉES sur le parc
 * (deviceManagement/detectedApps, voir intune/apps.py::get_discovered_apps) — jamais consulté
 * depuis sa création ("Nicolas n'a rien demandé dessus", CLAUDE.md). Le 2026-08-26, demande
 * explicite : "enlève toute la partie avec les discover app... je veux que ce soit une
 * bibliothèque d'app que je peux rajouter". Remplacé intégralement par une BIBLIOTHÈQUE
 * PERSISTANTE (backend/intune/app_library.py, backend/data/app_library.json — même motif de
 * stockage que defender/watchlist.py, CVE suivies) alimentée de deux façons ("les deux",
 * tranché explicitement) : packaging via l'assistant, ou ajout manuel libre.
 *
 * Plus tard le même jour : scission en deux onglets distincts, puis redesign en grille de
 * cartes (`.library-grid`/`.library-card`, `.dossier--wide`) — voir CLAUDE.md pour l'historique
 * complet, trop long pour être répété ici à chaque itération.
 *
 * ── Deuxième redesign : barre de recherche + filtre source + cartes retravaillées (2026-08-26,
 * même jour, skill frontend-design, retour de Nicolas : "je trouve vraiment le design moche...
 * une barre de recherche... base-toi sur des solutions existantes") ──
 * "Solutions existantes" = le motif déjà en place ailleurs dans CE dashboard plutôt qu'une
 * référence externe : `DeployedAppsTab.jsx` a déjà exactement ce besoin (recherche texte +
 * filtre par catégorie en pastilles avec compteur) via `.filter-bar`/`.filter-input`/
 * `.os-filter`/`.os-chip`. `.filter-input` est une classe VRAIMENT générique, réutilisée telle
 * quelle (déjà le cas partout ailleurs dans ce fichier/le reste du dashboard). `.filter-bar`/
 * `.os-filter`/`.os-chip` en revanche sont scopées au filtre OS de `DeployedAppsTab.jsx`
 * (jamais réutilisées ailleurs à ce jour) — même MOTIF visuel repris ici mais dans des classes
 * dédiées (`.library-toolbar`/`.library-source-filter`/`.library-source-chip`), cohérent avec
 * la convention déjà en place sur ce fichier plutôt que de coupler les deux pages.
 *
 * Filtre par texte (nom OU éditeur, insensible à la casse) + par source (Toutes/Manuelle/
 * Packagée, avec compteur par pastille) — appliqués côté client (liste déjà chargée en
 * entier, pas de nouvel appel réseau). Cartes retravaillées : icône passée en tête de ligne
 * (icône à gauche, nom/version à droite, plus proche d'une tuile "app store" qu'un simple badge
 * dans un coin), liseré de couleur en bord gauche selon la source (bleu `--star` = packagée,
 * neutre = manuelle — lecture rapide sans avoir à lire le badge texte), séparateurs discrets
 * entre les 3 zones de la carte (identité / métadonnées / actions) pour casser la carte plate
 * d'avant.
 *
 * ── Popup de détail + date de dernière modification (2026-08-27, demande de Nicolas : "voir la
 * dernière modification plutôt que le ajouté le... une pop avec toutes les infos pour juste
 * copier coller le déploiement et que le téléchargement du package se fasse depuis la") ──
 * `entry.updatedAt` (nouveau champ backend, voir intune/app_library.py — égal à `addedAt` à la
 * création, mis à jour par `update_library_app`/`repackage_library_app`) remplace `addedAt` dans
 * le texte affiché sur chaque carte. Absent sur une entrée créée AVANT ce changement : repli sur
 * `addedAt` (`entry.updatedAt || entry.addedAt`), jamais de date manquante.
 *
 * Cliquer une carte (zone `.library-card-clickable`, tête + corps — PAS le bouton "Retirer",
 * resté hors de cette zone plutôt qu'imbriqué dedans, voir styles.css) ouvre `LibraryDetailModal`
 * : même chrome que les autres popups du dashboard (`.wizard-overlay`/`.wizard-shell`,
 * Échap/clic dehors — copié à l'identique depuis `EditAppTab.jsx::EditAppModal`). Pour une entrée
 * packagée, reprend exactement la mise en page 2 colonnes de l'écran "Résultat" du wizard
 * (`.wizard-result-grid`, commandes à gauche + script de détection à droite, tout en blocs
 * copiables) — LECTURE SEULE, aucun champ éditable ici (ça reste le rôle de "Modifier une
 * application", pas de ce catalogue). Le bouton "Télécharger" (auparavant sur la carte
 * elle-même) vit maintenant DANS cette popup, à la demande explicite de Nicolas — retiré du pied
 * de carte, qui ne garde plus que "Retirer".
 *
 * ── "Système de mise à jour automatique" (2026-08-27, demande de Nicolas, après clarification
 * via AskUserQuestion : bouton manuel — pas de tâche de fond — et asset déduit par substitution
 * de tag avec warning explicite en cas de doute plutôt qu'un choix à l'aveugle) ──
 * Bouton "Vérifier les mises à jour" dans l'en-tête de la carte "Catalogue d'application" →
 * `api.appLibrary.checkUpdates()` (voir intune/app_library.py::check_for_updates) : pour
 * chaque entrée packagée avec un dépôt GitHub connu (`entry.package.repo`, absent sur toute
 * entrée créée/repackagée avant cette fonctionnalité — rien à vérifier pour elles), compare la
 * dernière release du dépôt à la version enregistrée et REPACKAGE réellement (nouveau
 * `.intunewin`, nouvelles commandes/script) celles qui sont périmées. `checkSummary` (état
 * local) affiche un résumé compact après coup (compte par statut) ; la liste est rechargée
 * pour refléter les nouvelles versions. Une entrée où l'asset de la nouvelle version n'a pas pu
 * être déduit avec confiance reste INCHANGÉE mais gagne un badge d'avertissement
 * (`entry.package.updateWarning`, persistant en base jusqu'à résolution manuelle) — visible sur
 * la carte ET dans `LibraryDetailModal`, avec un renvoi vers "Modifier une application" >
 * "Repackager avec une autre version" pour choisir l'asset à la main.
 */

const SOURCE_FILTERS = [
  { key: "all", label: "Toutes" },
  { key: "manual", label: "Manuelle" },
  { key: "packaged", label: "Packagée" },
];

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric" });
}

/** Hash de nom → index de palette déterministe — même mécanisme que `hashString` dans
 * DeployedAppsTab.jsx (dupliqué, pas exporté là-bas, cohérent avec la convention du fichier
 * plutôt que de restructurer un module partagé pour une seule fonction pure de 4 lignes). */
function hashString(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

/** Logo si l'admin en a déposé un (2026-08-26, demande de Nicolas : "mettre un logo à
 * l'application... pour le voir dans le catalogue" — déposé depuis `AddAppTab.jsx`/
 * `DeployAppWizard.jsx`, voir `fileToIconPayload` dans ces deux fichiers), sinon repli sur la
 * pastille à l'initiale, teinte déterministe tirée de `GENERIC_PALETTE` (theme.js — même
 * palette que les camemberts du dashboard). Même bascule logo/repli que `AppIcon`
 * (DeployedAppsTab.jsx), dupliquée en composant dédié plutôt que réutilisée (convention déjà en
 * place sur ce fichier) — la source de l'image diffère (upload direct ici, `largeIcon` Graph
 * là-bas), pas la mécanique d'affichage. */
function LibraryIcon({ name, icon }) {
  const label = name || "?";
  if (icon?.value) {
    return (
      <span className="library-card-icon has-logo">
        <img src={`data:${icon.contentType || "image/png"};base64,${icon.value}`} alt="" />
      </span>
    );
  }
  const color = GENERIC_PALETTE[hashString(label) % GENERIC_PALETTE.length];
  return (
    <span className="library-card-icon" style={{ "--icon-fg": color, "--icon-bg": `${color}26` }}>
      {label.trim().charAt(0).toUpperCase() || "?"}
    </span>
  );
}

/** Copie un bloc de commande/script — même motif que `CopyButton` dans DeployAppWizard.jsx/
 * EditAppTab.jsx (non exporté là-bas, dupliqué ici : composant de 15 lignes, cohérent avec la
 * convention déjà en place sur ce fichier plutôt qu'un module partagé pour si peu). */
/** Popup de détail (2026-08-27, demande de Nicolas — voir le commentaire d'en-tête de fichier)
 * : LECTURE SEULE, montre tout ce qu'il faut pour coller le déploiement dans Intune sans
 * ouvrir "Modifier une application". Même chrome que les autres popups du dashboard
 * (`.wizard-overlay`/`.wizard-shell`, Échap/clic dehors — copié depuis
 * `EditAppTab.jsx::EditAppModal`). */
function LibraryDetailModal({ entry, onClose, onNavigate }) {
  const shellRef = useRef(null);
  const isPackaged = entry.source === "packaged" && !!entry.package;
  const updateWarning = entry.package?.updateWarning || null;

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

  return (
    <div className="wizard-overlay">
      <div
        className={`wizard-shell${isPackaged ? " wizard-shell-wide" : ""}`}
        ref={shellRef}
        role="dialog"
        aria-modal="true"
        aria-label={entry.displayName}
      >
        <div className="wizard-header">
          <LibraryIcon name={entry.displayName} icon={entry.icon} />
          <div className="wizard-header-text">
            <div className="library-detail-title-row">
              <h2>
                {entry.displayName}
                <span className="library-detail-modified">
                  {" "}
                  - Éditeur : {entry.publisher || "non renseigné"} - modifiée le {formatDate(entry.updatedAt || entry.addedAt)}
                </span>
              </h2>
              <div className="library-detail-title-tags">
                <span className={`library-source-badge${isPackaged ? " packaged" : ""}`}>
                  {isPackaged ? "Packagée" : "Manuelle"}
                </span>
                {entry.version && <span className="library-version-badge">v{entry.version}</span>}
              </div>
            </div>
          </div>
          <button type="button" className="deployed-detail-close" onClick={onClose} aria-label="Fermer le détail">
            <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        <div className="wizard-step-body">
          {updateWarning && (
            <div className="wizard-field-group">
              <p className="error-note">{updateWarning.message}</p>
              <button type="button" className="library-inline-link" onClick={() => onNavigate?.("app-edit")}>
                Ouvrir "Modifier une application"
              </button>
            </div>
          )}

          {entry.note && (
            <div className="wizard-field-group">
              <p className="card-note">{entry.note}</p>
            </div>
          )}

          {!isPackaged && (
            <p className="card-note">Ajout manuel — aucun livrable technique associé, rien à copier-coller ici.</p>
          )}

          {isPackaged && (
            <>
              <div className="wizard-result-grid">
                <div className="wizard-result-col">
                  <div className="wizard-field-group">
                    <div className="wizard-result-row">
                      <p className="filter-chip-group-label">Commande d'installation</p>
                      <CopyButton text={entry.package.installCommand} />
                    </div>
                    <pre className="wizard-code-block">{entry.package.installCommand}</pre>
                  </div>

                  <div className="wizard-field-group">
                    <div className="wizard-result-row">
                      <p className="filter-chip-group-label">Commande de désinstallation</p>
                      <CopyButton text={entry.package.uninstallCommand} />
                    </div>
                    <pre className="wizard-code-block">{entry.package.uninstallCommand}</pre>
                  </div>

                  <div className="wizard-field-group">
                    <p className="filter-chip-group-label">Configuration requise</p>
                    <div className="wizard-requirements">
                      {entry.package.requirements?.operatingSystem && (
                        <span className="wizard-requirement-badge">{entry.package.requirements.operatingSystem}</span>
                      )}
                      {entry.package.requirements?.architecture && (
                        <span className="wizard-requirement-badge">{entry.package.requirements.architecture}</span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="wizard-result-col">
                  <div className="wizard-field-group">
                    <div className="wizard-result-row">
                      <p className="filter-chip-group-label">Script de détection</p>
                      <CopyButton text={entry.package.detectionScript} />
                    </div>
                    <pre className="wizard-code-block wizard-code-block-tall">{entry.package.detectionScript}</pre>
                  </div>
                </div>
              </div>

              <div className="wizard-actions library-manual-actions">
                <a
                  className="library-download-btn"
                  href={api.appLibrary.downloadUrl(entry.id)}
                  download
                  title="Télécharger le .intunewin et les instructions"
                >
                  <IconDownload />
                  Télécharger le package
                </a>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/** Une carte = une entrée de bibliothèque, "packagée" (livrable réel) ou "manuelle" (fiche de
 * référence seule). Cliquer la zone tête+corps ouvre le détail en popup (`onOpenDetail`) — le
 * pied de carte (`.library-card-actions`) ne garde que "Retirer", hors de cette zone
 * cliquable (pas de bouton imbriqué dans un élément `role="button"`, voir styles.css). */
function LibraryCard({ entry, onRemove, removing, onOpenDetail }) {
  const isPackaged = entry.source === "packaged";
  function handleKeyDown(e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onOpenDetail(entry);
    }
  }
  return (
    <div className={`library-card${isPackaged ? " packaged" : ""}`}>
      <div
        className="library-card-clickable"
        role="button"
        tabIndex={0}
        onClick={() => onOpenDetail(entry)}
        onKeyDown={handleKeyDown}
      >
        <div className="library-card-head">
          <LibraryIcon name={entry.displayName} icon={entry.icon} />
          <div className="library-card-title">
            <span className="library-card-name" title={entry.displayName}>
              {entry.displayName}
            </span>
            <span className="library-card-meta">{entry.publisher || "Éditeur non renseigné"}</span>
          </div>
          {entry.version && <span className="library-version-badge">v{entry.version}</span>}
        </div>

        <div className="library-card-body">
          <div className="library-card-tags">
            <span className={`library-source-badge${isPackaged ? " packaged" : ""}`}>
              {isPackaged ? "Packagée" : "Manuelle"}
            </span>
            <span className="library-card-date">modifiée le {formatDate(entry.updatedAt || entry.addedAt)}</span>
            {entry.package?.updateWarning && (
              <span className="library-update-warning-badge" title={entry.package.updateWarning.message}>
                Mise à jour {entry.package.updateWarning.latestTag} disponible
              </span>
            )}
          </div>
          {entry.note && <p className="library-card-note">{entry.note}</p>}
        </div>
      </div>

      <div className="library-card-actions">
        <button
          type="button"
          className="library-remove-btn"
          onClick={() => onRemove(entry.id)}
          disabled={removing}
        >
          {removing ? "…" : "Retirer"}
        </button>
      </div>
    </div>
  );
}

export default function AppCatalogTab({ onNavigate }) {
  const [state, setState] = useState({ status: "loading", entries: [], error: null });
  const [removingId, setRemovingId] = useState(null);
  const [query, setQuery] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [detailEntry, setDetailEntry] = useState(null);
  const [checking, setChecking] = useState(false);
  const [checkSummary, setCheckSummary] = useState(null);
  const [checkError, setCheckError] = useState(null);

  const load = useCallback(async () => {
    try {
      const entries = await api.appLibrary.list();
      if (entries?.error) {
        setState({ status: "error", entries: [], error: entries.message });
      } else {
        setState({ status: "done", entries: Array.isArray(entries) ? entries : [], error: null });
      }
    } catch (err) {
      setState({ status: "error", entries: [], error: err.message });
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function handleRemove(entryId) {
    setRemovingId(entryId);
    try {
      await api.appLibrary.remove(entryId);
      await load();
    } catch (err) {
      setState((s) => ({ ...s, error: err.message }));
    } finally {
      setRemovingId(null);
    }
  }

  // "Système de mise à jour automatique" (2026-08-27, demande de Nicolas) — voir le
  // commentaire d'en-tête de fichier. `checkSummary` compte les entrées par statut
  // (`updated`/`needs_review`/`up_to_date`/`error`) pour un résumé compact après coup ; la
  // liste est rechargée pour que les cartes reflètent immédiatement les nouvelles versions/
  // badges d'avertissement éventuels.
  async function handleCheckUpdates() {
    setChecking(true);
    setCheckError(null);
    setCheckSummary(null);
    try {
      const payload = await api.appLibrary.checkUpdates();
      if (isErrorPayload(payload)) {
        setCheckError(payload.message);
      } else {
        const counts = { updated: 0, needs_review: 0, up_to_date: 0, error: 0 };
        for (const r of payload.results || []) {
          counts[r.status] = (counts[r.status] || 0) + 1;
        }
        setCheckSummary({ counts, results: payload.results || [] });
        await load();
      }
    } catch (err) {
      setCheckError(err.message || "Échec de la vérification des mises à jour.");
    } finally {
      setChecking(false);
    }
  }

  const packagedCount = state.entries.filter((e) => e.source === "packaged").length;
  const manualCount = state.entries.length - packagedCount;
  const sourceCounts = { all: state.entries.length, manual: manualCount, packaged: packagedCount };

  const filteredEntries = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return state.entries.filter((entry) => {
      if (sourceFilter !== "all" && entry.source !== sourceFilter) return false;
      if (!needle) return true;
      return (
        (entry.displayName || "").toLowerCase().includes(needle) ||
        (entry.publisher || "").toLowerCase().includes(needle)
      );
    });
  }, [state.entries, query, sourceFilter]);

  const hasActiveFilters = query.trim() !== "" || sourceFilter !== "all";

  return (
    <>
      <div className="strip">
        <SummaryCard
          icon={<IconLibrary />}
          title="Applications en bibliothèque"
          value={state.status === "loading" ? "—" : state.entries.length}
          hint="ajout manuel ou via packaging"
        />
        <SummaryCard
          icon={<IconPackage />}
          title="Packagées via l'assistant"
          value={state.status === "loading" ? "—" : packagedCount}
          hint="livrable .intunewin re-téléchargeable"
        />
      </div>

      <div className="card">
        <div className="card-head">
          <h2>Catalogue d'application</h2>
          <div className="library-card-head-actions">
            <span className="card-note">
              {filteredEntries.length !== state.entries.length
                ? `${filteredEntries.length} / ${state.entries.length} entrée${state.entries.length > 1 ? "s" : ""}`
                : `${state.entries.length} entrée${state.entries.length > 1 ? "s" : ""}`}
            </span>
            {state.status === "done" && packagedCount > 0 && (
              <button type="button" className="wizard-secondary-btn" onClick={handleCheckUpdates} disabled={checking}>
                {checking ? "Vérification…" : "Vérifier les mises à jour"}
              </button>
            )}
          </div>
        </div>

        {checkError && <p className="error-note">{checkError}</p>}

        {checkSummary && (
          <p className="card-note">
            {checkSummary.results.length === 0
              ? "Aucune application avec un dépôt GitHub connu à vérifier."
              : [
                  checkSummary.counts.updated > 0 && `${checkSummary.counts.updated} mise${checkSummary.counts.updated > 1 ? "s" : ""} à jour appliquée${checkSummary.counts.updated > 1 ? "s" : ""}`,
                  checkSummary.counts.needs_review > 0 && `${checkSummary.counts.needs_review} à vérifier manuellement`,
                  checkSummary.counts.up_to_date > 0 && `${checkSummary.counts.up_to_date} déjà à jour`,
                  checkSummary.counts.error > 0 && `${checkSummary.counts.error} erreur${checkSummary.counts.error > 1 ? "s" : ""}`,
                ]
                  .filter(Boolean)
                  .join(" — ")}
          </p>
        )}

        {state.status === "done" && state.entries.length > 0 && (
          <div className="library-toolbar">
            <div className="library-search">
              <IconSearch />
              <input
                type="text"
                className="filter-input library-search-input"
                placeholder="Rechercher par nom d'application ou éditeur…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                aria-label="Rechercher dans le catalogue"
              />
            </div>
            <div className="library-source-filter" role="group" aria-label="Filtrer par source">
              {SOURCE_FILTERS.map((f) => (
                <button
                  key={f.key}
                  type="button"
                  className={`library-source-chip${sourceFilter === f.key ? " active" : ""}`}
                  onClick={() => setSourceFilter(f.key)}
                >
                  {f.label} <span className="chip-count">{sourceCounts[f.key] ?? 0}</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {state.status === "loading" && <p className="card-note">Chargement de la bibliothèque…</p>}
        {state.status === "error" && <p className="error-note">{state.error}</p>}

        {state.status === "done" && state.entries.length === 0 && (
          <div className="vuln-idle-note">
            <IconBookmark />
            <p>
              Aucune application dans la bibliothèque pour l'instant —{" "}
              <button type="button" className="library-inline-link" onClick={() => onNavigate?.("app-add")}>
                ajoutes-en une
              </button>
              .
            </p>
          </div>
        )}

        {state.status === "done" && state.entries.length > 0 && filteredEntries.length === 0 && (
          <div className="vuln-idle-note">
            <IconSearch />
            <p>
              Aucun résultat{hasActiveFilters ? " pour ce filtre" : ""} —{" "}
              <button
                type="button"
                className="library-inline-link"
                onClick={() => {
                  setQuery("");
                  setSourceFilter("all");
                }}
              >
                réinitialiser
              </button>
              .
            </p>
          </div>
        )}

        {state.status === "done" && filteredEntries.length > 0 && (
          <div className="library-grid">
            {filteredEntries.map((entry) => (
              <LibraryCard
                key={entry.id}
                entry={entry}
                onRemove={handleRemove}
                removing={removingId === entry.id}
                onOpenDetail={setDetailEntry}
              />
            ))}
          </div>
        )}
      </div>

      {detailEntry && (
        <LibraryDetailModal entry={detailEntry} onClose={() => setDetailEntry(null)} onNavigate={onNavigate} />
      )}
    </>
  );
}
