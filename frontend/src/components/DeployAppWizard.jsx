import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { isErrorPayload } from "../hooks/useDashboardData.js";
import CopyButton from "./CopyButton.jsx";
import { IconPicker } from "./IconPicker.jsx";
import { IconDownload, IconPackage, IconUpload } from "./icons.jsx";

/** Toutes les routes `/api/intune/packaging/*` (sauf le téléchargement) répondent en HTTP
 * 200 même en cas d'erreur métier — `handle_tool_errors` (backend/common/http_client.py)
 * encode ça en `{"error": true, "message": ...}`, jamais en HTTP non-2xx. `postJSON`/
 * `postForm` (api.js) ne lèvent donc PAS pour ce genre d'erreur : repéré en testant le
 * backend en direct pendant l'implémentation (une erreur de packaging affichait sinon un
 * écran "Résultat" vide plutôt qu'un message clair). `unwrap` applique ici le même contrat
 * `isErrorPayload` que le reste du dashboard (useDashboardData.js) pour que chaque `catch`
 * de ce composant reçoive bien le message d'erreur métier. */
async function unwrap(promise) {
  const payload = await promise;
  if (isErrorPayload(payload)) {
    throw new Error(payload.message || "Erreur inconnue.");
  }
  return payload;
}

/**
 * Assistant de packaging Win32 pour Intune (2026-08-26, demande de Nicolas) — Catalogue
 * d'application > "Déployer une application". CE COMPOSANT NE PUBLIE RIEN SUR INTUNE : il
 * prépare un livrable (.intunewin + commandes + script de détection) que l'admin colle
 * ensuite À LA MAIN dans l'Intune admin center — voir backend/intune/packaging.py pour le
 * cadrage complet et le détail de chaque appel.
 *
 * Premier modal/dialog de ce dashboard (aucun composant de ce type n'existait avant) — overlay
 * `position: fixed` + panneau centré construit à la main, fermeture sur Échap et clic en
 * dehors reprise du même mécanisme `pointerdown`/`keydown` que le panneau niveau 2 de
 * Sidebar.jsx plutôt que réinventée.
 *
 * V1 scopée aux installeurs MSI (décision explicite de Nicolas, 2026-08-26) — les 6 volets de
 * sa demande initiale (source / packaging / mode / options / détection / publication) sont
 * regroupés en 3 écrans : la génération du `.intunewin` (volet 2) n'a pas de paramètre propre
 * (elle ne dépend que du fichier source), donc pas de round-trip réseau dédié — elle se
 * déclenche avec le reste de la configuration (mode + options + détection) en UN SEUL appel
 * `package_app` à la fin de l'étape "Configuration", puisque c'est le seul moment où toutes
 * les informations nécessaires sont réunies. Le volet 6 ("publication") n'existe pas ici par
 * design : c'est le téléchargement du livrable qui le remplace.
 *
 * Scripts PowerShell (2026-08-27, demande de Nicolas : "mettre la possibilité de mettre un
 * script powershell pour le package via la même solution") — extension du scope MSI ci-dessus,
 * pas une refonte : le type de source est déduit de l'extension du fichier déposé (`.msi` vs
 * `.ps1`, voir `sourceTypeFromFileName`/`intune/packaging.py::_SOURCE_TYPE_BY_EXT`). Trois
 * choix de conception tranchés AVEC Nicolas (`AskUserQuestion`) avant l'implémentation : (1)
 * commande d'installation FIXE (`powershell -executionpolicy bypass -file .\Pandore.ps1`,
 * syntaxe donnée telle quelle par Nicolas) — pas de mode interactif/affiché/silencieux, un
 * script n'a pas ce vocabulaire ; les écrans "Mode d'installation"/"Options complémentaires"
 * sont donc SAUTÉS pour une source PowerShell (voir `handleSourceNext`) ; (2) commande de
 * désinstallation saisie À LA MAIN par l'admin (nouveau champ sur l'écran "Détection", pas de
 * générateur possible pour un script arbitraire) ; (3) détection INCHANGÉE — même gabarit
 * registre `_DETECTION_TEMPLATE` que pour une source MSI, aucune nouvelle stratégie.
 */

/** Glyphes des cartes "Mode d'installation"/"Options complémentaires" (2026-08-26, retour de
 * Nicolas : "revoir le design des boutons... je trouve ça moche") — traits fins, mêmes
 * conventions que `components/icons.jsx` (viewBox 20×20, stroke `currentColor`, coins ronds),
 * dessinés ici plutôt qu'exportés là-bas : glyphes propres à ce wizard, pas des icônes de nav
 * réutilisables ailleurs. */
const modeIconProps = {
  width: 18,
  height: 18,
  viewBox: "0 0 20 20",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": "true",
};

function IconModeInteractive() {
  return (
    <svg {...modeIconProps}>
      <rect x="3" y="3.5" width="14" height="10.5" rx="1.4" />
      <path d="M3 6.6h14" />
      <circle cx="5.2" cy="5.05" r="0.4" fill="currentColor" stroke="none" />
      <path d="M10.5 9.8 15.5 12.2 13.4 12.7 14.6 15 13.4 15.6 12.2 13.3 10.6 14.7Z" fill="currentColor" stroke="none" />
    </svg>
  );
}

function IconModeDisplayed() {
  return (
    <svg {...modeIconProps}>
      <path d="M10 3.4c-2.1 0-3.5 1.6-3.5 3.8v2.2c0 .9-.3 1.6-.9 2.3l-.6.7h10l-.6-.7a3.2 3.2 0 0 1-.9-2.3V7.2c0-2.2-1.4-3.8-3.5-3.8Z" />
      <path d="M8.3 15a1.7 1.7 0 0 0 3.4 0" />
    </svg>
  );
}

function IconModeSilent() {
  return (
    <svg {...modeIconProps}>
      <path d="M10 3.4c-2.1 0-3.5 1.6-3.5 3.8v2.2c0 .9-.3 1.6-.9 2.3l-.6.7h10l-.6-.7a3.2 3.2 0 0 1-.9-2.3V7.2c0-2.2-1.4-3.8-3.5-3.8Z" />
      <path d="M8.3 15a1.7 1.7 0 0 0 3.4 0" />
      <path d="M3.8 16.2 16.2 3.8" />
    </svg>
  );
}

function IconRestartDefault() {
  return (
    <svg {...modeIconProps}>
      <circle cx="10" cy="10" r="6.3" />
      <path d="M7.2 10h5.6" />
    </svg>
  );
}

function IconRestartNever() {
  return (
    <svg {...modeIconProps}>
      <path d="M5 6.2A6.2 6.2 0 0 1 16.1 10" />
      <path d="M16.1 6.6V10h-3.4" />
      <path d="M3.9 14 16.1 3" />
    </svg>
  );
}

function IconRestartPrompt() {
  return (
    <svg {...modeIconProps}>
      <path d="M3.4 5.5h13.2v7.7h-6.3L6.9 16v-2.8H3.4Z" />
      <path d="M10 8.2v1.5" />
      <circle cx="10" cy="11.4" r="0.5" fill="currentColor" stroke="none" />
    </svg>
  );
}

function IconRestartForce() {
  return (
    <svg {...modeIconProps}>
      <path d="M4 10.4A6.2 6.2 0 1 0 5.9 5.9" />
      <path d="M4 6.6v3.8h3.8" />
    </svg>
  );
}

// Exportées (2026-08-26, demande de Nicolas : "modifier les applications... tous les autres
// champs qu'il y avait lors de la configuration") — `EditAppTab.jsx` réutilise ces 3 constantes
// (+ les glyphes `Icon*` qu'elles référencent) pour présenter EXACTEMENT les mêmes choix que le
// wizard sur l'écran de modification d'une app packagée. Contrairement aux petits utilitaires
// dupliqués ailleurs dans ce projet, ces tableaux embarquent 7 glyphes SVG dessinés à la main
// (~90 lignes) — les dupliquer une 2e fois aurait été un vrai risque de dérive visuelle entre
// le wizard et l'écran de modification, pas juste une question de lignes économisées.
export const INSTALL_MODES = [
  {
    key: "interactive",
    label: "Affichage interactif",
    hint: "L'utilisateur peut différer jusqu'à 3 fois.",
    Icon: IconModeInteractive,
  },
  {
    key: "displayed",
    label: "Affichage",
    hint: "Notification visible, sans interaction possible.",
    Icon: IconModeDisplayed,
  },
  { key: "silent", label: "Silencieux", hint: "Aucune notification.", Icon: IconModeSilent },
];

// Un seul comportement de redémarrage à la fois (voir _RESTART_BEHAVIOR_OPTIONS côté backend,
// intune/packaging.py) — présenté en radio, pas en cases indépendantes, pour ne pas pouvoir
// générer une commande incohérente (/norestart ET /forcerestart en même temps).
export const RESTART_BEHAVIORS = [
  { key: "", label: "Comportement par défaut de l'installeur", Icon: IconRestartDefault },
  { key: "norestart", label: "Ne jamais redémarrer", Icon: IconRestartNever },
  { key: "promptrestart", label: "Demander avant de redémarrer", Icon: IconRestartPrompt },
  { key: "forcerestart", label: "Forcer le redémarrage", Icon: IconRestartForce },
];

export const DETECTION_MODES = [
  { key: "greaterOrEqual", label: "Version installée ≥ version cible" },
  { key: "equals", label: "Version installée = version cible" },
];

// Étape "Configuration" scindée en 3 (2026-08-26, retour de Nicolas : "rendre la
// configuration en 3 étapes au lieu d'une... et leur réduire le champ qui est bien trop
// grand") — un seul groupe de champs par écran plutôt que les 3 empilés (mode d'installation +
// options + détection) sur un seul écran, qui rendait le wizard bien plus haut que ses deux
// voisines ("Source"/"Résultat"). État déplacé du (défunt) `ConfigStep` vers
// `DeployAppWizard` pour survivre à la navigation entre les 3 nouveaux écrans.
//
// Deux jeux de libellés (2026-08-27, scripts PowerShell) — les étapes 2/3 ("Mode
// d'installation"/"Options complémentaires") n'ont pas de sens pour une source PowerShell (pas
// de vocabulaire msiexec à choisir), donc SAUTÉES pour ce type de source plutôt que affichées
// vides. `STEP_NUMBERS_*` fait correspondre chaque libellé affiché à son numéro d'étape RÉEL
// (`step`, dans `DeployAppWizard`) — les numéros d'étape restent fixes/sémantiques (2 =
// InstallModeStep, 3 = OptionsStep, peu importe si affichés) pour ne pas avoir à renuméroter
// tout le reste du composant selon le type de source.
const STEP_LABELS_MSI = ["Source", "Mode d'installation", "Options", "Détection", "Résultat"];
const STEP_NUMBERS_MSI = [1, 2, 3, 4, 5];
const STEP_LABELS_POWERSHELL = ["Source", "Détection", "Résultat"];
const STEP_NUMBERS_POWERSHELL = [1, 4, 5];

function sourceTypeFromFileName(fileName) {
  const ext = (fileName || "").toLowerCase().split(".").pop();
  return ext === "ps1" ? "powershell" : "msi";
}

function StepIndicator({ step, sourceType }) {
  const labels = sourceType === "powershell" ? STEP_LABELS_POWERSHELL : STEP_LABELS_MSI;
  const numbers = sourceType === "powershell" ? STEP_NUMBERS_POWERSHELL : STEP_NUMBERS_MSI;
  return (
    <div className="wizard-steps" role="list" aria-label="Étapes de l'assistant">
      {labels.map((label, i) => {
        const n = numbers[i];
        return (
          <div key={label} className={`wizard-step${step === n ? " active" : ""}${step > n ? " done" : ""}`} role="listitem">
            <span className="wizard-step-index">{step > n ? "✓" : i + 1}</span>
            <span className="wizard-step-label">{label}</span>
          </div>
        );
      })}
    </div>
  );
}

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return "—";
  const units = ["o", "Ko", "Mo", "Go"];
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Date de publication d'une release GitHub, affichée à la place de la taille de fichier dans
 * `.wizard-asset-size` (réutilisée telle quelle, générique — juste un texte mono court aligné
 * à droite d'une ligne cliquable, peu importe si c'est une taille ou une date). */
function formatReleaseDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric" });
}

/** Extrait `{owner, repo}` d'une entrée libre — un lien GitHub complet (avec ou sans
 * `https://`, slash final, `.git`, ou segments de chemin en plus comme `/releases`) OU le
 * raccourci `owner/repo` déjà utilisé auparavant (deux champs séparés, fusionnés en un seul
 * ici — 2026-08-26, demande de Nicolas : "se baser plutôt sur un lien... et mettre la
 * possibilité de rechercher comme c'est actuellement aussi", les deux formats doivent
 * cohabiter dans le MÊME champ plutôt que dupliquer l'UI). Renvoie `null` si l'entrée ne
 * contient pas au moins deux segments organisation/dépôt. */
function parseGithubRepoInput(value) {
  const trimmed = (value || "").trim();
  if (!trimmed) return null;
  const withoutProtocol = trimmed.replace(/^https?:\/\//i, "");
  const withoutDomain = withoutProtocol.replace(/^(www\.)?github\.com\//i, "");
  const withoutGitSuffix = withoutDomain.replace(/\.git$/i, "");
  const segments = withoutGitSuffix.split("/").filter(Boolean);
  if (segments.length < 2) return null;
  const [owner, repo] = segments;
  return { owner, repo };
}

/** Étape 1 — dépôt de la source : upload direct OU recherche GitHub Releases. L'admin
 * choisit TOUJOURS l'asset dans la liste renvoyée par GitHub (jamais de sélection
 * automatique) — un repo comme ip7z/7zip publie plusieurs assets par release.
 *
 * `initialFile` (2026-08-26, demande de Nicolas : "pour l'ajout manuel on peut permettre de
 * faire un upload... pour le faire package et le rajouter dans le catalogue") — quand le
 * wizard est ouvert depuis `AddAppTab.jsx` avec un fichier déjà choisi par l'admin (upload
 * direct depuis la carte "Ajout manuel", plutôt que de re-choisir le fichier une deuxième
 * fois dans ce wizard), cette étape dépose ce fichier AUTOMATIQUEMENT au montage et passe
 * directement à l'étape suivante — l'admin choisit ensuite le mode d'installation/options/
 * détection normalement, rien n'est packagé sans passer par ces écrans. */
function SourceStep({ jobId, ensureJob, source, setSource, onNext, initialFile }) {
  const [mode, setMode] = useState("upload");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [repoInput, setRepoInput] = useState("");
  // 2026-08-26, demande de Nicolas ("voir toutes les versions dans le repo git pour pouvoir
  // le changer") : `releases` (toutes les releases du dépôt, juste tag/nom/date) précède
  // `selectedRelease` (assets d'UNE release choisie) — deux écrans successifs au lieu d'un
  // seul appel direct à la dernière release. `repo` mémorise `{owner, repo}` entre la
  // recherche et le choix d'une release (le champ `repoInput` pourrait changer entre-temps).
  const [repo, setRepo] = useState(null);
  const [releases, setReleases] = useState(null);
  const [selectedRelease, setSelectedRelease] = useState(null);
  const fileInputRef = useRef(null);

  async function uploadFile(file) {
    setBusy(true);
    setError(null);
    try {
      const id = await ensureJob();
      const info = await unwrap(api.packaging.uploadSource(id, file));
      setSource(info);
      return info;
    } catch (err) {
      setError(err.message || "Échec du dépôt du fichier.");
      return null;
    } finally {
      setBusy(false);
    }
  }

  async function handleFileChange(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    await uploadFile(file);
  }

  useEffect(() => {
    if (!initialFile || source) return;
    uploadFile(initialFile).then((info) => {
      // `onNext(info)` — PAS `onNext()` (2026-08-27) : cet effet ne s'exécute qu'une fois, au
      // montage, et capture donc la closure `onNext` de CE rendu-là (avant que la source ne
      // soit connue du parent). Passer `info` explicitement laisse `handleSourceNext` déduire
      // le type de source depuis un argument frais plutôt que depuis l'état du parent, qui
      // serait lui périmé dans cette closure.
      if (info) onNext(info);
    });
    // Un seul dépôt automatique au montage — `initialFile` ne change jamais pour une instance
    // donnée du wizard (fourni une fois à l'ouverture depuis AddAppTab.jsx).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleGithubSearch(e) {
    e?.preventDefault();
    const parsed = parseGithubRepoInput(repoInput);
    if (!parsed) {
      setError("Entrée invalide — attendu un lien GitHub (https://github.com/organisation/depot) ou « organisation/depot ».");
      return;
    }
    setBusy(true);
    setError(null);
    setReleases(null);
    setSelectedRelease(null);
    try {
      const id = await ensureJob();
      const data = await unwrap(api.packaging.githubReleases(id, parsed.owner, parsed.repo));
      setRepo(parsed);
      setReleases(data.releases || []);
    } catch (err) {
      setError(err.message || "Échec de la recherche GitHub.");
    } finally {
      setBusy(false);
    }
  }

  async function handleReleasePick(rel) {
    setBusy(true);
    setError(null);
    try {
      const id = await ensureJob();
      const data = await unwrap(api.packaging.githubLookup(id, repo.owner, repo.repo, rel.tagName));
      setSelectedRelease(data);
    } catch (err) {
      setError(err.message || "Échec de la récupération de cette release.");
    } finally {
      setBusy(false);
    }
  }

  async function handleAssetPick(asset) {
    setBusy(true);
    setError(null);
    try {
      const info = await unwrap(api.packaging.githubFetch(jobId, asset.downloadUrl, asset.name, repo?.owner, repo?.repo));
      setSource(info);
    } catch (err) {
      setError(err.message || "Échec du téléchargement de l'asset.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="wizard-step-body">
      <div className="wizard-source-toggle" role="group" aria-label="Origine de la source">
        <button type="button" className={`wizard-toggle-btn${mode === "upload" ? " active" : ""}`} onClick={() => setMode("upload")}>
          Déposer un fichier
        </button>
        <button type="button" className={`wizard-toggle-btn${mode === "github" ? " active" : ""}`} onClick={() => setMode("github")}>
          Depuis GitHub Releases
        </button>
      </div>

      {mode === "upload" && (
        <div className="wizard-source-panel">
          <p className="card-note">Installeur MSI ou script PowerShell (.ps1) de l'application à packager.</p>
          <button type="button" className="wizard-upload-drop" onClick={() => fileInputRef.current?.click()} disabled={busy}>
            <IconUpload />
            <span>Choisir un fichier .msi ou .ps1…</span>
          </button>
          <input ref={fileInputRef} type="file" accept=".msi,.ps1" hidden onChange={handleFileChange} />
        </div>
      )}

      {mode === "github" && (
        <div className="wizard-source-panel">
          <p className="card-note">
            Lien du dépôt (ex. https://github.com/ip7z/7zip) ou raccourci « organisation/dépôt » (ex. ip7z/7zip) —
            liste toutes les releases publiées.
          </p>
          <form className="wizard-github-form" onSubmit={handleGithubSearch}>
            <input
              type="text"
              className="filter-input"
              placeholder="https://github.com/organisation/depot ou organisation/depot"
              value={repoInput}
              onChange={(e) => setRepoInput(e.target.value)}
            />
            <button type="submit" className="wizard-secondary-btn" disabled={busy || !repoInput.trim()}>
              Rechercher
            </button>
          </form>

          {/* Liste des releases (2026-08-26, demande de Nicolas : "voir toutes les versions
              dans le repo git pour pouvoir le changer") — remplace l'ancien appel direct à la
              dernière release : l'admin choisit d'abord LAQUELLE, puis l'asset à l'intérieur,
              deux écrans successifs plutôt qu'un seul. */}
          {releases && !selectedRelease && (
            <div className="wizard-github-assets">
              <p className="filter-chip-group-label">{releases.length} release{releases.length > 1 ? "s" : ""} — choisis une version</p>
              {releases.length === 0 && <p className="empty">Aucune release publiée sur ce dépôt.</p>}
              {releases.map((rel) => (
                <button
                  type="button"
                  key={rel.tagName}
                  className="wizard-asset-row"
                  onClick={() => handleReleasePick(rel)}
                  disabled={busy}
                >
                  <span className="wizard-asset-name">{rel.name || rel.tagName}</span>
                  <span className="wizard-asset-size cve-mono">{formatReleaseDate(rel.publishedAt)}</span>
                </button>
              ))}
            </div>
          )}

          {selectedRelease && (
            <div className="wizard-github-assets">
              <div className="wizard-result-row">
                <p className="filter-chip-group-label">
                  {selectedRelease.tagName || "release"} — choisis l'asset à packager
                </p>
                <button type="button" className="wizard-copy-btn" onClick={() => setSelectedRelease(null)}>
                  ‹ Toutes les versions
                </button>
              </div>
              {selectedRelease.assets.length === 0 && <p className="empty">Aucun asset publié sur cette release.</p>}
              {selectedRelease.assets.map((asset) => (
                <button
                  type="button"
                  key={asset.name}
                  className="wizard-asset-row"
                  onClick={() => handleAssetPick(asset)}
                  disabled={busy}
                >
                  <span className="wizard-asset-name">{asset.name}</span>
                  <span className="wizard-asset-size cve-mono">{formatBytes(asset.sizeBytes)}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {busy && <p className="card-note">Traitement en cours…</p>}
      {error && <p className="error-note">{error}</p>}

      {source && (
        <div className="wizard-source-confirmed">
          <p className="filter-chip-group-label">Source déposée</p>
          <p className="cve-mono cve-small">{source.fileName} · {formatBytes(source.sizeBytes)}</p>
          <p className="cve-mono cve-small wizard-sha" title="SHA256 — à comparer visuellement avec la source d'origine si besoin">
            SHA256 : {source.sha256}
          </p>
        </div>
      )}

      <div className="wizard-actions">
        <button type="button" className="wizard-primary-btn" disabled={!source} onClick={() => onNext(source)}>
          Suivant
        </button>
      </div>
    </div>
  );
}

/** Étape 2 — mode d'installation seul (1er tiers de l'ex-`ConfigStep`, voir plus haut). Pas
 * d'appel réseau ici — juste un choix mémorisé dans l'état du parent (`DeployAppWizard`).
 *
 * Cartes `.wizard-mode-card` (2026-08-26, retour de Nicolas : "revoir le design des boutons...
 * je trouve ça moche") — remplace la liste de lignes radio bordées (`.wizard-radio-row`, garde
 * pour "Journalisation détaillée" en case à cocher simple) par une grille de 3 cartes
 * sélectionnables (glyphe + libellé + description), même mécanique `role="radiogroup"` +
 * `<input type="radio">` (visuellement masqué, la carte entière sert de zone cliquable via
 * `<label>`) — accessibilité clavier/lecteur d'écran inchangée. */
function InstallModeStep({ installMode, setInstallMode, onNext, onBack }) {
  return (
    <div className="wizard-step-body">
      <div className="wizard-field-group">
        <p className="filter-chip-group-label">Mode d'installation</p>
        <div className="wizard-mode-grid" role="radiogroup" aria-label="Mode d'installation">
          {INSTALL_MODES.map((m) => (
            <label key={m.key} className="wizard-mode-card">
              <input type="radio" name="installMode" checked={installMode === m.key} onChange={() => setInstallMode(m.key)} />
              <span className="wizard-mode-icon">
                <m.Icon />
              </span>
              <span className="wizard-mode-label">{m.label}</span>
              <span className="wizard-mode-hint">{m.hint}</span>
            </label>
          ))}
        </div>
      </div>

      <div className="wizard-actions">
        <button type="button" className="wizard-secondary-btn" onClick={onBack}>
          Retour
        </button>
        <button type="button" className="wizard-primary-btn" onClick={onNext}>
          Suivant
        </button>
      </div>
    </div>
  );
}

/** Étape 3 — options complémentaires seules (2e tiers de l'ex-`ConfigStep`). Même traitement
 * `.wizard-mode-card` que l'étape 2 ci-dessus (demande explicite de Nicolas : "faire la même
 * [chose] dans la partie 3"), en grille 2 colonnes plutôt que 3 (`.wizard-mode-grid-compact`) —
 * libellés plus longs ("Demander avant de redémarrer") que ceux du mode d'installation. */
function OptionsStep({ restartBehavior, setRestartBehavior, logVerbose, setLogVerbose, onNext, onBack }) {
  return (
    <div className="wizard-step-body">
      <div className="wizard-field-group">
        <p className="filter-chip-group-label">Options complémentaires</p>
        <div
          className="wizard-mode-grid wizard-mode-grid-compact"
          role="radiogroup"
          aria-label="Comportement de redémarrage"
        >
          {RESTART_BEHAVIORS.map((r) => (
            <label key={r.key || "default"} className="wizard-mode-card">
              <input type="radio" name="restartBehavior" checked={restartBehavior === r.key} onChange={() => setRestartBehavior(r.key)} />
              <span className="wizard-mode-icon">
                <r.Icon />
              </span>
              <span className="wizard-mode-label">{r.label}</span>
            </label>
          ))}
        </div>
        <label className="wizard-checkbox-row">
          <input type="checkbox" checked={logVerbose} onChange={(e) => setLogVerbose(e.target.checked)} />
          <span>Journalisation détaillée (/l*v)</span>
        </label>
      </div>

      <div className="wizard-actions">
        <button type="button" className="wizard-secondary-btn" onClick={onBack}>
          Retour
        </button>
        <button type="button" className="wizard-primary-btn" onClick={onNext}>
          Suivant
        </button>
      </div>
    </div>
  );
}

/** Étape 4 — règles de détection (3e tiers de l'ex-`ConfigStep`) + déclenchement du packaging.
 * Ne déclenche AUCUN appel réseau tant que l'admin n'a pas cliqué "Lancer le packaging" : c'est
 * ce clic qui exécute IntuneWinAppUtil.exe côté backend ET génère les commandes/le script en
 * un seul appel (voir intune/packaging.py::package_app) — dernier écran de la config, donc le
 * seul moment où toutes les infos des 3 écrans sont réunies. */
function DetectionStep({
  jobId,
  sourceType,
  installMode,
  restartBehavior,
  logVerbose,
  applicationName,
  setApplicationName,
  version,
  setVersion,
  detectionMode,
  setDetectionMode,
  uninstallCommand,
  setUninstallCommand,
  onPackaged,
  onBack,
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit() {
    setBusy(true);
    setError(null);
    try {
      const options = [restartBehavior, logVerbose ? "logverbose" : null].filter(Boolean);
      const result = await unwrap(
        api.packaging.package(jobId, {
          installMode,
          options,
          applicationName: applicationName.trim(),
          version: version.trim(),
          detectionMode,
          uninstallCommand: uninstallCommand.trim(),
        })
      );
      onPackaged(result);
    } catch (err) {
      setError(err.message || "Échec du packaging.");
    } finally {
      setBusy(false);
    }
  }

  const canSubmit = applicationName.trim() && version.trim() && !busy;

  return (
    <div className="wizard-step-body">
      <div className="wizard-field-group">
        <p className="filter-chip-group-label">Règle de détection</p>
        <div className="wizard-detection-fields">
          <input
            type="text"
            className="filter-input"
            placeholder="Nom de l'application (DisplayName)"
            value={applicationName}
            onChange={(e) => setApplicationName(e.target.value)}
          />
          <input
            type="text"
            className="filter-input"
            placeholder="Version cible (ex. 24.09.0)"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
          />
          <select className="filter-input" value={detectionMode} onChange={(e) => setDetectionMode(e.target.value)}>
            {DETECTION_MODES.map((d) => (
              <option key={d.key} value={d.key}>
                {d.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Source PowerShell uniquement (2026-08-27, demande de Nicolas) — pas de commande de
          désinstallation générable pour un script arbitraire (contrairement au MSI, dérivée
          automatiquement de `installMode`/`options`) : saisie manuelle par l'admin, décision
          explicite tranchée via AskUserQuestion avant l'implémentation. */}
      {sourceType === "powershell" && (
        <div className="wizard-field-group">
          <p className="filter-chip-group-label">Commande de désinstallation</p>
          <p className="card-note">
            Aucune génération automatique possible pour un script — à saisir à la main (ex. commande d'appel de ton
            propre script de désinstallation).
          </p>
          <input
            type="text"
            className="filter-input"
            placeholder="powershell -executionpolicy bypass -file .\Uninstall.ps1"
            value={uninstallCommand}
            onChange={(e) => setUninstallCommand(e.target.value)}
          />
        </div>
      )}

      {error && <p className="error-note">{error}</p>}

      <div className="wizard-actions">
        <button type="button" className="wizard-secondary-btn" onClick={onBack} disabled={busy}>
          Retour
        </button>
        <button type="button" className="wizard-primary-btn" onClick={handleSubmit} disabled={!canSubmit}>
          {busy ? "Packaging en cours…" : "Lancer le packaging"}
        </button>
      </div>
    </div>
  );
}

/** Étape 3 — prévisualisation du livrable + téléchargement. Jamais de publication Intune
 * depuis ce composant : le bouton "Télécharger" récupère un .zip (.intunewin + instructions),
 * la création de l'app dans Intune admin center reste un geste manuel de l'admin.
 *
 * "Ajouter à la bibliothèque" (2026-08-26, demande de Nicolas — remplace le catalogue d'apps
 * détectées de AppCatalogTab.jsx par une bibliothèque qu'il alimente lui-même) : sauvegarde ce
 * résultat de façon PERMANENTE (copie le livrable hors du répertoire scratch du job — voir
 * intune/app_library.py::add_packaged_app) — indépendant du téléchargement direct, l'admin
 * peut faire l'un, l'autre, ou les deux. */
function ResultStep({ jobId, result, onClose, onSavedToLibrary }) {
  const [displayName, setDisplayName] = useState(result.suggestedMetadata?.displayName || "");
  const [publisher, setPublisher] = useState("");
  const [icon, setIcon] = useState(null);
  const [iconContentType, setIconContentType] = useState(null);
  const [iconError, setIconError] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState(null);

  function handleIconPick(nextIcon, nextContentType, nextError) {
    setIcon(nextIcon);
    setIconContentType(nextContentType);
    setIconError(nextError);
  }

  async function handleSave() {
    setSaving(true);
    setSaveError(null);
    try {
      const entry = await unwrap(
        api.appLibrary.addPackaged(jobId, {
          displayName: displayName.trim(),
          publisher: publisher.trim(),
          icon,
          iconContentType,
        })
      );
      setSaved(true);
      onSavedToLibrary(entry);
    } catch (err) {
      setSaveError(err.message || "Échec de l'ajout à la bibliothèque.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="wizard-step-body">
      <p className="card-note">
        <code className="cve-mono">{result.intunewinFileName}</code> généré. Vérifie/ajuste ci-dessous avant de le coller dans
        Intune.
      </p>

      <div className="wizard-result-grid">
        <div className="wizard-result-col">
          <div className="wizard-field-group">
            <div className="wizard-result-row">
              <p className="filter-chip-group-label">Commande d'installation</p>
              <CopyButton text={result.installCommand} />
            </div>
            <pre className="wizard-code-block">{result.installCommand}</pre>
          </div>

          <div className="wizard-field-group">
            <div className="wizard-result-row">
              <p className="filter-chip-group-label">Commande de désinstallation</p>
              <CopyButton text={result.uninstallCommand} />
            </div>
            <pre className="wizard-code-block">{result.uninstallCommand}</pre>
          </div>

          <div className="wizard-field-group">
            <p className="filter-chip-group-label">Configuration requise</p>
            <div className="wizard-requirements">
              {result.requirements?.operatingSystem && (
                <span className="wizard-requirement-badge">{result.requirements.operatingSystem}</span>
              )}
              {result.requirements?.architecture && (
                <span className="wizard-requirement-badge">{result.requirements.architecture}</span>
              )}
            </div>
          </div>
        </div>

        <div className="wizard-result-col">
          <div className="wizard-field-group">
            <div className="wizard-result-row">
              <p className="filter-chip-group-label">Script de détection</p>
              <CopyButton text={result.detectionScript} />
            </div>
            <pre className="wizard-code-block wizard-code-block-tall">{result.detectionScript}</pre>
          </div>
        </div>
      </div>

      <div className="wizard-field-group">
        <p className="filter-chip-group-label">Ajouter à la bibliothèque</p>
        {saved ? (
          <p className="card-note">Ajoutée à la bibliothèque — retrouvable dans Bibliothèque d'application.</p>
        ) : (
          <>
            <div className="wizard-github-form">
              <input
                type="text"
                className="filter-input"
                placeholder="Nom de l'application"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                aria-label="Nom de l'application pour la bibliothèque"
              />
              <input
                type="text"
                className="filter-input"
                placeholder="Éditeur (optionnel)"
                value={publisher}
                onChange={(e) => setPublisher(e.target.value)}
                aria-label="Éditeur pour la bibliothèque"
              />
              <button type="button" className="wizard-secondary-btn" onClick={handleSave} disabled={saving || !displayName.trim()}>
                {saving ? "Ajout…" : "Ajouter"}
              </button>
            </div>
            <IconPicker
              icon={icon}
              iconContentType={iconContentType}
              onPick={handleIconPick}
              onClear={() => handleIconPick(null, null, null)}
              error={iconError}
            />
            {saveError && <p className="error-note">{saveError}</p>}
          </>
        )}
      </div>

      <div className="wizard-actions">
        <button type="button" className="wizard-secondary-btn" onClick={onClose}>
          Fermer
        </button>
        <a className="wizard-primary-btn wizard-download-link" href={api.packaging.downloadUrl(jobId)} download>
          <IconDownload />
          Télécharger le package
        </a>
      </div>
    </div>
  );
}

export default function DeployAppWizard({ onClose, onSavedToLibrary = () => {}, initialFile = null }) {
  const [step, setStep] = useState(1);
  const [jobId, setJobId] = useState(null);
  const [source, setSource] = useState(null);
  // Type de source déduit de l'extension du fichier déposé (2026-08-27, scripts PowerShell) —
  // `null` tant qu'aucune source n'a été déposée (StepIndicator retombe alors sur le jeu de
  // libellés MSI par défaut, voir plus haut).
  const [sourceType, setSourceType] = useState(null);
  const [result, setResult] = useState(null);
  // Config répartie sur 3 écrans (étapes 2/3/4, voir InstallModeStep/OptionsStep/DetectionStep
  // ci-dessus) — état levé ici pour survivre à la navigation entre ces écrans.
  const [installMode, setInstallMode] = useState("silent");
  const [restartBehavior, setRestartBehavior] = useState("");
  const [logVerbose, setLogVerbose] = useState(false);
  const [applicationName, setApplicationName] = useState("");
  const [version, setVersion] = useState("");
  const [detectionMode, setDetectionMode] = useState("greaterOrEqual");
  // Source PowerShell uniquement (2026-08-27) — voir DetectionStep.
  const [uninstallCommand, setUninstallCommand] = useState("");
  const jobPromiseRef = useRef(null);
  const shellRef = useRef(null);

  // Suite de l'étape "Source" (2026-08-27) — reçoit la source FRAÎCHEMENT déposée en argument
  // plutôt que de lire l'état `source` du composant : cette fonction est aussi appelée depuis
  // l'effet de dépôt automatique de SourceStep (`initialFile`), qui capture sa propre closure
  // au montage, AVANT que `source` ne soit connu ici — lire l'état aurait été périmé dans ce
  // cas précis. Une source MSI passe par les écrans 2/3 (mode/options) ; une source PowerShell
  // les saute entièrement (pas de vocabulaire msiexec) et va direct à "Détection".
  function handleSourceNext(info) {
    const type = sourceTypeFromFileName(info?.fileName);
    setSourceType(type);
    setStep(type === "powershell" ? 4 : 2);
  }

  // Un seul job créé pour toute la durée du wizard, quel que soit le nombre de fois où
  // ensureJob() est appelé avant que jobId ne soit posé en state (upload très rapide sur un
  // petit fichier + double-clic accidentel) — mémorise la PROMESSE de création, pas seulement
  // son résultat, pour ne jamais déclencher deux jobs en parallèle par accident.
  async function ensureJob() {
    if (jobId) return jobId;
    if (!jobPromiseRef.current) {
      jobPromiseRef.current = unwrap(api.packaging.createJob())
        .then((r) => r.jobId)
        .catch((err) => {
          // Ne jamais mémoriser une promesse rejetée : sans ce reset, un premier échec
          // (réseau, backend indisponible) condamnerait tout nouvel essai du wizard à
          // rejouer indéfiniment la même erreur sans jamais retenter l'appel.
          jobPromiseRef.current = null;
          throw err;
        });
    }
    const id = await jobPromiseRef.current;
    setJobId(id);
    return id;
  }

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
      {/* Écran "Résultat" élargi (2026-08-26, retour de Nicolas : "utilise plus de largeur pour
          éviter d'avoir à scroller") — seul cet écran passe en 2 colonnes
          (`.wizard-result-grid`, voir ResultStep), donc seul lui bénéficie d'un `.wizard-shell`
          plus large ; les 4 autres écrans (une colonne, contenu bien plus court) gardent la
          largeur d'origine. */}
      <div
        className={`wizard-shell${step === 5 ? " wizard-shell-wide" : ""}`}
        ref={shellRef}
        role="dialog"
        aria-modal="true"
        aria-label="Déployer une application"
      >
        <div className="wizard-header">
          <span className="wizard-header-icon">
            <IconPackage />
          </span>
          <div className="wizard-header-text">
            <h2>Déployer une application</h2>
            <p className="card-note">Prépare un package Win32 pour Intune — ne publie rien automatiquement.</p>
          </div>
          <button type="button" className="deployed-detail-close" onClick={onClose} aria-label="Fermer l'assistant">
            <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        <StepIndicator step={step} sourceType={sourceType} />

        {step === 1 && (
          <SourceStep
            jobId={jobId}
            ensureJob={ensureJob}
            source={source}
            setSource={setSource}
            onNext={handleSourceNext}
            initialFile={initialFile}
          />
        )}
        {step === 2 && (
          <InstallModeStep
            installMode={installMode}
            setInstallMode={setInstallMode}
            onNext={() => setStep(3)}
            onBack={() => setStep(1)}
          />
        )}
        {step === 3 && (
          <OptionsStep
            restartBehavior={restartBehavior}
            setRestartBehavior={setRestartBehavior}
            logVerbose={logVerbose}
            setLogVerbose={setLogVerbose}
            onNext={() => setStep(4)}
            onBack={() => setStep(2)}
          />
        )}
        {step === 4 && (
          <DetectionStep
            jobId={jobId}
            sourceType={sourceType}
            installMode={installMode}
            restartBehavior={restartBehavior}
            logVerbose={logVerbose}
            applicationName={applicationName}
            setApplicationName={setApplicationName}
            version={version}
            setVersion={setVersion}
            detectionMode={detectionMode}
            setDetectionMode={setDetectionMode}
            uninstallCommand={uninstallCommand}
            setUninstallCommand={setUninstallCommand}
            onPackaged={(r) => {
              setResult(r);
              setStep(5);
            }}
            onBack={() => setStep(sourceType === "powershell" ? 1 : 3)}
          />
        )}
        {step === 5 && result && (
          <ResultStep jobId={jobId} result={result} onClose={onClose} onSavedToLibrary={onSavedToLibrary} />
        )}
      </div>
    </div>
  );
}
