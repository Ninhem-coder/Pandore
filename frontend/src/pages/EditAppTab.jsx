import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { isErrorPayload } from "../hooks/useDashboardData.js";
import CopyButton from "../components/CopyButton.jsx";
import { IconPicker } from "../components/IconPicker.jsx";
import { GENERIC_PALETTE } from "../theme.js";
import { DETECTION_MODES, INSTALL_MODES, RESTART_BEHAVIORS } from "../components/DeployAppWizard.jsx";
import { IconSearch, IconUpload, IconWrench } from "../components/icons.jsx";
import { currentLocale, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

/**
 * Onglet "Application" > Administration > "Modifier une application" (2026-08-26, demande de
 * Nicolas — "une nouvelle page en bas d'ajouter une application pour modifier les
 * applications... la version et tous les autres champs qu'il y avait lors de la
 * configuration"). Cadrage tranché AVEC Nicolas (`AskUserQuestion`) : deux volets, pas un seul —
 * 1. La FICHE (nom/éditeur/version/note/logo), pour TOUTE entrée de la bibliothèque, manuelle
 *    ou packagée — les mêmes champs que le formulaire d'ajout manuel (`AddAppTab.jsx`).
 * 2. La CONFIGURATION DE PACKAGING (mode d'installation/options complémentaires/règle de
 *    détection) pour une entrée "packagée" SEULEMENT — remet la main sur les mêmes choix que
 *    l'écran "Configuration" du wizard (`DeployAppWizard.jsx`) et RÉGÉNÈRE les commandes
 *    d'installation/désinstallation + le script de détection en conséquence, SANS ré-exécuter
 *    IntuneWinAppUtil.exe (le `.intunewin` déjà produit ne dépend pas de ces réglages — voir
 *    backend/intune/app_library.py::update_library_app). Une entrée "manuelle" n'a jamais eu de
 *    configuration de packaging, cette section n'apparaît donc pas pour elle.
 *
 * ── Retouches du même après-midi (retour de Nicolas) ──────────────────────────────────────
 * "Le même principe que le catalogue des applications pour les lister" — le sélecteur
 * d'application est passé d'une liste de lignes compactes à la MÊME grille de cartes que
 * `AppCatalogTab.jsx` (`.library-grid`/`.library-card`, recherche + filtre par source) —
 * cohérence visuelle avec le reste de la fonctionnalité "bibliothèque" plutôt qu'un 2e motif de
 * liste. `.library-card` gagne un modificateur `.selectable` (voir styles.css) : ici la carte
 * entière est un bouton qui SÉLECTIONNE l'app à modifier, pas des actions Télécharger/Retirer
 * en pied de carte comme dans le catalogue.
 *
 * "Voir toutes les versions dans le repo git pour pouvoir le changer" (confirmé "les deux" via
 * `AskUserQuestion` : le wizard de packaging ET cet écran) — `RepackageSection` permet, pour
 * une entrée packagée, de déposer un NOUVEL installeur (upload direct ou une AUTRE release
 * GitHub que celle d'origine) puis de "repackager" : ça RÉ-EXÉCUTE réellement
 * IntuneWinAppUtil.exe sur le nouveau fichier (via
 * `packaging.package_app`, PUIS `app_library.py::repackage_library_app` qui remplace le
 * livrable + les commandes/script de l'entrée) — contrairement à la section
 * Configuration ci-dessus qui ne fait que RÉGÉNÉRER le texte sans toucher au fichier. Utilise
 * le mode d'installation/options/détection déjà choisis dans le formulaire au moment du clic
 * (pas de 2e jeu de champs à ressaisir).
 *
 * `INSTALL_MODES`/`RESTART_BEHAVIORS`/`DETECTION_MODES` importées de `DeployAppWizard.jsx`
 * (exportées spécifiquement pour cet usage) plutôt que dupliquées : ces 3 tableaux embarquent 7
 * glyphes SVG dessinés à la main — les dupliquer aurait été un vrai risque de dérive visuelle
 * entre le wizard et cet écran, pas juste des lignes économisées (voir le commentaire
 * d'export dans DeployAppWizard.jsx). Même raisonnement pour `IconPicker`
 * (components/IconPicker.jsx, déjà factorisé pour AddAppTab.jsx/DeployAppWizard.jsx — cet
 * écran est son 3e appelant). `parseGithubRepoInput`/`formatBytes`/`formatReleaseDate`/`unwrap`
 * en revanche restent dupliqués ici (petits utilitaires purs, même convention que
 * `hashString`/`formatDate` ailleurs dans ce fichier/le reste du projet).
 *
 * ── Passage en popup (2026-08-26, encore le même après-midi, retour de Nicolas : "quand je
 * clique sur une app j'aimerais bien que ce soit une pop up avec les différents paramètres au
 * lieu d'avoir à la suite en bas de la page") ──
 * La fiche/configuration/repackaging (ex-2e `<div className="card">` empilée sous la grille de
 * sélection, poussant la page à défiler très bas dès qu'une entrée packagée était choisie —
 * fiche + 3 groupes de config + section repackaging + éventuels blocs "mis à jour") est
 * maintenant un vrai MODAL (`EditAppModal`), même chrome que `DeployAppWizard.jsx`
 * (`.wizard-overlay`/`.wizard-shell`/`.wizard-shell-wide`, fermeture Échap/clic en dehors —
 * copié à l'identique, pas de nouveau mécanisme de modal introduit) plutôt qu'une 2e carte
 * empilée dans le flux normal de la page. La grille de sélection (recherche + filtre + cartes)
 * reste, elle, dans la page — seule la BASCULE sélection→édition change de forme. `EditAppForm`
 * lui-même est inchangé (même props `entry`/`onSaved`), juste déplacé dans ce nouveau
 * conteneur.
 */

/** Même contrat que `unwrap` dans DeployAppWizard.jsx — dupliqué (petite fonction pure, pas le
 * même risque de dérive que les tableaux de config). */
async function unwrap(promise) {
  const payload = await promise;
  if (isErrorPayload(payload)) {
    throw new Error(payload.message || tr("wiz.unknownError"));
  }
  return payload;
}

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

function formatBytes(bytes) {
  if (!bytes || bytes <= 0) return "—";
  const units = tr("wiz.units").split(",");
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toLocaleString(currentLocale(), { maximumFractionDigits: i === 0 ? 0 : 1, minimumFractionDigits: i === 0 ? 0 : 1 })} ${units[i]}`;
}

function formatReleaseDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(currentLocale(), { day: "2-digit", month: "2-digit", year: "numeric" });
}

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(currentLocale(), { day: "2-digit", month: "2-digit", year: "numeric" });
}

function hashString(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

/** Même mécanique que `LibraryIcon` dans AppCatalogTab.jsx (logo si déposé, sinon pastille à
 * l'initiale) — dupliquée (petit composant, pas de logique d'état propre, contrairement à
 * `IconPicker`). */
function EntryIcon({ name, icon }) {
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

/** Copie un bloc de commande/script généré — même motif que `CopyButton` dans
 * `DeployAppWizard.jsx` (non exporté là-bas, dupliqué ici : un composant de 15 lignes, pas le
 * même risque de dérive que les tableaux de config ci-dessus). */
// `key` doubles as the translation suffix (apps.source.<key>).
const SOURCE_FILTERS = [{ key: "all" }, { key: "manual" }, { key: "packaged" }];

/** Carte du sélecteur — même gabarit visuel que `LibraryCard` (AppCatalogTab.jsx), mais SANS
 * pied de carte "Télécharger"/"Retirer" : la carte entière est le bouton, cliquer SÉLECTIONNE
 * l'app pour modification plutôt que de déclencher une action. `.selectable`/`.active` (voir
 * styles.css) portent la sémantique "choisi" avec le même accent ambre que le reste du
 * dashboard (cartes du wizard, filtres actifs…). */
function EditAppPickerCard({ entry, active, onSelect }) {
  const isPackaged = entry.source === "packaged";
  return (
    <button
      type="button"
      className={`library-card selectable${isPackaged ? " packaged" : ""}${active ? " active" : ""}`}
      onClick={() => onSelect(entry.id)}
      aria-pressed={active}
    >
      <div className="library-card-head">
        <EntryIcon name={entry.displayName} icon={entry.icon} />
        <div className="library-card-title">
          <span className="library-card-name" title={entry.displayName}>
            {entry.displayName}
          </span>
          <span className="library-card-meta">{entry.publisher || tr("apps.publisherNotSet")}</span>
        </div>
        {entry.version && <span className="library-version-badge">v{entry.version}</span>}
      </div>
      <div className="library-card-body">
        <div className="library-card-tags">
          <span className={`library-source-badge${isPackaged ? " packaged" : ""}`}>{tr(isPackaged ? "apps.source.packaged" : "apps.source.manual")}</span>
          <span className="library-card-date">{tr("edit.addedOn", { date: formatDate(entry.addedAt) })}</span>
        </div>
      </div>
    </button>
  );
}

/** "Repackager avec une autre version" (2026-08-26, demande de Nicolas : "voir toutes les
 * versions dans le repo git pour pouvoir le changer") — visible SEULEMENT pour une entrée
 * packagée. Gère son propre job de packaging (indépendant de celui, éphémère, qui aurait créé
 * l'entrée à l'origine) : upload direct OU recherche GitHub (toutes les releases, pas juste la
 * dernière — même flux que `SourceStep` dans DeployAppWizard.jsx). Le mode d'installation/
 * options/détection utilisés pour le nouveau packaging sont ceux DÉJÀ choisis dans le
 * formulaire parent au moment du clic sur "Repackager" (props), pas un 2e jeu de champs à
 * ressaisir séparément.
 *
 * `sourceRepo` (2026-08-27, demande de Nicolas : "que ce soit possible d'enregistrer le lien
 * du dépôt Git... pour proposer de modifier la version via les versions dispo sur le repo") —
 * pour une entrée packagée DEPUIS ce changement, le dépôt d'origine (`owner`/`repo`) est
 * maintenant retenu côté backend (voir packaging.py::_write_source_repo/_read_source_repo) et
 * remonté jusqu'ici via `entry.package.repo`. Quand il est connu, cette section démarre déjà
 * en mode GitHub avec la recherche lancée automatiquement — recherche libre toujours possible
 * si l'admin veut changer de dépôt. `None` pour toute entrée packagée AVANT ce changement, ou
 * dont la source était un upload direct (jamais de dépôt à retenir dans ce cas) — pas une
 * erreur, la recherche reste manuelle comme avant dans ces deux cas. */
function RepackageSection({
  entryId,
  installMode,
  options,
  detectionMode,
  uninstallCommand,
  displayName,
  version,
  sourceRepo,
  onRepackaged,
  onVersionSuggested,
}) {
  // Dépôt d'origine connu (2026-08-27, demande de Nicolas : "enregistrer le lien du dépôt Git
  // pour proposer les versions dispo sur le repo lors de la modification") — quand l'entrée a
  // été packagée depuis une release GitHub (`sourceRepo` = `entry.package.repo`, absent pour
  // une source uploadée directement), on démarre déjà en mode GitHub plutôt que sur "Déposer
  // un fichier", et la recherche se lance TOUTE SEULE au montage (voir l'effet plus bas) — pas
  // besoin de retaper "owner/repo" à la main pour changer de version.
  const [mode, setMode] = useState(sourceRepo ? "github" : "upload");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [jobId, setJobId] = useState(null);
  const [source, setSource] = useState(null);
  const [repoInput, setRepoInput] = useState(sourceRepo ? `${sourceRepo.owner}/${sourceRepo.repo}` : "");
  const [repo, setRepo] = useState(null);
  const [releases, setReleases] = useState(null);
  const [selectedRelease, setSelectedRelease] = useState(null);
  const [repackaging, setRepackaging] = useState(false);
  const [repackaged, setRepackaged] = useState(false);
  const jobPromiseRef = useRef(null);
  const fileInputRef = useRef(null);
  const autoSearchedRef = useRef(false);

  async function ensureJob() {
    if (jobId) return jobId;
    if (!jobPromiseRef.current) {
      jobPromiseRef.current = unwrap(api.packaging.createJob())
        .then((r) => r.jobId)
        .catch((err) => {
          jobPromiseRef.current = null;
          throw err;
        });
    }
    const id = await jobPromiseRef.current;
    setJobId(id);
    return id;
  }

  async function handleFileChange(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const id = await ensureJob();
      const info = await unwrap(api.packaging.uploadSource(id, file));
      setSource(info);
    } catch (err) {
      setError(err.message || tr("wiz.uploadFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handleGithubSearch(e) {
    e?.preventDefault();
    const parsed = parseGithubRepoInput(repoInput);
    if (!parsed) {
      setError(tr("wiz.invalidRepo"));
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
      setError(err.message || tr("wiz.githubSearchFailed"));
    } finally {
      setBusy(false);
    }
  }

  // Lance la recherche automatiquement au montage si le dépôt d'origine est déjà connu — une
  // seule fois (`autoSearchedRef`), pour ne pas relancer un appel réseau à chaque re-render.
  // N'écrase rien si l'admin a déjà commencé à taper un autre dépôt entre-temps (peu probable
  // vu que ça se déclenche au montage, mais gardé par prudence).
  useEffect(() => {
    if (!sourceRepo || autoSearchedRef.current) return;
    autoSearchedRef.current = true;
    handleGithubSearch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleReleasePick(rel) {
    setBusy(true);
    setError(null);
    try {
      const id = await ensureJob();
      const data = await unwrap(api.packaging.githubLookup(id, repo.owner, repo.repo, rel.tagName));
      setSelectedRelease(data);
      // Le champ "Version" du formulaire parent sert au script de détection généré — le
      // pré-remplir avec le tag de la release choisie ici évite d'obtenir un livrable pour
      // "26.00" avec un script qui cherche toujours "26.01" parce que l'admin a oublié de le
      // changer à la main (repéré en testant : le premier essai laissait la version périmée).
      onVersionSuggested?.(rel.tagName);
    } catch (err) {
      setError(err.message || tr("wiz.releaseFailed"));
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
      setError(err.message || tr("wiz.assetFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handleRepackage() {
    setRepackaging(true);
    setError(null);
    try {
      await unwrap(
        api.packaging.package(jobId, {
          installMode,
          options,
          applicationName: displayName,
          version,
          detectionMode,
          uninstallCommand,
        })
      );
      const entry = await unwrap(api.appLibrary.repackage(entryId, jobId));
      setRepackaged(true);
      onRepackaged(entry);
    } catch (err) {
      setError(err.message || tr("edit.repackageFailed"));
    } finally {
      setRepackaging(false);
    }
  }

  return (
    <div className="wizard-field-group edit-app-repackage-group">
      <div className="edit-app-section-divider">
        <span>{tr("edit.optionalRepackaging")}</span>
      </div>
      <p className="filter-chip-group-label">{tr("edit.repackageTitle")}</p>
      <p className="card-note">
        {trRich("edit.repackageIntro", {
          strong: <strong>{tr("edit.independent")}</strong>,
          source: sourceRepo ? (
            <>
              {trRich("edit.originRepo", {
                repo: (
                  <span className="cve-mono">
                    {sourceRepo.owner}/{sourceRepo.repo}
                  </span>
                ),
              })}
            </>
          ) : (
            <>{tr("edit.uploadOrRelease")}</>
          ),
        })}
      </p>

      <div className="wizard-source-toggle" role="group" aria-label={tr("edit.newSourceAria")}>
        <button type="button" className={`wizard-toggle-btn${mode === "upload" ? " active" : ""}`} onClick={() => setMode("upload")}>
          {tr("wiz.uploadFile")}
        </button>
        <button type="button" className={`wizard-toggle-btn${mode === "github" ? " active" : ""}`} onClick={() => setMode("github")}>
          {tr("wiz.fromGithub")}
        </button>
      </div>

      {mode === "upload" && (
        <div className="wizard-source-panel">
          <button type="button" className="wizard-upload-drop" onClick={() => fileInputRef.current?.click()} disabled={busy}>
            <IconUpload />
            <span>{tr("apps.chooseFile")}</span>
          </button>
          <input ref={fileInputRef} type="file" accept=".msi,.ps1" hidden onChange={handleFileChange} />
        </div>
      )}

      {mode === "github" && (
        <div className="wizard-source-panel">
          <form className="wizard-github-form" onSubmit={handleGithubSearch}>
            <input
              type="text"
              className="filter-input"
              placeholder={tr("wiz.githubPlaceholder")}
              value={repoInput}
              onChange={(e) => setRepoInput(e.target.value)}
            />
            <button type="submit" className="wizard-secondary-btn" disabled={busy || !repoInput.trim()}>
              {tr("wiz.search")}
            </button>
          </form>

          {releases && !selectedRelease && (
            <div className="wizard-github-assets">
              <p className="filter-chip-group-label">{tr("wiz.releases", { count: releases.length })}</p>
              {releases.length === 0 && <p className="empty">{tr("wiz.noRelease")}</p>}
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
                <p className="filter-chip-group-label">{tr("edit.pickAsset", { tag: selectedRelease.tagName || "release" })}</p>
                <button type="button" className="wizard-copy-btn" onClick={() => setSelectedRelease(null)}>
                  {tr("wiz.allVersions")}
                </button>
              </div>
              {selectedRelease.assets.length === 0 && <p className="empty">{tr("wiz.noAsset")}</p>}
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

      {busy && <p className="card-note">{tr("wiz.processing")}</p>}

      {source && (
        <div className="wizard-source-confirmed">
          <p className="filter-chip-group-label">{tr("edit.newSource")}</p>
          <p className="cve-mono cve-small">{source.fileName} · {formatBytes(source.sizeBytes)}</p>
        </div>
      )}

      {source && !repackaged && (
        <div className="wizard-actions library-manual-actions">
          <button type="button" className="wizard-secondary-btn" onClick={handleRepackage} disabled={repackaging}>
            {repackaging ? tr("edit.repackaging") : tr("edit.repackageWithFile")}
          </button>
        </div>
      )}

      {repackaged && <p className="card-note">{tr("edit.repackaged")}</p>}
      {error && <p className="error-note">{error}</p>}
    </div>
  );
}

/** `key={entry.id}` posée par l'appelant (voir plus bas) — remonte tout l'état local à zéro
 * quand l'admin change d'application sélectionnée, plutôt que de laisser les valeurs d'une
 * fiche fuiter dans la suivante. */
function EditAppForm({ entry, onSaved }) {
  const isPackaged = entry.source === "packaged" && !!entry.package;
  const cfg = (isPackaged && entry.package.config) || {};
  // Absent sur toute entrée packagée AVANT le 2026-08-27 (champ introduit avec le support
  // PowerShell) — repli sur "msi", cohérent avec le repli déjà en place côté backend
  // (app_library.py::update_library_app, `cfg.get("sourceType", "msi")`).
  const sourceType = cfg.sourceType || "msi";
  const isPowershell = isPackaged && sourceType === "powershell";

  const [displayName, setDisplayName] = useState(entry.displayName || "");
  const [publisher, setPublisher] = useState(entry.publisher || "");
  const [version, setVersion] = useState(entry.version || "");
  const [note, setNote] = useState(entry.note || "");

  // Logo : `newIcon` = un nouveau fichier vient d'être choisi (remplace l'existant au save),
  // `removeIcon` = retrait explicite demandé, ni l'un ni l'autre = le logo déjà enregistré sur
  // l'entrée est conservé tel quel (voir update_library_app, backend).
  const [newIcon, setNewIcon] = useState(null);
  const [newIconContentType, setNewIconContentType] = useState(null);
  const [iconError, setIconError] = useState(null);
  const [removeIcon, setRemoveIcon] = useState(false);

  const [installMode, setInstallMode] = useState(cfg.installMode || "silent");
  const [restartBehavior, setRestartBehavior] = useState((cfg.options || []).find((o) => o !== "logverbose") || "");
  const [logVerbose, setLogVerbose] = useState((cfg.options || []).includes("logverbose"));
  const [detectionMode, setDetectionMode] = useState(cfg.detectionMode || "greaterOrEqual");
  // Source PowerShell uniquement (2026-08-27) — commande de désinstallation saisie à la main,
  // pas de générateur possible pour un script arbitraire (même décision que DeployAppWizard.jsx).
  const [uninstallCommand, setUninstallCommand] = useState((isPackaged && entry.package.uninstallCommand) || "");

  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [savedPackage, setSavedPackage] = useState(null);
  const [error, setError] = useState(null);

  function handleIconPick(nextIcon, nextContentType, nextError) {
    setNewIcon(nextIcon);
    setNewIconContentType(nextContentType);
    setIconError(nextError);
    if (nextIcon) setRemoveIcon(false);
  }

  function handleRemoveIcon() {
    setNewIcon(null);
    setNewIconContentType(null);
    setIconError(null);
    setRemoveIcon(true);
  }

  const previewIcon = newIcon || (!removeIcon ? entry.icon?.value : null);
  const previewIconContentType = newIcon ? newIconContentType : entry.icon?.contentType;
  const currentOptions = [restartBehavior, logVerbose ? "logverbose" : null].filter(Boolean);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!displayName.trim()) return;
    setSaving(true);
    setSaved(false);
    setError(null);
    try {
      const result = await api.appLibrary.update(entry.id, {
        displayName: displayName.trim(),
        publisher: publisher.trim(),
        version: version.trim(),
        note: note.trim(),
        icon: newIcon,
        iconContentType: newIconContentType,
        removeIcon,
        installMode: isPackaged && sourceType === "msi" ? installMode : undefined,
        options: isPackaged && sourceType === "msi" ? currentOptions : undefined,
        detectionMode: isPackaged ? detectionMode : undefined,
        uninstallCommand: isPowershell ? uninstallCommand.trim() : undefined,
      });
      if (result?.error) {
        setError(result.message);
      } else {
        setSaved(true);
        setSavedPackage(result.package || null);
        setNewIcon(null);
        setNewIconContentType(null);
        setRemoveIcon(false);
        onSaved(result);
      }
    } catch (err) {
      setError(err.message || tr("edit.updateFailed"));
    } finally {
      setSaving(false);
    }
  }

  function handleRepackaged(updatedEntry) {
    setSaved(true);
    setSavedPackage(updatedEntry.package || null);
    if (updatedEntry.version) setVersion(updatedEntry.version);
    onSaved(updatedEntry);
  }

  return (
    <>
      <form className="library-manual-form" onSubmit={handleSubmit}>
        <div className="library-manual-form-fields">
          <input
            type="text"
            className="filter-input"
            placeholder={tr("apps.namePlaceholder")}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            aria-label={tr("apps.nameAria")}
          />
          <input
            type="text"
            className="filter-input"
            placeholder={tr("apps.publisher")}
            value={publisher}
            onChange={(e) => setPublisher(e.target.value)}
            aria-label={tr("apps.publisher")}
          />
          <input
            type="text"
            className="filter-input"
            placeholder={tr("apps.version")}
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            aria-label={tr("apps.version")}
          />
        </div>
        <input
          type="text"
          className="filter-input library-manual-note"
          placeholder={tr("apps.notePlaceholder")}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          aria-label={tr("apps.note")}
        />
        <IconPicker
          icon={previewIcon}
          iconContentType={previewIconContentType}
          onPick={handleIconPick}
          onClear={handleRemoveIcon}
          error={iconError}
          clearLabel={newIcon ? tr("edit.removeNewLogo") : tr("icon.remove")}
        />

        {isPackaged && (
          <>
            {/* Mode d'installation/Options complémentaires : vocabulaire msiexec, sans objet
                pour une source PowerShell (2026-08-27) — masqués plutôt qu'affichés vides. */}
            {sourceType === "msi" && (
              <>
                <div className="wizard-field-group">
                  <p className="filter-chip-group-label">{tr("wiz.step.installMode")}</p>
                  <div className="wizard-mode-grid" role="radiogroup" aria-label={tr("wiz.step.installMode")}>
                    {INSTALL_MODES.map((m) => (
                      <label key={m.key} className="wizard-mode-card">
                        <input
                          type="radio"
                          name={`editInstallMode-${entry.id}`}
                          checked={installMode === m.key}
                          onChange={() => setInstallMode(m.key)}
                        />
                        <span className="wizard-mode-icon">
                          <m.Icon />
                        </span>
                        <span className="wizard-mode-label">{m.label}</span>
                        <span className="wizard-mode-hint">{m.hint}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="wizard-field-group">
                  <p className="filter-chip-group-label">{tr("wiz.extraOptions")}</p>
                  <div
                    className="wizard-mode-grid wizard-mode-grid-compact"
                    role="radiogroup"
                    aria-label={tr("wiz.restartAria")}
                  >
                    {RESTART_BEHAVIORS.map((r) => (
                      <label key={r.key || "default"} className="wizard-mode-card">
                        <input
                          type="radio"
                          name={`editRestartBehavior-${entry.id}`}
                          checked={restartBehavior === r.key}
                          onChange={() => setRestartBehavior(r.key)}
                        />
                        <span className="wizard-mode-icon">
                          <r.Icon />
                        </span>
                        <span className="wizard-mode-label">{r.label}</span>
                      </label>
                    ))}
                  </div>
                  <label className="wizard-checkbox-row">
                    <input type="checkbox" checked={logVerbose} onChange={(e) => setLogVerbose(e.target.checked)} />
                    <span>{tr("wiz.verboseLog")}</span>
                  </label>
                </div>
              </>
            )}

            {isPowershell && (
              <div className="wizard-field-group">
                <p className="filter-chip-group-label">{tr("apps.uninstallCommand")}</p>
                <p className="card-note">
                  {tr("edit.manualUninstallShort")}
                </p>
                <input
                  type="text"
                  className="filter-input"
                  placeholder="powershell -executionpolicy bypass -file .\Uninstall.ps1"
                  value={uninstallCommand}
                  onChange={(e) => setUninstallCommand(e.target.value)}
                  aria-label={tr("apps.uninstallCommand")}
                />
              </div>
            )}

            <div className="wizard-field-group">
              <p className="filter-chip-group-label">{tr("wiz.detectionRule")}</p>
              <select className="filter-input" value={detectionMode} onChange={(e) => setDetectionMode(e.target.value)}>
                {DETECTION_MODES.map((d) => (
                  <option key={d.key} value={d.key}>
                    {d.label}
                  </option>
                ))}
              </select>
            </div>
          </>
        )}

        <div className="wizard-actions library-manual-actions">
          <button type="submit" className="wizard-secondary-btn" disabled={saving || !displayName.trim()}>
            {saving ? tr("edit.saving") : tr("edit.save")}
          </button>
        </div>
        {error && <p className="error-note">{error}</p>}

        {saved && (
          <div className="wizard-field-group">
            <p className="card-note">{tr("edit.saved")}</p>
            {savedPackage && (
              <>
                <div className="wizard-result-row">
                  <p className="filter-chip-group-label">{tr("edit.installUpdated")}</p>
                  <CopyButton text={savedPackage.installCommand} />
                </div>
                <pre className="wizard-code-block">{savedPackage.installCommand}</pre>
                <div className="wizard-result-row">
                  <p className="filter-chip-group-label">{tr("edit.uninstallUpdated")}</p>
                  <CopyButton text={savedPackage.uninstallCommand} />
                </div>
                <pre className="wizard-code-block">{savedPackage.uninstallCommand}</pre>
                <div className="wizard-result-row">
                  <p className="filter-chip-group-label">{tr("edit.detectionUpdated")}</p>
                  <CopyButton text={savedPackage.detectionScript} />
                </div>
                <pre className="wizard-code-block wizard-code-block-tall">{savedPackage.detectionScript}</pre>
              </>
            )}
          </div>
        )}
      </form>

      {isPackaged && (
        <RepackageSection
          entryId={entry.id}
          installMode={installMode}
          options={currentOptions}
          detectionMode={detectionMode}
          uninstallCommand={uninstallCommand.trim()}
          displayName={displayName.trim() || entry.displayName}
          version={version.trim()}
          sourceRepo={entry.package?.repo || null}
          onRepackaged={handleRepackaged}
          onVersionSuggested={setVersion}
        />
      )}
    </>
  );
}

/** Popup de modification (2026-08-26, retour de Nicolas — voir le commentaire d'en-tête de
 * fichier) — même chrome que `DeployAppWizard.jsx` (`.wizard-overlay`/`.wizard-shell`,
 * fermeture Échap/clic en dehors) : cohérence visuelle entre les deux seuls modals de ce
 * dashboard plutôt qu'un 2e mécanisme de popup. `.wizard-shell-wide` (déjà réservée à l'écran
 * "Résultat" du wizard pour la même raison — beaucoup de contenu, fiche + 3 groupes de config +
 * repackaging) posée ici sans condition : cet écran est toujours dense. */
function EditAppModal({ entry, onClose, onSaved }) {
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

  return (
    <div className="wizard-overlay">
      <div className="wizard-shell wizard-shell-wide" ref={shellRef} role="dialog" aria-modal="true" aria-label={tr("edit.title")}>
        <div className="wizard-header">
          <span className="wizard-header-icon">
            <IconWrench />
          </span>
          <div className="wizard-header-text">
            <h2>{entry.displayName}</h2>
            <p className="card-note">{tr("edit.addedOn", { date: formatDate(entry.addedAt) })}</p>
          </div>
          <button type="button" className="deployed-detail-close" onClick={onClose} aria-label={tr("edit.closeAria")}>
            <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </div>
        <div className="wizard-step-body">
          <EditAppForm entry={entry} onSaved={onSaved} />
        </div>
      </div>
    </div>
  );
}

export default function EditAppTab() {
  const [state, setState] = useState({ status: "loading", entries: [], error: null });
  const [query, setQuery] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [selectedId, setSelectedId] = useState(null);

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

  const packagedCount = state.entries.filter((e) => e.source === "packaged").length;
  const manualCount = state.entries.length - packagedCount;
  const sourceCounts = { all: state.entries.length, manual: manualCount, packaged: packagedCount };

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return state.entries.filter((entry) => {
      if (sourceFilter !== "all" && entry.source !== sourceFilter) return false;
      if (!needle) return true;
      return (entry.displayName || "").toLowerCase().includes(needle) || (entry.publisher || "").toLowerCase().includes(needle);
    });
  }, [state.entries, query, sourceFilter]);

  const selected = state.entries.find((e) => e.id === selectedId) || null;

  // Après un enregistrement réussi, l'entrée modifiée est remplacée dans la liste locale — pas
  // besoin de recharger toute la bibliothèque, la réponse de update_library_app/
  // repackage_library_app renvoie déjà l'entrée complète à jour.
  function handleSaved(updatedEntry) {
    setState((s) => ({ ...s, entries: s.entries.map((e) => (e.id === updatedEntry.id ? updatedEntry : e)) }));
  }

  return (
    <>
      <div className="card">
        <div className="card-head">
          <h2>{tr("edit.title")}</h2>
          <span className="card-note">{tr("apps.entries", { count: state.entries.length })}</span>
        </div>
        <p className="card-note">{tr("edit.pick")}</p>

        {state.status === "loading" && <p className="card-note">{tr("apps.loadingLibrary")}</p>}
        {state.status === "error" && <p className="error-note">{state.error}</p>}
        {state.status === "done" && state.entries.length === 0 && (
          <p className="card-note">{tr("edit.emptyLibrary")}</p>
        )}

        {state.status === "done" && state.entries.length > 0 && (
          <>
            <div className="library-toolbar">
              <div className="library-search">
                <IconSearch />
                <input
                  type="text"
                  className="filter-input library-search-input"
                  placeholder={tr("apps.searchPlaceholder")}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  aria-label={tr("edit.searchAria")}
                />
              </div>
              <div className="library-source-filter" role="group" aria-label={tr("apps.filterSourceAria")}>
                {SOURCE_FILTERS.map((f) => (
                  <button
                    key={f.key}
                    type="button"
                    className={`library-source-chip${sourceFilter === f.key ? " active" : ""}`}
                    onClick={() => setSourceFilter(f.key)}
                  >
                    {tr(`apps.source.${f.key}`)} <span className="chip-count">{sourceCounts[f.key] ?? 0}</span>
                  </button>
                ))}
              </div>
            </div>

            {filtered.length === 0 && <p className="card-note">{tr("edit.noResult")}</p>}
            {filtered.length > 0 && (
              <div className="library-grid">
                {filtered.map((entry) => (
                  <EditAppPickerCard key={entry.id} entry={entry} active={entry.id === selectedId} onSelect={setSelectedId} />
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {selected && (
        <EditAppModal key={selected.id} entry={selected} onClose={() => setSelectedId(null)} onSaved={handleSaved} />
      )}
    </>
  );
}
