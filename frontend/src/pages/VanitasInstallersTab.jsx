import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { invalidateCache } from "../cache.js";
import { IconPackage, IconTerminal, IconWrench, IconUpload, IconRefresh } from "../components/icons.jsx";
import { INSTALL_MODES, RESTART_BEHAVIORS } from "../components/DeployAppWizard.jsx";
import {
  isErrorPayload,
  useVanitasAgentPackages,
  useVanitasAgents,
  useVanitasGroups,
  useVanitasInstallerDeployments,
  useVanitasInstallers,
} from "../hooks/useDashboardData.js";
import CopyButton from "../components/CopyButton.jsx";
import { ConfirmButton, VanitasWizardShell, fmtBytes, fmtDateTime, fmtRelative } from "./vanitasShared.jsx";
import { currentLocale, localizedTable, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

// Même mapping EXACT que `backend/intune/packaging.py::_INSTALL_MODE_UI_FLAGS`/
// `_msi_commands` (assistant de packaging Win32 de Pandore) — dupliqué ici en quelques lignes
// plutôt qu'importé : convention Windows fixe (pas de la logique métier propre à Pandore), et
// ce projet (Vanitas) est un serveur/frontend séparé qui ne peut de toute façon pas importer
// le backend Pandore. La commande finale est calculée CÔTÉ FRONTEND puis envoyée telle quelle
// au serveur Vanitas (`install_command`, une chaîne déjà prête) — pas de champ
// `install_mode`/`restart_behavior` séparé côté backend, aucun changement de contrat nécessaire.
const MSI_UI_FLAGS = { interactive: "", displayed: "/qb!", silent: "/qn" };
const MSI_RESTART_FLAGS = { "": "", norestart: "/norestart", promptrestart: "/promptrestart", forcerestart: "/forcerestart" };

function computeMsiInstallCommand(filename, installMode, restartBehavior) {
  const uiFlag = MSI_UI_FLAGS[installMode] ?? "/qn";
  const restartFlag = MSI_RESTART_FLAGS[restartBehavior] ?? "";
  return ["msiexec", "/i", `"${filename}"`, uiFlag, restartFlag].filter(Boolean).join(" ");
}

function sourceTypeFromFileName(fileName) {
  const ext = (fileName || "").toLowerCase().split(".").pop();
  if (ext === "msi") return "msi";
  if (ext === "ps1") return "powershell";
  return "other";
}

/** Extrait `{owner, repo}` d'une entrée libre — un lien GitHub complet OU le raccourci
 * `owner/repo` (2026-09-11, même fonction que `DeployAppWizard.jsx::parseGithubRepoInput`
 * côté Pandore, dupliquée ici — Vanitas est un module frontend séparé, pas d'import
 * cross-feature pour quelques lignes de parsing). `null` si moins de 2 segments. */
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

function formatReleaseDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString(currentLocale());
  } catch {
    return "—";
  }
}

// Un identifiant/type par installeur (2026-09-09, maquette validée par Nicolas) — mêmes
// couleurs `--hud-*` que le Journal d'activité (VanitasActivityLogTab.jsx), teal par défaut
// pour MSI (pas besoin de ton dédié, c'est déjà l'accent de base de cette page).
const TYPE_META = {
  msi: { label: "MSI", color: "var(--hud-accent)", dim: "var(--hud-accent-dim)", Icon: IconPackage },
  powershell: { label: "PS1", color: "var(--hud-accent2)", dim: "var(--hud-accent2-dim)", Icon: IconTerminal },
  other: {
    get label() {
      return tr("vin.type.other");
    },
    color: "var(--hud-warn)", dim: "var(--hud-warn-soft)", Icon: IconWrench },
};
const TYPE_ORDER = ["msi", "powershell", "other"];

/** Icône "coche" du dernier écran de l'assistant — inline plutôt que dans icons.jsx (motif
 * déjà établi ailleurs sur ce dashboard pour un glyphe de chrome de popup à usage unique, voir
 * le bouton de fermeture d'ActivityDetailModal.jsx). */
function CheckIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 10.5l4 4 8-9" />
    </svg>
  );
}
function PencilIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.5 3.5l2 2L6 16H4v-2z" />
    </svg>
  );
}
function DropIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 3v10M6 7l4-4 4 4" />
      <path d="M4 15v1a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1v-1" />
    </svg>
  );
}

/** Une carte du catalogue — réutilisée TELLE QUELLE pour l'aperçu de l'étape "Résultat" de
 * l'assistant (`readOnly`, masque les actions Modifier/Supprimer) : même composant, pas une
 * redérivation, pour que l'aperçu en fin d'assistant soit un reflet fidèle de ce qui apparaîtra
 * réellement dans le catalogue. */
function InstallerCard({ installer, onEdit, onDelete, onDeploy, readOnly }) {
  const type = sourceTypeFromFileName(installer.original_filename);
  const meta = TYPE_META[type];
  return (
    <div className="installer-card" style={{ "--type-c": meta.color, "--type-dim": meta.dim }}>
      <div className="installer-card-top">
        <div className="installer-card-icon">
          <meta.Icon />
        </div>
        <div className="installer-card-id">
          <div className="installer-card-name">{installer.name}</div>
          <div className="installer-card-version">{installer.version ? `v${installer.version}` : "—"}</div>
        </div>
        <span className="installer-card-badge">{meta.label}</span>
      </div>
      <div className="installer-card-file">{installer.original_filename}</div>
      <div className="installer-card-cmd">{installer.install_command}</div>
      <div className="installer-card-meta">
        <span>{fmtBytes(installer.size_bytes)}</span>
        <span>{tr("vin.addedOn", { date: fmtDateTime(installer.uploaded_at) })}</span>
      </div>
      {!readOnly && (
        <div className="installer-card-actions">
          <button type="button" className="vanitas-ghost-btn" onClick={() => onEdit(installer)}>
            {tr("vin.edit")}
          </button>
          <ConfirmButton
            label={tr("vin.delete")}
            confirmLabel={tr("v.confirm")}
            className="vanitas-danger-btn"
            onConfirm={() => onDelete(installer.id)}
          />
          <button type="button" className="vanitas-deploy-btn" onClick={() => onDeploy(installer)}>
            {tr("vin.deploy")}
          </button>
        </div>
      )}
    </div>
  );
}

const ADD_STEP_LABELS = localizedTable("vin.step", [1, 2, 3, 4, 5]);

/**
 * Étape "Source" de l'assistant — dépôt local OU recherche GitHub Releases (2026-09-11,
 * demande de Nicolas : "dans application la fonctionnalité permettait de me baser sur un
 * github mais la c'est pas possible sur Vanitas, tu peux regler ca"), même flux à 2 écrans que
 * `DeployAppWizard.jsx::SourceStep` côté Pandore (recherche → liste des releases → liste des
 * assets de la release choisie) — AUCUN téléchargement tant que l'admin n'a pas choisi un
 * asset précis (jamais de sélection automatique, même garde-fou que côté Pandore) ; le
 * téléchargement RÉEL n'a lieu qu'au clic final "Ajouter au catalogue" (voir
 * `handleGithubAssetPick`/`handleAdd` dans `AddInstallerWizard`, qui bundlent
 * téléchargement+ajout au catalogue en un seul appel serveur).
 */
function SourceStep({ file, fileInputRef, onFileChange, githubAsset, onGithubAssetPick }) {
  const [mode, setMode] = useState("upload");
  const [repoInput, setRepoInput] = useState("");
  const [repo, setRepo] = useState(null);
  const [releases, setReleases] = useState(null);
  const [selectedRelease, setSelectedRelease] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleGithubSearch(e) {
    e?.preventDefault();
    const parsed = parseGithubRepoInput(repoInput);
    if (!parsed) {
      setError(tr("vin.gh.invalid"));
      return;
    }
    setBusy(true);
    setError(null);
    setReleases(null);
    setSelectedRelease(null);
    try {
      const data = await api.vanitas.githubInstallerReleases(parsed.owner, parsed.repo);
      if (isErrorPayload(data)) {
        setError(data.message);
      } else {
        setRepo(parsed);
        setReleases(data.releases || []);
      }
    } catch (err) {
      setError(err.message || tr("vin.gh.searchFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handleReleasePick(rel) {
    setBusy(true);
    setError(null);
    try {
      const data = await api.vanitas.githubInstallerRelease(repo.owner, repo.repo, rel.tagName);
      if (isErrorPayload(data)) {
        setError(data.message);
      } else {
        setSelectedRelease(data);
      }
    } catch (err) {
      setError(err.message || tr("vin.gh.releaseFailed"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="installer-source-toggle" role="group" aria-label={tr("vin.sourceOrigin")}>
        <button type="button" className={`vanitas-hud-chip${mode === "upload" ? " active" : ""}`} onClick={() => setMode("upload")}>
          {tr("vin.upload")}
        </button>
        <button type="button" className={`vanitas-hud-chip${mode === "github" ? " active" : ""}`} onClick={() => setMode("github")}>
          {tr("vin.fromGithub")}
        </button>
      </div>

      {mode === "upload" && (
        <label className={`installer-dropzone${file ? " filled" : ""}`}>
          <div className="installer-dropzone-icon">
            <DropIcon />
          </div>
          <div className="installer-dropzone-text">
            <b>{file ? file.name : tr("vin.dropHere")}</b>
            <span>{file ? fmtBytes(file.size) : tr("vin.dropHint")}</span>
          </div>
          <input ref={fileInputRef} type="file" onChange={onFileChange} hidden />
        </label>
      )}

      {mode === "github" && (
        <div className="installer-github-panel">
          <p className="vanitas-hud-empty-note" style={{ margin: "0 0 10px" }}>
            {tr("vin.gh.help")}
          </p>
          <form className="installer-github-form" onSubmit={handleGithubSearch}>
            <input
              type="text"
              className="filter-input"
              style={{ flex: "1 1 auto" }}
              placeholder={tr("vin.gh.placeholder")}
              value={repoInput}
              onChange={(e) => setRepoInput(e.target.value)}
            />
            <button type="submit" className="vanitas-ghost-btn" disabled={busy || !repoInput.trim()}>
              {tr("vin.search")}
            </button>
          </form>

          {releases && !selectedRelease && (
            <div className="installer-github-list">
              <p className="filter-chip-group-label">{tr("vin.releases", { count: releases.length })}</p>
              {releases.length === 0 && <p className="vanitas-hud-empty-note">{tr("vin.noRelease")}</p>}
              {releases.map((rel) => (
                <button type="button" key={rel.tagName} className="installer-asset-row" onClick={() => handleReleasePick(rel)} disabled={busy}>
                  <span className="installer-asset-name">{rel.name || rel.tagName}</span>
                  <span className="installer-asset-size">{formatReleaseDate(rel.publishedAt)}</span>
                </button>
              ))}
            </div>
          )}

          {selectedRelease && (
            <div className="installer-github-list">
              <div className="installer-github-list-head">
                <p className="filter-chip-group-label">{tr("vin.pickAsset", { tag: selectedRelease.tagName || "release" })}</p>
                <button type="button" className="vanitas-ghost-btn" onClick={() => setSelectedRelease(null)}>
                  {tr("vin.allVersions")}
                </button>
              </div>
              {selectedRelease.assets.length === 0 && <p className="vanitas-hud-empty-note">{tr("vin.noAsset")}</p>}
              {selectedRelease.assets.map((asset) => (
                <button
                  type="button"
                  key={asset.name}
                  className={`installer-asset-row${githubAsset?.assetName === asset.name && githubAsset?.downloadUrl === asset.downloadUrl ? " picked" : ""}`}
                  onClick={() => onGithubAssetPick(asset, repo)}
                  disabled={busy}
                >
                  <span className="installer-asset-name">{asset.name}</span>
                  <span className="installer-asset-size">{fmtBytes(asset.sizeBytes)}</span>
                </button>
              ))}
            </div>
          )}

          {githubAsset && (
            <p className="installer-github-picked">
              {trRich("vin.assetPicked", { name: <b>{githubAsset.assetName}</b>, size: fmtBytes(githubAsset.sizeBytes) })}
            </p>
          )}
        </div>
      )}

      {error && <p className="error-note">{error}</p>}
    </>
  );
}

/**
 * Assistant "Ajouter un installeur" (2026-09-09, maquette validée par Nicolas — "je préfère
 * comme dans Pandore les popup étape par étape") : même structure que `DeployAppWizard.jsx`
 * (overlay/shell/indicateur d'étapes cliquables/Retour-Suivant), reskinnée en teal plutôt que
 * réutiliser telle quelle `.wizard-*` (amber, jurerait avec le thème cyberpunk de cette page —
 * défaut identifié en concevant la première maquette de cette page). Séquence d'étapes dérivée
 * du TYPE RÉEL du fichier déposé (`sourceTypeFromFileName`), pas d'un choix manuel — un script
 * PowerShell/EXE saute directement de "Source" à "Informations", les étapes Mode/Redémarrage
 * n'ayant de sens que pour un MSI.
 */
function AddInstallerWizard({ onClose, onAdded }) {
  const [file, setFile] = useState(null);
  // Asset GitHub choisi (2026-09-11, "tu peux regler ca" — parité avec le wizard de packaging
  // Win32 de Pandore) — PAS téléchargé tout de suite : contrairement au job Pandore (job-scopé,
  // téléchargement immédiat puis packaging plus tard), Vanitas n'a qu'UN SEUL appel réseau
  // final (`addInstallerFromGithub`, download+catalogue en une fois côté serveur — voir
  // `vanitas_github_installer.py`) — retarder le téléchargement jusqu'à "Ajouter au catalogue"
  // évite de télécharger un asset que l'admin abandonnerait avant la fin de l'assistant, et
  // garde `file`/`githubAsset` mutuellement exclusifs, un seul "en attente d'envoi" à la fois.
  const [githubAsset, setGithubAsset] = useState(null);
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [installMode, setInstallMode] = useState("silent");
  const [restartBehavior, setRestartBehavior] = useState("");
  const [manualCommand, setManualCommand] = useState("");
  const [stepIdx, setStepIdx] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [created, setCreated] = useState(null);
  const fileInputRef = useRef(null);

  const sourceFileName = file?.name ?? githubAsset?.assetName ?? "";
  const sourceType = useMemo(() => sourceTypeFromFileName(sourceFileName), [sourceFileName]);
  const sequence = sourceType === "msi" ? [1, 2, 3, 4, 5] : [1, 4, 5];
  const activeStep = sequence[stepIdx];

  const installCommand =
    sourceType === "msi" ? computeMsiInstallCommand(sourceFileName, installMode, restartBehavior) : manualCommand;

  function applyPickedSource(fileName) {
    if (sourceTypeFromFileName(fileName) === "powershell") {
      setManualCommand(`powershell -executionpolicy bypass -file ".\\${fileName}"`);
    }
  }

  function handleFileChange(e) {
    const picked = e.target.files?.[0] ?? null;
    setFile(picked);
    setGithubAsset(null);
    if (picked) applyPickedSource(picked.name);
  }

  function handleGithubAssetPick(asset, repo) {
    setFile(null);
    setGithubAsset({ owner: repo.owner, repo: repo.repo, downloadUrl: asset.downloadUrl, assetName: asset.name, sizeBytes: asset.sizeBytes });
    applyPickedSource(asset.name);
  }

  function goTo(idx) {
    setStepIdx(Math.max(0, Math.min(idx, sequence.length - 1)));
  }
  function goNext() {
    goTo(stepIdx + 1);
  }
  function goBack() {
    goTo(stepIdx - 1);
  }

  async function handleAdd() {
    if (!name.trim() || !installCommand.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      const payload = githubAsset
        ? await api.vanitas.addInstallerFromGithub({
            owner: githubAsset.owner,
            repo: githubAsset.repo,
            downloadUrl: githubAsset.downloadUrl,
            assetName: githubAsset.assetName,
            name: name.trim(),
            version: version.trim(),
            installCommand: installCommand.trim(),
          })
        : await (() => {
            const formData = new FormData();
            formData.append("name", name.trim());
            formData.append("version", version.trim());
            formData.append("install_command", installCommand.trim());
            formData.append("file", file);
            return api.vanitas.uploadInstaller(formData);
          })();
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        setCreated(payload);
        goTo(sequence.length - 1);
        onAdded();
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
        <div className="vanitas-wiz-header-icon">
          <IconUpload />
        </div>
        <div className="vanitas-wiz-header-text">
          <h2>{tr("vin.addTitle")}</h2>
          <p>{tr("vin.catalogSub")}</p>
        </div>
      </div>

      <div className="vanitas-wiz-steps">
        {sequence.map((n, i) => (
          <button
            type="button"
            key={n}
            className={`vanitas-wiz-step${i === stepIdx ? " active" : i < stepIdx ? " done" : ""}`}
            onClick={() => goTo(i)}
          >
            <span className="vanitas-wiz-step-idx">{n}</span>
            <span className="vanitas-wiz-step-lbl">{ADD_STEP_LABELS[n]}</span>
          </button>
        ))}
      </div>

      <div className="vanitas-wiz-body">
        {activeStep === 1 && (
          <>
            <SourceStep
              file={file}
              fileInputRef={fileInputRef}
              onFileChange={handleFileChange}
              githubAsset={githubAsset}
              onGithubAssetPick={handleGithubAssetPick}
            />
            <div className="wizard-actions">
              <button type="button" className="vanitas-wiz-primary-btn" disabled={!file && !githubAsset} onClick={goNext}>
                {tr("vin.next")}
              </button>
            </div>
          </>
        )}

        {activeStep === 2 && (
          <>
            <div className="wizard-field-group">
              <p className="filter-chip-group-label">{tr("vin.installMode")}</p>
              <div className="installer-mode-grid g3" role="radiogroup" aria-label={tr("vin.installMode")}>
                {INSTALL_MODES.map((m) => (
                  <label key={m.key} className="installer-mode-card">
                    <input type="radio" name="installerInstallMode" checked={installMode === m.key} onChange={() => setInstallMode(m.key)} />
                    <span className="ic">
                      <m.Icon />
                    </span>
                    <span className="lbl">{m.label}</span>
                    <span className="hint">{m.hint}</span>
                  </label>
                ))}
              </div>
            </div>
            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={goBack}>
                {tr("vin.back")}
              </button>
              <button type="button" className="vanitas-wiz-primary-btn" onClick={goNext}>
                {tr("vin.next")}
              </button>
            </div>
          </>
        )}

        {activeStep === 3 && (
          <>
            <div className="wizard-field-group">
              <p className="filter-chip-group-label">{tr("vin.restart")}</p>
              <div className="installer-mode-grid g4" role="radiogroup" aria-label={tr("vin.restart")}>
                {RESTART_BEHAVIORS.map((r) => (
                  <label key={r.key || "default"} className="installer-mode-card">
                    <input type="radio" name="installerRestartBehavior" checked={restartBehavior === r.key} onChange={() => setRestartBehavior(r.key)} />
                    <span className="ic">
                      <r.Icon />
                    </span>
                    <span className="lbl" style={{ fontSize: "10.5px" }}>
                      {r.label}
                    </span>
                  </label>
                ))}
              </div>
            </div>
            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={goBack}>
                {tr("vin.back")}
              </button>
              <button type="button" className="vanitas-wiz-primary-btn" onClick={goNext}>
                {tr("vin.next")}
              </button>
            </div>
          </>
        )}

        {activeStep === 4 && (
          <>
            <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
              <div style={{ flex: "1 1 220px" }}>
                <p className="filter-chip-group-label">{tr("vin.name")}</p>
                <input className="filter-input" style={{ flex: "none", width: "100%" }} type="text" placeholder={tr("vin.namePlaceholder")} value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
              </div>
              <div style={{ flex: "0 0 140px" }}>
                <p className="filter-chip-group-label">Version</p>
                <input className="filter-input" style={{ flex: "none", width: "100%" }} type="text" placeholder={tr("vin.optional")} value={version} onChange={(e) => setVersion(e.target.value)} disabled={busy} />
              </div>
            </div>

            {sourceType === "msi" ? (
              <div className="wizard-field-group">
                <p className="filter-chip-group-label">{tr("vin.finalCmd")}</p>
                <div className="installer-cmd-final">{installCommand || "—"}</div>
              </div>
            ) : (
              <div className="wizard-field-group">
                <p className="filter-chip-group-label">{tr("vin.installCmd")}</p>
                <input
                  className="filter-input"
                  style={{ flex: "none", width: "100%" }}
                  type="text"
                  value={manualCommand}
                  onChange={(e) => setManualCommand(e.target.value)}
                  placeholder={sourceType === "powershell" ? tr("vin.ps1Placeholder") : tr("vin.exePlaceholder")}
                  disabled={busy}
                />
                {sourceType === "other" && (
                  <p className="vanitas-hud-empty-note" style={{ margin: "6px 0 0" }}>
                    {trRich("vin.noSilentFlag", { s: <code>/S</code>, quiet: <code>/quiet</code> })}
                  </p>
                )}
              </div>
            )}

            {error && <p className="error-note">{error}</p>}

            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={goBack} disabled={busy}>
                {tr("vin.back")}
              </button>
              <button type="button" className="vanitas-wiz-primary-btn" disabled={!name.trim() || !installCommand.trim() || busy} onClick={handleAdd}>
                {busy ? tr("vin.sending") : tr("vin.addToCatalog")}
              </button>
            </div>
          </>
        )}

        {activeStep === 5 && created && (
          <>
            <div className="vanitas-wiz-result-panel">
              <div className="vanitas-wiz-result-check">
                <CheckIcon />
              </div>
              <div className="vanitas-wiz-result-title">{tr("vin.added")}</div>
              <div className="vanitas-wiz-result-sub">{tr("vin.addedSub")}</div>
              <InstallerCard installer={created} readOnly />
            </div>
            <div className="wizard-actions">
              <button type="button" className="vanitas-wiz-primary-btn" onClick={onClose}>
                {tr("vin.close")}
              </button>
            </div>
          </>
        )}
      </div>
    </VanitasWizardShell>
  );
}

/**
 * Popup "Modifier" (2026-09-09) — un seul écran, sans indicateur d'étapes, même précédent que
 * "Modifier une application" côté Pandore (`EditAppModal`) : nom/version/commande d'installation
 * seuls, JAMAIS le fichier lui-même — remplacer le binaire reviendrait à créer un nouvel
 * installeur, hors du périmètre de cette demande précise.
 */
function EditInstallerModal({ installer, onClose, onSaved }) {
  const [name, setName] = useState(installer.name);
  const [version, setVersion] = useState(installer.version || "");
  const [installCommand, setInstallCommand] = useState(installer.install_command);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const canSubmit = name.trim() && installCommand.trim() && !busy;

  async function handleSubmit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.updateInstaller(installer.id, {
        name: name.trim(),
        version: version.trim(),
        install_command: installCommand.trim(),
      });
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        onSaved();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <VanitasWizardShell onClose={onClose} wide>
      <div className="vanitas-wiz-header">
        <div className="vanitas-wiz-header-icon">
          <PencilIcon />
        </div>
        <div className="vanitas-wiz-header-text">
          <h2>{tr("vin.editTitle", { name: installer.name })}</h2>
          <p>{tr("vin.originalFile", { file: installer.original_filename })}</p>
        </div>
      </div>
      <form onSubmit={handleSubmit} className="vanitas-wiz-body">
        <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 100%" }}>
            <p className="filter-chip-group-label">{tr("vin.name")}</p>
            <input className="filter-input" style={{ flex: "none", width: "100%" }} type="text" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
          </div>
        </div>
        <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 100%" }}>
            <p className="filter-chip-group-label">Version</p>
            <input className="filter-input" style={{ flex: "none", width: "100%" }} type="text" value={version} onChange={(e) => setVersion(e.target.value)} disabled={busy} />
          </div>
        </div>
        <div className="wizard-field-group">
          <p className="filter-chip-group-label">{tr("vin.installCmd")}</p>
          <input className="filter-input" style={{ flex: "none", width: "100%" }} type="text" value={installCommand} onChange={(e) => setInstallCommand(e.target.value)} disabled={busy} />
        </div>
        <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
          {tr("vin.editNote", { file: installer.original_filename })}
        </p>
        {error && <p className="error-note">{error}</p>}
        <div className="wizard-actions">
          <button type="button" className="vanitas-ghost-btn" onClick={onClose} disabled={busy}>
            {tr("vin.cancel")}
          </button>
          <button type="submit" className="vanitas-wiz-primary-btn" disabled={!canSubmit}>
            {busy ? tr("vin.saving") : tr("vin.saveChanges")}
          </button>
        </div>
      </form>
    </VanitasWizardShell>
  );
}

/**
 * Popup "Déployer" (2026-09-10, demande de Nicolas — "déployer depuis le catalogue, assigner
 * les groupes ect" ; maquette validée) : un second point d'entrée pour pousser un installeur,
 * en plus de la carte "Pousser une application" déjà en place sur `VanitasGroupDetail.jsx` —
 * celui-ci évite d'avoir à aller chercher le bon groupe depuis sa propre fiche quand on part
 * du catalogue. Cible = un groupe (compte de postes déjà connu, `device_count`) OU un poste
 * unique (recherche texte si le parc est grand) — mêmes routes serveur que le push depuis
 * "Groupes" (`pushInstallToGroup`/`queueCommand`), aucune nouvelle capacité côté backend pour
 * CE geste précis.
 */
function DeployInstallerModal({ installer, groups, agents, onClose, onDeployed, onNavigateVanitas }) {
  const [targetType, setTargetType] = useState("group");
  // Aucune présélection par défaut (ni groupe ni poste) — un push envoie une vraie commande à
  // un vrai poste, quitte à ce que ce soit un simple groupe de test comme dans cette session ;
  // forcer un clic explicite avant que "Déployer" ne s'active évite de pousser par inadvertance
  // vers "le premier de la liste" sans l'avoir choisi consciemment.
  const [groupId, setGroupId] = useState("");
  const [agentQuery, setAgentQuery] = useState("");
  const [agentId, setAgentId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const filteredAgents = useMemo(() => {
    const q = agentQuery.trim().toLowerCase();
    if (!q) return agents;
    return agents.filter((a) => a.hostname.toLowerCase().includes(q));
  }, [agents, agentQuery]);

  const selectedGroup = groups.find((g) => g.id === groupId) ?? null;
  // 🔧 Bug réel trouvé en testant (2026-09-10) : chercher dans `agents` (la liste COMPLÈTE,
  // pas filtrée) laissait `selectedAgent` résolu — et donc "sera poussé vers 1 poste" +
  // bouton actif — même quand la recherche texte avait fait disparaître ce poste de la liste
  // visible (aucune pastille radio cochée à l'écran). Sur ce dashboard, un poste filtré hors
  // de vue reste alors sélectionné EN INTERNE sans qu'on puisse le voir — dangereux pour un
  // geste qui pousse une vraie commande. Cherché dans `filteredAgents` : un poste qui sort du
  // filtre redevient explicitement "aucune sélection" (recap à 0, bouton désactivé) plutôt que
  // de rester silencieusement armé sur un choix qu'on ne voit plus.
  const selectedAgent = filteredAgents.find((a) => a.id === agentId) ?? null;
  const targetCount = targetType === "group" ? selectedGroup?.device_count ?? 0 : selectedAgent ? 1 : 0;
  const targetLabel = targetType === "group" ? selectedGroup?.name : selectedAgent?.hostname;

  async function handleDeploy() {
    if (busy || targetCount === 0) return;
    setBusy(true);
    setError(null);
    try {
      const payload =
        targetType === "group"
          ? await api.vanitas.pushInstallToGroup(groupId, installer.id)
          : await api.vanitas.queueCommand(agentId, "install_application", installer.id);
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        setResult({ count: targetType === "group" ? payload.queued : 1, label: targetLabel });
        // La page "Applications déployées" (cache partagé 2h) doit refléter ce push dès la
        // prochaine visite, pas seulement au bout du TTL — invalidée ici plutôt que côté
        // parent, ce composant est le seul point qui sait qu'un push vient de réussir.
        invalidateCache("vanitasInstallerDeployments");
        onDeployed();
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
        <div className="vanitas-wiz-header-icon">
          <IconUpload />
        </div>
        <div className="vanitas-wiz-header-text">
          <h2>{tr("vin.deployTitle", { name: installer.name })}</h2>
          <p>{tr("vin.catalogSub")}</p>
        </div>
      </div>
      <div className="vanitas-wiz-body">
        {result ? (
          <>
            <div className="vanitas-wiz-result-panel">
              <div className="vanitas-wiz-result-check">
                <CheckIcon />
              </div>
              <div className="vanitas-wiz-result-title">
                {tr("vin.queued", { count: result.count })}
              </div>
              <div className="vanitas-wiz-result-sub">
                {tr("vin.resultSub", { name: installer.name, target: result.label })}
              </div>
            </div>
            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={onClose}>
                {tr("vin.close")}
              </button>
              {onNavigateVanitas && (
                <button
                  type="button"
                  className="vanitas-wiz-primary-btn"
                  onClick={() => {
                    onNavigateVanitas("vanitas-deployed-apps");
                    onClose();
                  }}
                >
                  {tr("vin.viewDeployed")}
                </button>
              )}
            </div>
          </>
        ) : (
          <>
            <div className="wizard-field-group">
              <p className="filter-chip-group-label">{tr("vin.target")}</p>
              <div className="deploy-target-toggle" role="radiogroup" aria-label={tr("vin.targetAria")}>
                <label className={`deploy-target-card${targetType === "group" ? " active" : ""}`}>
                  <input type="radio" name="deployTargetType" checked={targetType === "group"} onChange={() => setTargetType("group")} />
                  {tr("vin.aGroup")}
                </label>
                <label className={`deploy-target-card${targetType === "device" ? " active" : ""}`}>
                  <input type="radio" name="deployTargetType" checked={targetType === "device"} onChange={() => setTargetType("device")} />
                  {tr("vin.aDevice")}
                </label>
              </div>
            </div>

            {targetType === "group" ? (
              <div className="wizard-field-group">
                <p className="filter-chip-group-label">{tr("vin.group")}</p>
                {groups.length === 0 ? (
                  <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
                    {tr("vin.noGroup")}
                  </p>
                ) : (
                  <div className="deploy-picker-list">
                    {groups.map((g) => (
                      <label key={g.id} className={`deploy-picker-row${groupId === g.id ? " checked" : ""}`}>
                        <span>
                          <input type="radio" name="deployGroup" checked={groupId === g.id} onChange={() => setGroupId(g.id)} />
                          {g.name}
                          {g.rules && <span className="deploy-picker-dynamic">{tr("vin.dynamic")}</span>}
                        </span>
                        <span className="deploy-picker-badge">
                          {tr("vin.endpoints", { count: g.device_count })}
                        </span>
                      </label>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="wizard-field-group">
                <p className="filter-chip-group-label">{tr("vin.device")}</p>
                <input
                  className="filter-input"
                  style={{ flex: "none", width: "100%", marginBottom: "8px" }}
                  type="text"
                  placeholder={tr("vin.searchDevice")}
                  value={agentQuery}
                  onChange={(e) => setAgentQuery(e.target.value)}
                  autoComplete="off"
                />
                {agents.length === 0 ? (
                  <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
                    {tr("vin.noDevice")}
                  </p>
                ) : filteredAgents.length === 0 ? (
                  <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
                    {tr("vin.noDeviceMatch")}
                  </p>
                ) : (
                  <div className="deploy-picker-list">
                    {filteredAgents.map((a) => (
                      <label key={a.id} className={`deploy-picker-row${agentId === a.id ? " checked" : ""}`}>
                        <span>
                          <input type="radio" name="deployAgent" checked={agentId === a.id} onChange={() => setAgentId(a.id)} />
                          {a.hostname}
                        </span>
                      </label>
                    ))}
                  </div>
                )}
              </div>
            )}

            <p className="deploy-recap">
              {trRich("vin.recap", { target: <b>{tr("vin.endpoints", { count: targetCount })}</b> })}
            </p>

            {error && <p className="error-note">{error}</p>}

            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={onClose} disabled={busy}>
                {tr("vin.cancel")}
              </button>
              <button
                type="button"
                className="vanitas-wiz-primary-btn"
                disabled={busy || targetCount === 0}
                onClick={handleDeploy}
              >
                {busy ? tr("vin.deploying") : tr("vin.deployTo", { count: targetCount })}
              </button>
            </div>
          </>
        )}
      </div>
    </VanitasWizardShell>
  );
}

/**
 * Popup "Uploader une nouvelle version" de l'agent (2026-09-11, revu — la page dédiée "Mise à
 * jour de l'agent" a été retirée, le catalogue d'upload rejoint cette page. Le déclenchement
 * (pousser la mise à jour vers un poste) reste ailleurs — automatique via
 * `_vanitas_agent_health_loop` côté backend, ou manuel depuis la fiche d'un poste
 * `VanitasDeviceDetail.jsx` — cette popup ne fait QUE gérer le catalogue). Un seul écran,
 * rien à configurer côté mode d'installation : la commande est FIXE pour Vanitas lui-même
 * (`msiexec /i ... /qn /norestart`, voir `UpdateRunner.cs`), contrairement à un installeur
 * applicatif classique.
 */
function UploadAgentPackageModal({ onClose, onUploaded }) {
  const [version, setVersion] = useState("");
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const canSubmit = version.trim() && file && !busy;

  async function handleSubmit(e) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append("version", version.trim());
      formData.append("file", file);
      const payload = await api.vanitas.uploadAgentPackage(formData);
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        onUploaded();
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
        <div className="vanitas-wiz-header-icon">
          <IconRefresh />
        </div>
        <div className="vanitas-wiz-header-text">
          <h2>{tr("vin.agentTitle")}</h2>
          <p>{tr("vin.agentSub")}</p>
        </div>
      </div>
      <form onSubmit={handleSubmit} className="vanitas-wiz-body">
        <div className="wizard-field-group">
          <p className="filter-chip-group-label">Version</p>
          <input
            className="filter-input"
            style={{ flex: "none", width: "100%" }}
            type="text"
            placeholder={tr("vin.agentVersionPlaceholder")}
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            disabled={busy}
            autoComplete="off"
          />
        </div>
        <div className="wizard-field-group">
          <p className="filter-chip-group-label">{tr("vin.msiFile")}</p>
          <label className={`installer-dropzone${file ? " filled" : ""}`}>
            <div className="installer-dropzone-text">
              <b>{file ? file.name : tr("vin.dropMsi")}</b>
              <span>{file ? fmtBytes(file.size) : tr("vin.dropMsiHint")}</span>
            </div>
            <input type="file" accept=".msi" hidden onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          </label>
        </div>
        <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
          {tr("vin.agentNote")}
        </p>
        {error && <p className="error-note">{error}</p>}
        <div className="wizard-actions">
          <button type="button" className="vanitas-ghost-btn" onClick={onClose} disabled={busy}>
            {tr("vin.cancel")}
          </button>
          <button type="submit" className="vanitas-wiz-primary-btn" disabled={!canSubmit}>
            {busy ? tr("vin.sending") : tr("vin.addToCatalog")}
          </button>
        </div>
      </form>
    </VanitasWizardShell>
  );
}

// État de déploiement d'un installeur (refonte 2026-10-24) — mêmes statuts par poste que
// "Applications déployées" (`ok`/`bad`/`pending`, tentative la plus récente côté serveur).
function deployCounts(deployment) {
  const c = { ok: 0, pending: 0, bad: 0, total: 0 };
  for (const d of deployment?.devices ?? []) {
    if (c[d.status] !== undefined) c[d.status]++;
    c.total++;
  }
  return c;
}

const DEPLOY_COLOR = { ok: "var(--hud-good)", pending: "var(--hud-accent)", bad: "var(--hud-high)" };

function DeployBadge({ counts }) {
  if (!counts.total) return <span className="vin-sub vin-small">{tr("vin.never")}</span>;
  const tone = counts.bad ? "bad" : counts.pending ? "pending" : "ok";
  const label = counts.bad
    ? tr("vin.badge.fail", { count: counts.bad })
    : counts.pending
      ? tr("vin.badge.pending", { ok: counts.ok, count: counts.total })
      : tr("vin.badge.ok", { ok: counts.ok, count: counts.total });
  return (
    <span className="vin-pill" style={{ "--c": DEPLOY_COLOR[tone] }}>
      {label}
    </span>
  );
}

function SplitBar({ counts }) {
  return (
    <span className="vin-bar">
      {["ok", "pending", "bad"].map((k) => (counts[k] ? <i key={k} style={{ flex: counts[k], background: DEPLOY_COLOR[k] }} /> : null))}
    </span>
  );
}

function InstallerPanel({ installer, deployment, onDeploy, onEdit, onDelete, onNavigateVanitas }) {
  const type = sourceTypeFromFileName(installer.original_filename);
  const meta = TYPE_META[type];
  const counts = deployCounts(deployment);
  return (
    <aside className="vin-card vin-detail" style={{ "--type-c": meta.color, "--type-dim": meta.dim }} aria-label={tr("vin.detailAria")}>
      <div className="vin-detail-head">
        <span className="vin-ico lg" aria-hidden="true">
          <meta.Icon />
        </span>
        <div className="vin-detail-title">
          <h2>
            {installer.name} {installer.version && <span className="vin-ver">v{installer.version}</span>}
          </h2>
          <span className="vin-sub">{tr("vin.typeAdded", { type: tr(`vin.typeLong.${type}`), date: fmtDateTime(installer.uploaded_at) })}</span>
        </div>
        <button type="button" className="vanitas-wiz-primary-btn" onClick={() => onDeploy(installer)}>
          {tr("vin.deployEllipsis")}
        </button>
      </div>

      <div className="vin-block">
        <span className="vin-lbl">{tr("vin.installCmd")}</span>
        <div className="vin-code">
          <code>{installer.install_command}</code>
          <CopyButton className="vanitas-enroll-copy-btn" text={installer.install_command} />
        </div>
        <span className="vin-sub vin-small">{tr("vin.cmdHint")}</span>
      </div>

      <dl className="vin-kv">
        <dt>{tr("vin.file")}</dt>
        <dd className="vin-mono">{installer.original_filename}</dd>
        <dt>{tr("vin.size")}</dt>
        <dd>{fmtBytes(installer.size_bytes)}</dd>
        <dt>SHA-256</dt>
        <dd className="vin-mono vin-muted">{installer.sha256}</dd>
      </dl>

      <div className="vin-box">
        <div className="vin-box-head">
          <span className="vin-lbl">{tr("vin.deployments")}</span>
          {counts.total > 0 && (
            <button type="button" className="vanitas-ghost-btn" onClick={() => onNavigateVanitas?.("vanitas-deployed-apps")}>
              {tr("vin.viewDeployed")}
            </button>
          )}
        </div>
        {counts.total > 0 ? (
          <>
            <SplitBar counts={counts} />
            <span className="vin-sub">
              {tr("vin.deployLine", { ok: counts.ok, pending: counts.pending, bad: counts.bad })}
              {deployment?.targets?.length ? ` — ${tr("vin.target")} : ${deployment.targets.join(", ")}` : ""}
            </span>
          </>
        ) : (
          <span className="vin-sub">{tr("vin.neverHint")}</span>
        )}
      </div>

      <div className="vin-foot">
        <button type="button" className="vanitas-ghost-btn" onClick={() => onEdit(installer)}>
          {tr("vin.editLong")}
        </button>
        <ConfirmButton label={tr("vin.delete")} confirmLabel={tr("v.confirm")} className="vanitas-danger-btn" onConfirm={() => onDelete(installer.id)} />
      </div>
    </aside>
  );
}

function AgentPackagePanel({ pkg, isLatest, agents, onDelete }) {
  const onVersion = agents.filter((a) => a.agent_version === pkg.version);
  const behind = isLatest ? agents.filter((a) => a.agent_version && a.agent_version !== pkg.version) : [];
  return (
    <aside className="vin-card vin-detail" aria-label={tr("vin.pkgAria")}>
      <div className="vin-detail-head">
        <div className="vin-detail-title">
          <h2>
            Endpoint Agent <span className="vin-ver">v{pkg.version}</span>
          </h2>
          <span className="vin-sub">{tr("vin.uploadedOn", { date: fmtDateTime(pkg.uploaded_at) })}</span>
        </div>
        <span className="vin-pill" style={{ "--c": isLatest ? "var(--hud-good)" : "var(--vin-muted)" }}>
          {tr(isLatest ? "vin.pkgLatest" : "vin.pkgOld")}
        </span>
      </div>

      <div className="vin-box">
        <span className="vin-lbl">{tr("vin.adoption")}</span>
        {agents.length === 0 ? (
          <span className="vin-sub">{tr("vin.noAgent")}</span>
        ) : (
          <>
            <span className="vin-bar">
              {onVersion.length > 0 && <i style={{ flex: onVersion.length, background: "var(--hud-good)" }} />}
              {agents.length - onVersion.length > 0 && <i style={{ flex: agents.length - onVersion.length, background: "var(--hud-warn)" }} />}
            </span>
            <span className="vin-sub">
              {tr("vin.onVersion", { count: onVersion.length, total: agents.length })}
              {isLatest && behind.length > 0 && <> — {tr("vin.behind", { hosts: behind.slice(0, 4).map((a) => a.hostname).join(", ") + (behind.length > 4 ? "…" : "") })}</>}
            </span>
          </>
        )}
      </div>

      <dl className="vin-kv">
        <dt>{tr("vin.file")}</dt>
        <dd className="vin-mono">{pkg.original_filename}</dd>
        <dt>{tr("vin.size")}</dt>
        <dd>{fmtBytes(pkg.size_bytes)}</dd>
        <dt>SHA-256</dt>
        <dd className="vin-mono vin-muted">{pkg.sha256}</dd>
      </dl>

      <div className="vin-foot">
        <ConfirmButton label={tr("vin.deleteVersion")} confirmLabel={tr("v.confirm")} className="vanitas-danger-btn" onConfirm={() => onDelete(pkg.id)} />
      </div>
    </aside>
  );
}

/**
 * "Vanitas" > Administration > Applications (2026-09-08, demande de Nicolas — "un push
 * d'application un peu comme dans Pandore, via les groupes"). Catalogue persistant d'installeurs
 * (upload une fois, repoussé ensuite vers n'importe quel groupe/poste sans re-déposer le
 * fichier) — même esprit que la bibliothèque d'application de Pandore, mais le fichier gardé
 * ici est TOUJOURS l'installeur brut (MSI/EXE/PS1) : c'est l'agent Vanitas lui-même qui
 * l'exécute, pas Intune.
 *
 * Redessinée le 2026-09-09 (maquette validée par Nicolas — "je préfère comme dans Pandore les
 * popup étape par étape") : grille de cartes (au lieu d'un tableau plat) + assistant "Ajouter"
 * en popup étape par étape + popup "Modifier" à un seul écran, plutôt que des formulaires
 * poussés inline dans la page.
 *
 * Le "push vers un groupe" se fait ICI (bouton "↑ Déployer" par carte, popup ci-dessus) OU
 * depuis `VanitasGroupDetail.jsx` (2026-09-08, premier chemin livré) — les deux appellent les
 * mêmes routes serveur, jamais divergé. La LECTURE seule du catalogue (parcourir les
 * applications déjà publiées, sans droits d'écriture) vit à part, voir
 * `VanitasAppCatalogTab.jsx` (remonté sous "Vue d'ensemble").
 *
 * Refonte liste + détail (2026-10-24, maquette canvas validée par Nicolas) : bandeau de synthèse
 * (formats en barre avec légende cliquable, installeurs déjà déployés, version de l'agent et
 * adoption), bascule "Installeurs / Agent Vanitas" en tête de liste (même motif que Mises à
 * jour), détail dans un panneau latéral au lieu des grilles de cartes. Nouveau : état de
 * déploiement par installeur (`useVanitasInstallerDeployments`, même cache qu'"Applications
 * déployées") et adoption de chaque version de l'agent (`agent.agent_version`). Les popups
 * (ajout en 5 étapes, déploiement, modification, envoi d'une version) sont inchangées. Classes
 * `.vin-*` ; `InstallerCard` reste utilisé par l'aperçu final de l'assistant d'ajout.
 */
export default function VanitasInstallersTab({ onNavigateVanitas }) {
  const installers = useVanitasInstallers();
  const deployments = useVanitasInstallerDeployments();
  const groups = useVanitasGroups();
  const agents = useVanitasAgents();
  const agentPackages = useVanitasAgentPackages();
  const [mode, setMode] = useState("installers");
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [selectedId, setSelectedId] = useState(null);
  const [selectedPkgId, setSelectedPkgId] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [showAddWizard, setShowAddWizard] = useState(false);
  const [editingInstaller, setEditingInstaller] = useState(null);
  const [deployingInstaller, setDeployingInstaller] = useState(null);
  const [showUploadAgentPackage, setShowUploadAgentPackage] = useState(false);
  const detailRef = useRef(null);

  useEffect(() => {
    installers.ensureLoaded();
    deployments.ensureLoaded();
    groups.ensureLoaded();
    agents.ensureLoaded();
    agentPackages.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const all = installers.state.data;
  const agentList = agents.state.data ?? [];
  const packages = agentPackages.state.data;
  const latestPkg = packages[0] ?? null;

  const deploymentById = useMemo(() => {
    const m = new Map();
    for (const d of deployments.state.data ?? []) m.set(d.installer_id, d);
    return m;
  }, [deployments.state.data]);

  const counts = useMemo(() => {
    const c = { msi: 0, powershell: 0, other: 0 };
    all.forEach((i) => {
      c[sourceTypeFromFileName(i.original_filename)]++;
    });
    return c;
  }, [all]);
  const totalBytes = all.reduce((n, i) => n + (Number(i.size_bytes) || 0), 0);
  const deployedCount = all.filter((i) => deployCounts(deploymentById.get(i.id)).total > 0).length;
  const upToDate = latestPkg ? agentList.filter((a) => a.agent_version === latestPkg.version).length : 0;

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return all
      .filter((i) => {
        if (typeFilter !== "all" && sourceTypeFromFileName(i.original_filename) !== typeFilter) return false;
        if (!q) return true;
        return [i.name, i.version, i.original_filename, i.install_command].filter(Boolean).join(" ").toLowerCase().includes(q);
      })
      .sort((a, b) => new Date(b.uploaded_at) - new Date(a.uploaded_at));
  }, [all, query, typeFilter]);

  const selected = filtered.find((i) => i.id === selectedId) ?? filtered[0] ?? null;
  const selectedPkg = packages.find((p) => p.id === selectedPkgId) ?? latestPkg;

  function select(setter, id) {
    setter(id);
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  async function runDelete(call, onDone) {
    setActionError(null);
    try {
      const payload = await call();
      if (isErrorPayload(payload)) setActionError(payload.message);
      else onDone();
    } catch (err) {
      setActionError(err.message);
    }
  }
  const handleDelete = (installerId) =>
    runDelete(
      () => api.vanitas.deleteInstaller(installerId),
      () => {
        if (editingInstaller?.id === installerId) setEditingInstaller(null);
        installers.refresh();
      }
    );
  const handleDeleteAgentPackage = (packageId) => runDelete(() => api.vanitas.deleteAgentPackage(packageId), () => agentPackages.refresh());

  const loading = installers.state.status === "loading";

  return (
    <div className="vanitas-hud vin">
      {installers.state.error && <p className="vanitas-hud-error">{installers.state.error}</p>}
      {actionError && <p className="vanitas-hud-error">{actionError}</p>}

      <section className="vin-card vin-sum" aria-label={tr("vin.sumAria")}>
        <div className="vin-col">
          <span className="vin-lbl">{tr("vin.installers")}</span>
          <span className="vin-val accent">{all.length}</span>
          <span className="vin-sub vin-small">{tr("vin.totalSize", { size: fmtBytes(totalBytes) })}</span>
        </div>
        <div className="vin-sum-state">
          <span className="vin-lbl">{tr("vin.byFormat")}</span>
          <span className="vin-bar" role="img" aria-label={TYPE_ORDER.map((k) => `${counts[k]} ${TYPE_META[k].label}`).join(", ")}>
            {TYPE_ORDER.map((k) => (counts[k] ? <i key={k} style={{ flex: counts[k], background: TYPE_META[k].color }} /> : null))}
          </span>
          <div className="vin-legend">
            {TYPE_ORDER.map((k) => (
              <button
                key={k}
                type="button"
                className="vin-leg"
                onClick={() => {
                  setMode("installers");
                  setTypeFilter(k);
                }}
              >
                <i style={{ background: TYPE_META[k].color }} />
                <b>{counts[k]}</b> {tr(`vin.typeLong.${k}`)}
              </button>
            ))}
          </div>
        </div>
        <div className="vin-col vin-sum-third">
          <span className="vin-lbl">{tr("vin.deployedLbl")}</span>
          <span className="vin-val">
            {deployedCount} <small>/ {all.length}</small>
          </span>
          <span className="vin-sub vin-small">{tr("vin.deployedSub")}</span>
        </div>
        <div className="vin-col vin-sum-fourth">
          <span className="vin-lbl">{tr("vin.agentLbl")}</span>
          {latestPkg ? (
            <>
              <button type="button" className="vin-agent-btn" onClick={() => setMode("agent")}>
                v{latestPkg.version}
              </button>
              <span className="vin-sub vin-small">{tr("vin.upToDate", { count: upToDate, total: agentList.length })}</span>
            </>
          ) : (
            <span className="vin-sub">—</span>
          )}
        </div>
      </section>

      <div className="vin-split">
        <section className="vin-card vin-list" aria-label={tr("vin.listAria")}>
          <div className="vin-list-head">
            <span className="vin-seg" role="tablist" aria-label={tr("vin.listAria")}>
              <button type="button" role="tab" aria-selected={mode === "installers"} className={mode === "installers" ? "on" : ""} onClick={() => setMode("installers")}>
                {tr("vin.mode.installers")}
              </button>
              <button type="button" role="tab" aria-selected={mode === "agent"} className={mode === "agent" ? "on" : ""} onClick={() => setMode("agent")}>
                {tr("vin.mode.agent")}
              </button>
            </span>
            {mode === "installers" ? (
              <button type="button" className="vanitas-wiz-primary-btn" onClick={() => setShowAddWizard(true)}>
                {tr("vin.addInstaller")}
              </button>
            ) : (
              <button type="button" className="vanitas-wiz-primary-btn" onClick={() => setShowUploadAgentPackage(true)}>
                {tr("vin.uploadVersion")}
              </button>
            )}
          </div>

          {mode === "installers" ? (
            <>
              <label className="vin-search-wrap">
                <span className="vin-sr">{tr("vin.searchPlaceholder")}</span>
                <input type="search" className="vin-input" placeholder={tr("vin.searchPlaceholder")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
              </label>
              <span className="vin-chips" role="group" aria-label={tr("vin.formatAria")}>
                {["all", ...TYPE_ORDER].map((k) => (
                  <button key={k} type="button" className={`vin-chip${typeFilter === k ? " on" : ""}`} aria-pressed={typeFilter === k} onClick={() => setTypeFilter(k)}>
                    <i className="dot" style={{ background: k === "all" ? "var(--vin-muted)" : TYPE_META[k].color }} />
                    {k === "all" ? tr("vin.all") : k === "powershell" ? "PowerShell" : TYPE_META[k].label} <b>{k === "all" ? all.length : counts[k]}</b>
                  </button>
                ))}
              </span>
              {loading ? (
                <p className="vin-empty">{tr("v.loading")}</p>
              ) : all.length === 0 ? (
                <p className="vin-empty">{tr("vin.empty")}</p>
              ) : filtered.length === 0 ? (
                <p className="vin-empty">{tr("vin.noResult")}</p>
              ) : (
                <div className="vin-rows">
                  {filtered.map((i) => {
                    const meta = TYPE_META[sourceTypeFromFileName(i.original_filename)];
                    const isSel = selected?.id === i.id;
                    return (
                      <button
                        key={i.id}
                        type="button"
                        className={`vin-it${isSel ? " sel" : ""}`}
                        style={{ "--type-c": meta.color, "--type-dim": meta.dim }}
                        aria-pressed={isSel}
                        onClick={() => select(setSelectedId, i.id)}
                      >
                        <span className="vin-ico" aria-hidden="true">
                          <meta.Icon />
                        </span>
                        <span className="vin-name">
                          {i.name} {i.version && <span className="vin-ver">v{i.version}</span>}
                        </span>
                        <DeployBadge counts={deployCounts(deploymentById.get(i.id))} />
                        <span className="vin-meta">
                          <span className="vin-mono vin-ellipsis">{i.original_filename}</span>
                          <span>·</span>
                          <span>{fmtBytes(i.size_bytes)}</span>
                          <span>·</span>
                          <span>{tr("vin.addedRel", { when: fmtRelative(i.uploaded_at) })}</span>
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </>
          ) : (
            <>
              <span className="vin-sub">{tr("vin.agentIntro")}</span>
              {agentPackages.state.status === "loading" ? (
                <p className="vin-empty">{tr("v.loading")}</p>
              ) : packages.length === 0 ? (
                <p className="vin-empty">{trRich("vin.noPackage", { path: <code>Installer/Installer.wixproj</code> })}</p>
              ) : (
                <div className="vin-rows">
                  {packages.map((p, idx) => {
                    const isSel = selectedPkg?.id === p.id;
                    const on = agentList.filter((a) => a.agent_version === p.version).length;
                    return (
                      <button
                        key={p.id}
                        type="button"
                        className={`vin-it${isSel ? " sel" : ""}`}
                        style={{ "--type-c": "var(--hud-accent)", "--type-dim": "var(--hud-accent-dim)" }}
                        aria-pressed={isSel}
                        onClick={() => select(setSelectedPkgId, p.id)}
                      >
                        <span className="vin-ico" aria-hidden="true">
                          <IconRefresh />
                        </span>
                        <span className="vin-name">
                          Endpoint Agent <span className="vin-ver">v{p.version}</span>
                        </span>
                        <span className="vin-pill" style={{ "--c": idx === 0 ? "var(--hud-good)" : "var(--vin-muted)" }}>
                          {tr(idx === 0 ? "vin.pkgLatest" : "vin.pkgOld")}
                        </span>
                        <span className="vin-meta">
                          <span>{tr("vin.onThis", { count: on })}</span>
                          <span>·</span>
                          <span>{fmtBytes(p.size_bytes)}</span>
                          <span>·</span>
                          <span>{tr("vin.publishedRel", { when: fmtRelative(p.uploaded_at) })}</span>
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </section>

        <div ref={detailRef} className="vin-detail-slot">
          {mode === "installers" ? (
            selected ? (
              <InstallerPanel
                key={selected.id}
                installer={selected}
                deployment={deploymentById.get(selected.id)}
                onDeploy={setDeployingInstaller}
                onEdit={setEditingInstaller}
                onDelete={handleDelete}
                onNavigateVanitas={onNavigateVanitas}
              />
            ) : (
              <div className="vin-card vin-empty-panel">
                <p className="vin-sub">{tr("vin.pick")}</p>
              </div>
            )
          ) : selectedPkg ? (
            <AgentPackagePanel key={selectedPkg.id} pkg={selectedPkg} isLatest={selectedPkg.id === latestPkg?.id} agents={agentList} onDelete={handleDeleteAgentPackage} />
          ) : (
            <div className="vin-card vin-empty-panel">
              <p className="vin-sub">{tr("vin.pickPkg")}</p>
            </div>
          )}
        </div>
      </div>

      {showAddWizard && <AddInstallerWizard onClose={() => setShowAddWizard(false)} onAdded={() => installers.refresh()} />}
      {editingInstaller && (
        <EditInstallerModal
          key={editingInstaller.id}
          installer={editingInstaller}
          onClose={() => setEditingInstaller(null)}
          onSaved={() => {
            setEditingInstaller(null);
            installers.refresh();
          }}
        />
      )}
      {deployingInstaller && (
        <DeployInstallerModal
          key={deployingInstaller.id}
          installer={deployingInstaller}
          groups={groups.state.data}
          agents={agents.state.data}
          onClose={() => setDeployingInstaller(null)}
          onDeployed={() => deployments.refresh()}
          onNavigateVanitas={onNavigateVanitas}
        />
      )}
      {showUploadAgentPackage && (
        <UploadAgentPackageModal
          onClose={() => setShowUploadAgentPackage(false)}
          onUploaded={() => {
            setShowUploadAgentPackage(false);
            invalidateCache("vanitasAgentPackages");
            agentPackages.refresh();
          }}
        />
      )}
    </div>
  );
}
