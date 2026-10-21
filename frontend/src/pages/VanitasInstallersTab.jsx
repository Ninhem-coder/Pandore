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
  useVanitasInstallers,
} from "../hooks/useDashboardData.js";
import { ConfirmButton, VanitasWizardShell, fmtBytes, fmtDateTime } from "./vanitasShared.jsx";

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
    return new Date(iso).toLocaleDateString("fr-FR");
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
  other: { label: "Autre", color: "var(--hud-warn)", dim: "var(--hud-warn-soft)", Icon: IconWrench },
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
        <span>ajouté le {fmtDateTime(installer.uploaded_at)}</span>
      </div>
      {!readOnly && (
        <div className="installer-card-actions">
          <button type="button" className="vanitas-ghost-btn" onClick={() => onEdit(installer)}>
            Modifier
          </button>
          <ConfirmButton
            label="Supprimer"
            confirmLabel="Confirmer ?"
            className="vanitas-danger-btn"
            onConfirm={() => onDelete(installer.id)}
          />
          <button type="button" className="vanitas-deploy-btn" onClick={() => onDeploy(installer)}>
            ↑ Déployer
          </button>
        </div>
      )}
    </div>
  );
}

const ADD_STEP_LABELS = { 1: "Source", 2: "Mode", 3: "Redémarrage", 4: "Informations", 5: "Résultat" };

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
      setError("Entrée invalide — attendu un lien GitHub (https://github.com/organisation/depot) ou « organisation/depot ».");
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
      setError(err.message || "Échec de la recherche GitHub.");
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
      setError(err.message || "Échec de la récupération de cette release.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="installer-source-toggle" role="group" aria-label="Origine de la source">
        <button type="button" className={`vanitas-hud-chip${mode === "upload" ? " active" : ""}`} onClick={() => setMode("upload")}>
          Déposer un fichier
        </button>
        <button type="button" className={`vanitas-hud-chip${mode === "github" ? " active" : ""}`} onClick={() => setMode("github")}>
          Depuis GitHub Releases
        </button>
      </div>

      {mode === "upload" && (
        <label className={`installer-dropzone${file ? " filled" : ""}`}>
          <div className="installer-dropzone-icon">
            <DropIcon />
          </div>
          <div className="installer-dropzone-text">
            <b>{file ? file.name : "Glisser un fichier ici ou cliquer pour parcourir"}</b>
            <span>{file ? fmtBytes(file.size) : "MSI, PS1 ou EXE — 1 Go max"}</span>
          </div>
          <input ref={fileInputRef} type="file" onChange={onFileChange} hidden />
        </label>
      )}

      {mode === "github" && (
        <div className="installer-github-panel">
          <p className="vanitas-hud-empty-note" style={{ margin: "0 0 10px" }}>
            Lien du dépôt (ex. https://github.com/ip7z/7zip) ou raccourci « organisation/dépôt » — liste toutes les
            releases publiées.
          </p>
          <form className="installer-github-form" onSubmit={handleGithubSearch}>
            <input
              type="text"
              className="filter-input"
              style={{ flex: "1 1 auto" }}
              placeholder="https://github.com/organisation/depot ou organisation/depot"
              value={repoInput}
              onChange={(e) => setRepoInput(e.target.value)}
            />
            <button type="submit" className="vanitas-ghost-btn" disabled={busy || !repoInput.trim()}>
              Rechercher
            </button>
          </form>

          {releases && !selectedRelease && (
            <div className="installer-github-list">
              <p className="filter-chip-group-label">{releases.length} release{releases.length > 1 ? "s" : ""} — choisis une version</p>
              {releases.length === 0 && <p className="vanitas-hud-empty-note">Aucune release publiée sur ce dépôt.</p>}
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
                <p className="filter-chip-group-label">{selectedRelease.tagName || "release"} — choisis l'asset à ajouter</p>
                <button type="button" className="vanitas-ghost-btn" onClick={() => setSelectedRelease(null)}>
                  ‹ Toutes les versions
                </button>
              </div>
              {selectedRelease.assets.length === 0 && <p className="vanitas-hud-empty-note">Aucun asset publié sur cette release.</p>}
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
              Asset choisi · <b>{githubAsset.assetName}</b> ({fmtBytes(githubAsset.sizeBytes)}) — téléchargé au moment de
              l'ajout au catalogue.
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
          <h2>Ajouter un installeur</h2>
          <p>Catalogue Vanitas · Applications</p>
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
                Suivant
              </button>
            </div>
          </>
        )}

        {activeStep === 2 && (
          <>
            <div className="wizard-field-group">
              <p className="filter-chip-group-label">Mode d'installation</p>
              <div className="installer-mode-grid g3" role="radiogroup" aria-label="Mode d'installation">
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
                Retour
              </button>
              <button type="button" className="vanitas-wiz-primary-btn" onClick={goNext}>
                Suivant
              </button>
            </div>
          </>
        )}

        {activeStep === 3 && (
          <>
            <div className="wizard-field-group">
              <p className="filter-chip-group-label">Comportement de redémarrage</p>
              <div className="installer-mode-grid g4" role="radiogroup" aria-label="Comportement de redémarrage">
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
                Retour
              </button>
              <button type="button" className="vanitas-wiz-primary-btn" onClick={goNext}>
                Suivant
              </button>
            </div>
          </>
        )}

        {activeStep === 4 && (
          <>
            <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
              <div style={{ flex: "1 1 220px" }}>
                <p className="filter-chip-group-label">Nom</p>
                <input className="filter-input" style={{ flex: "none", width: "100%" }} type="text" placeholder="Nom (ex. 7-Zip)" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
              </div>
              <div style={{ flex: "0 0 140px" }}>
                <p className="filter-chip-group-label">Version</p>
                <input className="filter-input" style={{ flex: "none", width: "100%" }} type="text" placeholder="optionnel" value={version} onChange={(e) => setVersion(e.target.value)} disabled={busy} />
              </div>
            </div>

            {sourceType === "msi" ? (
              <div className="wizard-field-group">
                <p className="filter-chip-group-label">Commande finale (calculée)</p>
                <div className="installer-cmd-final">{installCommand || "—"}</div>
              </div>
            ) : (
              <div className="wizard-field-group">
                <p className="filter-chip-group-label">Commande d'installation</p>
                <input
                  className="filter-input"
                  style={{ flex: "none", width: "100%" }}
                  type="text"
                  value={manualCommand}
                  onChange={(e) => setManualCommand(e.target.value)}
                  placeholder={sourceType === "powershell" ? 'powershell -executionpolicy bypass -file ".\\installeur.ps1"' : 'ex. "installeur.exe" /S'}
                  disabled={busy}
                />
                {sourceType === "other" && (
                  <p className="vanitas-hud-empty-note" style={{ margin: "6px 0 0" }}>
                    Aucun flag silencieux générique fiable entre éditeurs pour ce format — à taper soi-même (ex. <code>/S</code>, <code>/quiet</code>, selon l'installeur).
                  </p>
                )}
              </div>
            )}

            {error && <p className="error-note">{error}</p>}

            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={goBack} disabled={busy}>
                Retour
              </button>
              <button type="button" className="vanitas-wiz-primary-btn" disabled={!name.trim() || !installCommand.trim() || busy} onClick={handleAdd}>
                {busy ? "Envoi…" : "Ajouter au catalogue"}
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
              <div className="vanitas-wiz-result-title">Installeur ajouté au catalogue.</div>
              <div className="vanitas-wiz-result-sub">visible immédiatement, prêt à être poussé depuis « Groupes »</div>
              <InstallerCard installer={created} readOnly />
            </div>
            <div className="wizard-actions">
              <button type="button" className="vanitas-wiz-primary-btn" onClick={onClose}>
                Fermer
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
          <h2>Modifier « {installer.name} »</h2>
          <p>Fichier d'origine · {installer.original_filename}</p>
        </div>
      </div>
      <form onSubmit={handleSubmit} className="vanitas-wiz-body">
        <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 100%" }}>
            <p className="filter-chip-group-label">Nom</p>
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
          <p className="filter-chip-group-label">Commande d'installation</p>
          <input className="filter-input" style={{ flex: "none", width: "100%" }} type="text" value={installCommand} onChange={(e) => setInstallCommand(e.target.value)} disabled={busy} />
        </div>
        <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
          Fichier d'origine « {installer.original_filename} » inchangé — cette fiche ne modifie que le nom/la version/la commande, jamais le binaire déjà en catalogue.
        </p>
        {error && <p className="error-note">{error}</p>}
        <div className="wizard-actions">
          <button type="button" className="vanitas-ghost-btn" onClick={onClose} disabled={busy}>
            Annuler
          </button>
          <button type="submit" className="vanitas-wiz-primary-btn" disabled={!canSubmit}>
            {busy ? "Enregistrement…" : "Enregistrer les modifications"}
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
          <h2>Déployer « {installer.name} »</h2>
          <p>Catalogue Vanitas · Applications</p>
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
                {result.count} commande{result.count > 1 ? "s" : ""} mise{result.count > 1 ? "s" : ""} en file.
              </div>
              <div className="vanitas-wiz-result-sub">
                « {installer.name} » → {result.label}
              </div>
            </div>
            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={onClose}>
                Fermer
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
                  Voir dans « Applications déployées »
                </button>
              )}
            </div>
          </>
        ) : (
          <>
            <div className="wizard-field-group">
              <p className="filter-chip-group-label">Cible</p>
              <div className="deploy-target-toggle" role="radiogroup" aria-label="Cible du déploiement">
                <label className={`deploy-target-card${targetType === "group" ? " active" : ""}`}>
                  <input type="radio" name="deployTargetType" checked={targetType === "group"} onChange={() => setTargetType("group")} />
                  Un groupe
                </label>
                <label className={`deploy-target-card${targetType === "device" ? " active" : ""}`}>
                  <input type="radio" name="deployTargetType" checked={targetType === "device"} onChange={() => setTargetType("device")} />
                  Un poste
                </label>
              </div>
            </div>

            {targetType === "group" ? (
              <div className="wizard-field-group">
                <p className="filter-chip-group-label">Groupe</p>
                {groups.length === 0 ? (
                  <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
                    Aucun groupe créé pour l'instant — crée-en un depuis « Groupes », ou choisis "Un poste" ci-dessus.
                  </p>
                ) : (
                  <div className="deploy-picker-list">
                    {groups.map((g) => (
                      <label key={g.id} className={`deploy-picker-row${groupId === g.id ? " checked" : ""}`}>
                        <span>
                          <input type="radio" name="deployGroup" checked={groupId === g.id} onChange={() => setGroupId(g.id)} />
                          {g.name}
                          {g.rules && <span className="deploy-picker-dynamic"> (dynamique)</span>}
                        </span>
                        <span className="deploy-picker-badge">
                          {g.device_count} poste{g.device_count > 1 ? "s" : ""}
                        </span>
                      </label>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="wizard-field-group">
                <p className="filter-chip-group-label">Poste</p>
                <input
                  className="filter-input"
                  style={{ flex: "none", width: "100%", marginBottom: "8px" }}
                  type="text"
                  placeholder="Rechercher un poste..."
                  value={agentQuery}
                  onChange={(e) => setAgentQuery(e.target.value)}
                  autoComplete="off"
                />
                {agents.length === 0 ? (
                  <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
                    Aucun poste enrôlé pour l'instant.
                  </p>
                ) : filteredAgents.length === 0 ? (
                  <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
                    0 résultat pour cette recherche.
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
              → sera poussé vers <b>{targetCount} poste{targetCount > 1 ? "s" : ""}</b>
            </p>

            {error && <p className="error-note">{error}</p>}

            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={onClose} disabled={busy}>
                Annuler
              </button>
              <button
                type="button"
                className="vanitas-wiz-primary-btn"
                disabled={busy || targetCount === 0}
                onClick={handleDeploy}
              >
                {busy ? "Déploiement…" : `Déployer vers ${targetCount} poste${targetCount > 1 ? "s" : ""}`}
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
          <h2>Uploader une nouvelle version de l'agent</h2>
          <p>Catalogue Vanitas · Agent · MSI uniquement</p>
        </div>
      </div>
      <form onSubmit={handleSubmit} className="vanitas-wiz-body">
        <div className="wizard-field-group">
          <p className="filter-chip-group-label">Version</p>
          <input
            className="filter-input"
            style={{ flex: "none", width: "100%" }}
            type="text"
            placeholder="ex. 1.2.0 — doit correspondre au <Package Version> de Product.wxs"
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            disabled={busy}
            autoComplete="off"
          />
        </div>
        <div className="wizard-field-group">
          <p className="filter-chip-group-label">Fichier .msi</p>
          <label className={`installer-dropzone${file ? " filled" : ""}`}>
            <div className="installer-dropzone-text">
              <b>{file ? file.name : "Glisser le .msi ici ou cliquer pour parcourir"}</b>
              <span>{file ? fmtBytes(file.size) : "EndpointAgent.msi — 200 Mo max"}</span>
            </div>
            <input type="file" accept=".msi" hidden onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          </label>
        </div>
        <p className="vanitas-hud-empty-note" style={{ margin: 0 }}>
          Une fois uploadé, tout poste en retard reçoit la mise à jour automatiquement au
          prochain cycle (~1h) — ou immédiatement en forçant depuis sa propre fiche.
        </p>
        {error && <p className="error-note">{error}</p>}
        <div className="wizard-actions">
          <button type="button" className="vanitas-ghost-btn" onClick={onClose} disabled={busy}>
            Annuler
          </button>
          <button type="submit" className="vanitas-wiz-primary-btn" disabled={!canSubmit}>
            {busy ? "Envoi…" : "Ajouter au catalogue"}
          </button>
        </div>
      </form>
    </VanitasWizardShell>
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
 */
export default function VanitasInstallersTab({ onNavigateVanitas }) {
  const installers = useVanitasInstallers();
  const groups = useVanitasGroups();
  const agents = useVanitasAgents();
  const [deleteError, setDeleteError] = useState(null);
  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [showAddWizard, setShowAddWizard] = useState(false);
  const [editingInstaller, setEditingInstaller] = useState(null);
  const [deployingInstaller, setDeployingInstaller] = useState(null);

  // Catalogue de mise à jour de l'agent (2026-09-11, revu — remplace la page dédiée "Mise à
  // jour de l'agent", qui ne faisait plus que ça).
  const agentPackages = useVanitasAgentPackages();
  const [showUploadAgentPackage, setShowUploadAgentPackage] = useState(false);
  const [agentPackageError, setAgentPackageError] = useState(null);

  useEffect(() => {
    installers.ensureLoaded();
    groups.ensureLoaded();
    agents.ensureLoaded();
    agentPackages.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleDeleteAgentPackage(packageId) {
    setAgentPackageError(null);
    try {
      const payload = await api.vanitas.deleteAgentPackage(packageId);
      if (isErrorPayload(payload)) {
        setAgentPackageError(payload.message);
      } else {
        agentPackages.refresh();
      }
    } catch (err) {
      setAgentPackageError(err.message);
    }
  }

  const counts = useMemo(() => {
    const c = { msi: 0, powershell: 0, other: 0 };
    installers.state.data.forEach((i) => {
      c[sourceTypeFromFileName(i.original_filename)]++;
    });
    return c;
  }, [installers.state.data]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return installers.state.data.filter((i) => {
      if (typeFilter !== "all" && sourceTypeFromFileName(i.original_filename) !== typeFilter) return false;
      if (!q) return true;
      return [i.name, i.version, i.original_filename, i.install_command]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
  }, [installers.state.data, query, typeFilter]);

  async function handleDelete(installerId) {
    setDeleteError(null);
    try {
      const payload = await api.vanitas.deleteInstaller(installerId);
      if (isErrorPayload(payload)) {
        setDeleteError(payload.message);
      } else {
        if (editingInstaller?.id === installerId) setEditingInstaller(null);
        installers.refresh();
      }
    } catch (err) {
      setDeleteError(err.message);
    }
  }

  return (
    <div className="vanitas-hud">
      {installers.state.error && <p className="vanitas-hud-error">{installers.state.error}</p>}
      {deleteError && <p className="vanitas-hud-error">{deleteError}</p>}

      <div className="vanitas-hud-toolbar" style={{ marginBottom: "16px" }}>
        <div className="vanitas-hud-search">
          <span className="prompt">&gt;</span>
          <input
            type="text"
            placeholder="Rechercher une application (nom, fichier, commande)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
          />
        </div>
        <div className="vanitas-hud-chips">
          <button type="button" className={`vanitas-hud-chip${typeFilter === "all" ? " active" : ""}`} onClick={() => setTypeFilter("all")}>
            <span className="led" />
            Tous<span className="n">{installers.state.data.length}</span>
          </button>
          <button type="button" className={`vanitas-hud-chip${typeFilter === "msi" ? " active" : ""}`} onClick={() => setTypeFilter("msi")}>
            <span className="led" />
            MSI<span className="n">{counts.msi}</span>
          </button>
          <button
            type="button"
            className={`vanitas-hud-chip tone-accent2${typeFilter === "powershell" ? " active" : ""}`}
            onClick={() => setTypeFilter("powershell")}
          >
            <span className="led" />
            PowerShell<span className="n">{counts.powershell}</span>
          </button>
          <button type="button" className={`vanitas-hud-chip tone-warn${typeFilter === "other" ? " active" : ""}`} onClick={() => setTypeFilter("other")}>
            <span className="led" />
            Autre<span className="n">{counts.other}</span>
          </button>
        </div>
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>
            {filtered.length} / {installers.state.data.length} installeur{installers.state.data.length > 1 ? "s" : ""}
          </h2>
          <button type="button" className="vanitas-wiz-primary-btn" onClick={() => setShowAddWizard(true)}>
            + Ajouter un installeur
          </button>
        </div>
        {installers.state.status === "loading" ? (
          <p className="vanitas-hud-empty-note">CHARGEMENT…</p>
        ) : installers.state.data.length === 0 ? (
          <p className="vanitas-hud-empty-note">Aucun installeur dans le catalogue pour l'instant — ajoutes-en un ci-dessus.</p>
        ) : filtered.length === 0 ? (
          <p className="vanitas-hud-empty-note">0 résultat — aucun installeur ne correspond à ce filtre.</p>
        ) : (
          <div className="installer-grid">
            {filtered.map((i) => (
              <InstallerCard
                key={i.id}
                installer={i}
                onEdit={setEditingInstaller}
                onDelete={handleDelete}
                onDeploy={setDeployingInstaller}
              />
            ))}
          </div>
        )}
        {filtered.length > 0 && (
          <p className="vanitas-hud-card-note" style={{ display: "block", padding: "0 16px 16px" }}>
            « ↑ DÉPLOYER » CI-DESSUS, OU DEPUIS LA FICHE D'UN GROUPE
          </p>
        )}
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame" style={{ marginTop: "16px" }}>
        <div className="vanitas-hud-card-head">
          <h2>Mise à jour de l'agent — {agentPackages.state.data.length} version{agentPackages.state.data.length > 1 ? "s" : ""}</h2>
          <button type="button" className="vanitas-wiz-primary-btn" onClick={() => setShowUploadAgentPackage(true)}>
            + Uploader une nouvelle version
          </button>
        </div>
        {agentPackageError && <p className="vanitas-hud-error">{agentPackageError}</p>}
        {agentPackages.state.status === "loading" ? (
          <p className="vanitas-hud-empty-note">CHARGEMENT…</p>
        ) : agentPackages.state.data.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            Aucun paquet au catalogue — uploade le .msi régénéré depuis <code>Installer/Installer.wixproj</code> ci-dessus.
            Une fois uploadé, la propagation vers un poste en retard est automatique (ou déclenchable immédiatement
            depuis sa fiche).
          </p>
        ) : (
          <div className="installer-grid">
            {agentPackages.state.data.map((p, i) => (
              <div
                key={p.id}
                className="installer-card"
                style={{ "--type-c": i === 0 ? "var(--hud-accent)" : "var(--hud-ink-faint)", "--type-dim": i === 0 ? "var(--hud-accent-dim)" : "var(--hud-warn-soft)" }}
              >
                <div className="installer-card-top">
                  <div className="installer-card-icon">
                    <IconRefresh />
                  </div>
                  <div className="installer-card-id">
                    <div className="installer-card-name">Endpoint Agent</div>
                    <div className="installer-card-version">v{p.version}</div>
                  </div>
                  {i === 0 && <span className="installer-card-badge">DERNIÈRE</span>}
                </div>
                <div className="installer-card-file">{p.original_filename}</div>
                <div className="installer-card-cmd">SHA-256 · {p.sha256.slice(0, 16)}…</div>
                <div className="installer-card-meta">
                  <span>{fmtBytes(p.size_bytes)}</span>
                  <span>uploadé le {fmtDateTime(p.uploaded_at)}</span>
                </div>
                <div className="installer-card-actions">
                  <ConfirmButton
                    label="Supprimer"
                    confirmLabel="Confirmer ?"
                    className="vanitas-danger-btn"
                    onConfirm={() => handleDeleteAgentPackage(p.id)}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showAddWizard && (
        <AddInstallerWizard
          onClose={() => setShowAddWizard(false)}
          onAdded={() => installers.refresh()}
        />
      )}
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
          onDeployed={() => {}}
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
