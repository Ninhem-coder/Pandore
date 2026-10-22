import { useRef, useState } from "react";
import { api } from "../api.js";
import DeployAppWizard from "../components/DeployAppWizard.jsx";
import { IconPicker } from "../components/IconPicker.jsx";
import { IconUpload } from "../components/icons.jsx";
import { tr } from "../i18n/core.js";

/**
 * Onglet "Application" > Administration > "Ajouter une application" (2026-08-26, demande de
 * Nicolas — "deux onglets différents pour l'ajout d'application et le catalogue des
 * applications... dans un sous-onglet Administration en dessous d'Inventaire").
 *
 * Scission de l'ancien `AppCatalogTab.jsx` (qui combinait dépôt + liste depuis la demande
 * précédente du même jour, "bibliothèque d'app que je peux rajouter") : CE fichier ne garde
 * QUE le dépôt (assistant de packaging + ajout manuel libre) — la liste/bibliothèque elle-même
 * vit maintenant dans `AppCatalogTab.jsx` uniquement. Backend inchangé
 * (`intune/app_library.py`) : la scission est purement une réorganisation de navigation, pas
 * un changement de modèle de données.
 *
 * "Empaqueter un installeur" (2026-08-26, même jour, demande de Nicolas : "pour l'ajout
 * manuel on peut permettre de faire un upload... pour le faire package et le rajouter dans le
 * catalogue") — scopé MSI uniquement (V1 du packaging reste MSI-only, décision explicite non
 * remise en cause ici) ET routé via le wizard complet plutôt qu'un packaging à réglages par
 * défaut (choix confirmé par Nicolas) : le fichier déposé ici pré-remplit l'étape "Source" de
 * `DeployAppWizard` (prop `initialFile`, voir ce fichier) et saute directement à "Mode
 * d'installation" — pas de nouveau chemin de packaging, juste un raccourci d'entrée vers le
 * wizard existant depuis la carte "Ajout manuel".
 */

/** Formulaire d'ajout manuel — même esprit que le formulaire "Ajouter une CVE à suivre" de
 * CveWatchTab.jsx. Contrairement à la version précédente (dans l'ex-AppCatalogTab.jsx unique),
 * il n'y a plus de liste locale à rafraîchir après un ajout : la confirmation reste sur place
 * (pas de redirection automatique) et propose un lien vers le catalogue via `onNavigate`. */
function ManualAddForm({ onNavigate }) {
  const [displayName, setDisplayName] = useState("");
  const [publisher, setPublisher] = useState("");
  const [version, setVersion] = useState("");
  const [note, setNote] = useState("");
  const [icon, setIcon] = useState(null);
  const [iconContentType, setIconContentType] = useState(null);
  const [iconError, setIconError] = useState(null);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState(null);
  const [justAdded, setJustAdded] = useState(false);

  function handleIconPick(nextIcon, nextContentType, nextError) {
    setIcon(nextIcon);
    setIconContentType(nextContentType);
    setIconError(nextError);
  }

  async function handleSubmit(e) {
    e.preventDefault();
    if (!displayName.trim()) return;
    setAdding(true);
    setError(null);
    setJustAdded(false);
    try {
      const result = await api.appLibrary.addManual({
        displayName: displayName.trim(),
        publisher: publisher.trim(),
        version: version.trim(),
        note: note.trim(),
        icon,
        iconContentType,
      });
      if (result?.error) {
        setError(result.message);
      } else {
        setDisplayName("");
        setPublisher("");
        setVersion("");
        setNote("");
        setIcon(null);
        setIconContentType(null);
        setJustAdded(true);
      }
    } catch (err) {
      setError(err.message || tr("apps.addFailed"));
    } finally {
      setAdding(false);
    }
  }

  return (
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
        icon={icon}
        iconContentType={iconContentType}
        onPick={handleIconPick}
        onClear={() => handleIconPick(null, null, null)}
        error={iconError}
      />
      <div className="wizard-actions library-manual-actions">
        <button type="submit" className="wizard-secondary-btn" disabled={adding || !displayName.trim()}>
          {adding ? tr("apps.adding") : tr("apps.addToLibrary")}
        </button>
        {justAdded && (
          <button type="button" className="wizard-secondary-btn" onClick={() => onNavigate?.("app-catalog")}>
            {tr("apps.seeCatalog")}
          </button>
        )}
      </div>
      {justAdded && <p className="card-note">{tr("apps.added")}</p>}
      {error && <p className="error-note">{error}</p>}
    </form>
  );
}

export default function AddAppTab({ onNavigate }) {
  const [wizardOpen, setWizardOpen] = useState(false);
  // Fichier déposé depuis le drop-zone de la carte "Ajout manuel" (voir plus bas) — passé au
  // wizard comme `initialFile`, qui le dépose automatiquement à son montage (SourceStep) et
  // saute directement à "Mode d'installation" (2026-08-26, demande de Nicolas : "pour l'ajout
  // manuel on peut permettre de faire un upload... pour le faire package et le rajouter dans
  // le catalogue"). `null` quand le wizard est ouvert via "Déployer une application"
  // (comportement normal, choix de la source dans le wizard).
  const [pendingFile, setPendingFile] = useState(null);
  const manualFileInputRef = useRef(null);

  function handleManualFileChange(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setPendingFile(file);
    setWizardOpen(true);
  }

  function handleWizardClose() {
    setWizardOpen(false);
    setPendingFile(null);
    // Sans ce reset, choisir DEUX FOIS DE SUITE le même fichier (même nom, même chemin) ne
    // redéclenche pas `onChange` — le navigateur considère que la valeur du champ n'a pas
    // changé.
    if (manualFileInputRef.current) manualFileInputRef.current.value = "";
  }

  return (
    <>
      <div className="card">
        <div className="card-head">
          <h2>{tr("apps.deploy")}</h2>
          <button type="button" className="app-catalog-deploy-btn" onClick={() => setWizardOpen(true)}>
            <IconUpload />
            {tr("apps.deploy")}
          </button>
        </div>
        <p className="card-note">
          {tr("apps.deployNote")}
        </p>
      </div>

      <div className="card">
        <div className="card-head">
          <h2>{tr("apps.manualAdd")}</h2>
        </div>

        <p className="filter-chip-group-label">{tr("apps.packageInstaller")}</p>
        <p className="card-note">
          {tr("apps.packageInstallerNote")}
        </p>
        <button type="button" className="add-app-upload-drop" onClick={() => manualFileInputRef.current?.click()}>
          <IconUpload />
          <span>{tr("apps.chooseFile")}</span>
        </button>
        <input ref={manualFileInputRef} type="file" accept=".msi,.ps1" hidden onChange={handleManualFileChange} />

        <div className="add-app-manual-divider">
          <span>{tr("apps.or")}</span>
        </div>

        <p className="filter-chip-group-label">{tr("apps.referenceOnly")}</p>
        <p className="card-note">
          {tr("apps.referenceOnlyNote")}
        </p>
        <ManualAddForm onNavigate={onNavigate} />
      </div>

      {wizardOpen && <DeployAppWizard onClose={handleWizardClose} initialFile={pendingFile} />}
    </>
  );
}
