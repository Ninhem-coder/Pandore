import { useRef } from "react";
import { IconUpload } from "./icons.jsx";
import { tr } from "../i18n/core.js";

/**
 * Sélecteur de logo d'application (2026-08-26, demande de Nicolas : "mettre un logo à
 * l'application... pour le voir dans le catalogue"). Utilisé par trois formulaires qui
 * alimentent/modifient la bibliothèque (`AddAppTab.jsx` > ajout manuel, `DeployAppWizard.jsx` >
 * "Ajouter à la bibliothèque", `EditAppTab.jsx` > modification) — factorisé ici en composant
 * partagé plutôt que dupliqué une troisième fois : contrairement aux petits utilitaires purs
 * dupliqués ailleurs dans ce projet (`hashString`...), c'est un composant avec état et logique
 * de validation, la duplication devenait un vrai risque de dérive entre 3 copies.
 *
 * Même borne que `backend/intune/app_library.py::_MAX_ICON_BYTES` — rejeter côté client avant
 * même de lire le fichier plutôt que de laisser l'admin découvrir l'erreur après soumission.
 */
export const MAX_ICON_BYTES = 750_000;

/** Lit un fichier image et renvoie son contenu en base64 PUR (sans le préfixe
 * `data:...;base64,` que `FileReader.readAsDataURL` ajoute) + son type MIME. */
export function fileToIconPayload(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result || "";
      const commaIndex = result.indexOf(",");
      resolve({
        icon: commaIndex >= 0 ? result.slice(commaIndex + 1) : result,
        iconContentType: file.type || "image/png",
      });
    };
    reader.onerror = () => reject(reader.error || new Error(tr("icon.readFailed")));
    reader.readAsDataURL(file);
  });
}

/** `onPick(icon, iconContentType, error)` — appelé aussi bien sur un choix réussi
 * (`error` = `null`) que sur un rejet (taille/lecture, `icon`/`iconContentType` = `null`), pour
 * que l'appelant n'ait qu'un seul callback à câbler. `clearLabel` personnalisable
 * ("Retirer le logo" par défaut, "Retirer le nouveau logo" dans `EditAppTab.jsx` où un logo
 * existant reste en toile de fond tant qu'aucun nouveau fichier n'est choisi). */
export function IconPicker({ icon, iconContentType, onPick, onClear, error, clearLabel = tr("icon.remove") }) {
  const inputRef = useRef(null);

  async function handleChange(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > MAX_ICON_BYTES) {
      onPick(null, null, tr("icon.tooBig", { size: Math.round(file.size / 1024) }));
      e.target.value = "";
      return;
    }
    try {
      const payload = await fileToIconPayload(file);
      onPick(payload.icon, payload.iconContentType, null);
    } catch (err) {
      onPick(null, null, err.message || tr("icon.readFailed"));
    }
    e.target.value = "";
  }

  return (
    <div className="library-icon-picker">
      {icon ? (
        <div className="library-icon-picker-preview">
          <img src={`data:${iconContentType || "image/png"};base64,${icon}`} alt="" />
          <button type="button" className="library-icon-picker-clear" onClick={onClear}>
            {clearLabel}
          </button>
        </div>
      ) : (
        <button type="button" className="library-icon-picker-drop" onClick={() => inputRef.current?.click()}>
          <IconUpload />
          <span>{tr("icon.drop")}</span>
        </button>
      )}
      <input ref={inputRef} type="file" accept="image/*" hidden onChange={handleChange} />
      {error && <p className="error-note">{error}</p>}
    </div>
  );
}
