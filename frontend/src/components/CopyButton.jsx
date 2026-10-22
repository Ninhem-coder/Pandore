import { useState } from "react";
import { tr } from "../i18n/core.js";

/** Bouton "copier dans le presse-papiers" partagé (2026-09-12 — extrait des 5 copies quasi
 * identiques qui vivaient dans DeployAppWizard/AppCatalogTab/EditAppTab/VanitasActivityLogTab/
 * VanitasEnrollTab). L'admin doit coller le texte tel quel (token, commande msiexec, script
 * Intune) : autant lui éviter une sélection manuelle sujette à erreur (espace en trop, ligne
 * tronquée). `navigator.clipboard` fonctionne sur localhost (contexte sécurisé), pas de repli
 * nécessaire pour ce dashboard local.
 *
 * `className` reste paramétrable car chaque contexte a son propre style de bouton
 * (`wizard-copy-btn`, `activity-detail-copy-btn`, `vanitas-enroll-copy-btn`) dans styles.css —
 * on factorise le comportement, pas l'habillage. */
export default function CopyButton({
  text,
  className = "wizard-copy-btn",
  label = tr("common.copy"),
  copiedLabel = tr("common.copied"),
}) {
  const [copied, setCopied] = useState(false);
  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(text || "");
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Presse-papiers indisponible (permission navigateur refusée) — pas bloquant, le texte
      // reste sélectionnable/copiable manuellement dans le bloc juste à côté.
    }
  }
  return (
    <button type="button" className={className} onClick={handleCopy}>
      {copied ? copiedLabel : label}
    </button>
  );
}
