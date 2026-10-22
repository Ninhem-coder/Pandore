import { useState } from "react";
import { IconSearch } from "./icons.jsx";
import { useI18n } from "../i18n/I18nContext.jsx";

/**
 * Recherche globale du masthead (2026-08-20, demande de Nicolas — point 3.5/4 du
 * compte-rendu de revue globale du 2026-08-20 : "chaque onglet a sa propre recherche
 * isolée [...] il n'y a pas de barre de recherche globale"). Visible sur TOUS les onglets
 * (montée dans Dashboard.jsx, pas dans un onglet en particulier) — un nom d'appareil ou une
 * CVE tapé ici saute directement vers la bonne page ET lance la recherche, plutôt que de
 * devoir d'abord naviguer manuellement puis retaper la même requête dans le champ de
 * l'onglet cible.
 *
 * Volontairement un simple aiguillage vers les recherches EXISTANTES (VulnerabilitiesTab,
 * DeviceOverviewTab) via la prop `initialQuery` — pas une troisième implémentation de
 * recherche. Voir Dashboard.jsx::handleGlobalSearch pour la détection CVE vs nom d'appareil
 * et le câblage vers l'onglet cible.
 */

// Un identifiant CVE a une forme fixe (CVE-AAAA-N...) — tout le reste est traité comme un
// nom d'appareil. Même regex d'intention que le hint déjà affiché sur VulnerabilitiesTab
// ("Une CVE exacte [...] filtre sur cet identifiant ; tout autre texte recherche [...]"),
// pas une nouvelle convention introduite ici.
const CVE_PATTERN = /^cve-\d{4}-\d+$/i;

export function isCveLike(value) {
  return CVE_PATTERN.test((value || "").trim());
}

export default function GlobalSearch({ onSearch }) {
  const { t } = useI18n();
  const [value, setValue] = useState("");

  function handleSubmit(event) {
    event.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) return;
    onSearch(trimmed);
    // Le champ se vide après envoi (comme un champ de recherche d'app native) — la requête
    // reste visible dans le champ de recherche PROPRE à l'onglet cible (VulnerabilitiesTab/
    // DeviceOverviewTab la reprennent via `initialQuery`), donc rien n'est perdu.
    setValue("");
  }

  return (
    <form className="global-search" onSubmit={handleSubmit} role="search">
      <span className="global-search-icon">
        <IconSearch />
      </span>
      <input
        type="text"
        className="global-search-input"
        placeholder={t("search.placeholder")}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        aria-label={t("search.aria")}
      />
    </form>
  );
}
