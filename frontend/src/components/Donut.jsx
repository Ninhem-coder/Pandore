import { useState } from "react";
import { buildDonutEntries } from "../selectors.js";
import DonutSvg from "./DonutSvg.jsx";
import DonutLegend from "./DonutLegend.jsx";

/**
 * Carte camembert complète (titre badge + donut + légende) — assemble DonutSvg et
 * DonutLegend dans le même habillage `.card`/`.card-head` que le reste du dashboard.
 * Utilisé pour les répartitions "libres" (onboarding, OS) ; la conformité Intune (deux
 * colonnes état + échecs par politique) est assemblée séparément par
 * ComplianceOverview.jsx, comme côté skill (build_compliance_overview_html).
 *
 * `compact` (Vue d'ensemble v2, 2026-08-10) : réutilise le donut "sm" déjà prévu par
 * DonutSvg/DonutLegend (voir leur doc) et empile donut + légende verticalement au lieu de
 * côte à côte — pensé pour tenir à 4 par ligne à côté d'autres cartes compactes.
 *
 * `headerExtra` (2026-08-27, "Vue d'ensemble (test)" — OverviewTestTab.jsx) : contenu
 * optionnel ajouté à la fin de `.card-head` (poignée de glisser-déposer/boutons de
 * redimensionnement de la tuile bento) — `null` par défaut, tous les appelants existants
 * gardent un rendu strictement identique.
 *
 * `cardRef`/`onDragOver`/`onDragEnter`/`onDrop` (2026-08-27, correctif "Vue d'ensemble" —
 * bordure double sur Onboarding/OS) : posés directement sur le `.card` racine, PAS ajoutés en
 * enveloppant Donut dans un `.card` supplémentaire côté appelant. `OverviewTab.jsx` faisait
 * exactement ça (un `<div className="card">` autour de `<Donut/>`, pour porter la ref FLIP et
 * les handlers de glisser-déposer) — deux `.card` imbriqués, donc deux bordures/deux paddings
 * empilés visuellement ("un bloc dans un bloc", retour de Nicolas). Tous optionnels, `null`
 * par défaut : aucun appelant existant n'est affecté.
 *
 * Survol/clic croisés graph ↔ légende (2026-08-27, demande de Nicolas sur les tuiles
 * Onboarding/OS : "si je vais dans une zone du graph ça me montre quel OS ça référence [...]
 * si je clique sur l'os dans le détail en bas du graph ça me met la zone du graph") —
 * `hoveredKey` (survol, transitoire, déclenché depuis LE GRAPH ou LA LÉGENDE) et
 * `selectedKey` (clic sur une ligne de légende, PERSISTANT jusqu'au clic suivant — voir
 * `handleLegendClick`, qui bascule : recliquer la même ligne désélectionne). `activeKey`
 * (survol prioritaire sur la sélection persistante) est la clé unique passée aux deux
 * enfants, qui appliquent chacun leur propre highlight. Toujours actif (pas de prop pour
 * désactiver) — s'applique donc À TOUS les usages de `Donut` (Vue d'ensemble ET
 * DefenderTab.jsx, qui l'utilise aussi pour ses propres camemberts Onboarding/OS), cohérent
 * avec le fait que c'est le même composant partagé plutôt qu'une variante spéciale. */
export default function Donut({
  title,
  note,
  data,
  colors,
  labels,
  defaultColor = "#6B6E76",
  compact = false,
  headerExtra = null,
  cardRef = null,
  onDragOver = null,
  onDragEnter = null,
  onDrop = null,
}) {
  const { entries, total } = buildDonutEntries(data, { colors, labels, defaultColor });
  const size = compact ? "sm" : "default";

  const [hoveredKey, setHoveredKey] = useState(null);
  const [selectedKey, setSelectedKey] = useState(null);
  const activeKey = hoveredKey ?? selectedKey;

  function handleLegendClick(key) {
    setSelectedKey((prev) => (prev === key ? null : key));
  }

  return (
    <div
      className={`card${compact ? " donut-card-compact" : ""}`}
      ref={cardRef}
      onDragOver={onDragOver}
      onDragEnter={onDragEnter}
      onDrop={onDrop}
    >
      <div className="card-head">
        <h2>{title}</h2>
        {note && <span className="card-note">{note}</span>}
        {headerExtra}
      </div>
      {entries.length === 0 ? (
        <p className="empty">Aucune donnée</p>
      ) : (
        <div className={compact ? "donut-card" : "compliance-layout"}>
          <DonutSvg
            entries={entries}
            centerText={total}
            ariaLabel={title}
            size={size}
            activeKey={activeKey}
            onSegmentEnter={setHoveredKey}
            onSegmentLeave={() => setHoveredKey(null)}
          />
          <DonutLegend
            entries={entries}
            size={size}
            activeKey={activeKey}
            onItemEnter={setHoveredKey}
            onItemLeave={() => setHoveredKey(null)}
            onItemClick={handleLegendClick}
          />
        </div>
      )}
    </div>
  );
}
