/**
 * Tuile KPI — bordure haute colorée, label mono majuscule, valeur mono en gros, sous-texte.
 * `tone` pilote la couleur de bordure/badge. `icon` (optionnel) affiche un badge rond
 * teinté à gauche du libellé — inspiré de la référence transmise par Nicolas (cartes KPI
 * arrondies avec icônes, passe design du 2026-08-06). Reste optionnel : les appels
 * existants sans `icon` gardent l'ancienne mise en page texte seul.
 */
export default function SummaryCard({ title, value, hint, tone = "default", icon }) {
  const toneClass = { good: "c-low", warning: "c-med", danger: "c-high" }[tone] ?? "";
  return (
    <div className={`strip-item ${toneClass}`}>
      {icon && <span className="strip-icon">{icon}</span>}
      <div className="strip-body">
        <div className="strip-label">{title}</div>
        <div className="strip-value">{value}</div>
        {hint && <div className="strip-sub">{hint}</div>}
      </div>
    </div>
  );
}
