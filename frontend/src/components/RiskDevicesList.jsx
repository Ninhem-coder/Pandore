/**
 * "Top devices à risque" (Vue d'ensemble v2, 2026-08-10) — classement construit côté
 * client par selectors.js::computeTopRiskDevices à partir de /api/defender/machines
 * (exposureLevel, riskScore) et /api/defender/alerts (alertes actives comptées par
 * machine). Même esprit que RecommendationsList.jsx (rang mono + ligne + badge) pour
 * rester cohérent visuellement.
 *
 * `onSelectDevice` (2026-08-20, demande de Nicolas : "tu peux me faire les devices
 * cliquable et qui renvoie en recherche d'appareil et me met la fiche de l'appareil ?") —
 * rend chaque ligne actionnable au clic ET au clavier (élément `<button>`, comme
 * `SignalCard`/`Disclosure` ailleurs dans l'app) plutôt qu'un `onClick` posé sur un `<div>`.
 * Optionnel : sans le prop, la ligne reste un simple `<div>` non interactif — même
 * composant utilisable en lecture seule si besoin un jour ailleurs. Pas de ligne cliquable
 * quand `computerDnsName` est absent : il n'y aurait rien de valide à rechercher.
 */
const BADGE_CLASS = { High: "high", Medium: "medium", Low: "low" };

export default function RiskDevicesList({ devices, onSelectDevice }) {
  const rows = devices || [];

  if (rows.length === 0) {
    return <p className="empty">Aucun device signalé à risque pour l'instant.</p>;
  }

  return (
    <div className="risk-list">
      {rows.map((d, i) => {
        const level = d.exposureLevel || d.riskScore || "Low";
        const badgeClass = BADGE_CLASS[level] || "low";
        const plural = d.alertCount > 1 ? "s" : "";
        const name = d.computerDnsName;
        const rowContent = (
          <>
            <span className="risk-rank">{String(i + 1).padStart(2, "0")}</span>
            <span className="risk-name">
              {name ?? "Device inconnu"}
              <span className="sub">{d.osPlatform ?? "OS inconnu"}</span>
            </span>
            <span className={`badge ${badgeClass}`}>{level}</span>
            <span className="alert-count">
              {d.alertCount} alerte{plural}
            </span>
          </>
        );
        const key = d.id ?? name ?? i;
        return name && onSelectDevice ? (
          <button type="button" className="risk-row device-row-btn" key={key} onClick={() => onSelectDevice(name)}>
            {rowContent}
          </button>
        ) : (
          <div className="risk-row" key={key}>
            {rowContent}
          </div>
        );
      })}
    </div>
  );
}
