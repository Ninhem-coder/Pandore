import { ALERT_SEVERITY_COLORS, formatRelativeDays } from "../theme.js";
import { tr } from "../i18n/core.js";

/**
 * "Top alertes" (2026-08-27, retour de Nicolas sur la tuile "Alertes Defender" de Vue
 * d'ensemble : "rajouter sur le même bloc à la suite les alertes defender qui sont les plus
 * haut en sévérité, top 3 ou 4") — classement client des alertes les plus sévères, en
 * complément du camembert/des pastilles de statut déjà affichés au-dessus dans la même carte
 * (voir OverviewTab.jsx, tri fait là-bas via `topAlerts` — ce composant reste un simple
 * renderer, pas de logique de tri ici).
 *
 * Même esprit que RiskDevicesList.jsx/NewDevicesList.jsx (pastille + ligne + meta, cliquable
 * vers la fiche device quand un nom valide existe) plutôt qu'un nouveau motif de liste —
 * pastille de couleur (`ALERT_SEVERITY_COLORS`) à la place du rang numéroté : la sévérité EST
 * le critère de tri ici, un numéro de rang n'aurait rien ajouté.
 */
export default function TopAlertsList({ alerts, onSelectDevice }) {
  const rows = alerts || [];

  if (rows.length === 0) {
    return <p className="empty">{tr("overview.noActiveAlert")}</p>;
  }

  return (
    <div className="top-alerts-list">
      {rows.map((a, i) => {
        const color = ALERT_SEVERITY_COLORS[a.severity] || ALERT_SEVERITY_COLORS.UnSpecified;
        const name = a.computerDnsName;
        const rowContent = (
          <>
            <span className="top-alert-dot" style={{ background: color }} title={a.severity || tr("overview.unknownSeverity")} />
            <span className="top-alert-main">
              <span className="top-alert-title">{a.title || tr("overview.untitledAlert")}</span>
              <span className="sub">
                {name ?? tr("common.unknownDevice")} · {formatRelativeDays(a.alertCreationTime)}
              </span>
            </span>
          </>
        );
        const key = a.id ?? `${a.title}-${i}`;
        return name && onSelectDevice ? (
          <button type="button" className="top-alert-row device-row-btn" key={key} onClick={() => onSelectDevice(name)}>
            {rowContent}
          </button>
        ) : (
          <div className="top-alert-row" key={key}>
            {rowContent}
          </div>
        );
      })}
    </div>
  );
}
