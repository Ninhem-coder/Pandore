import { formatRelativeDays } from "../theme.js";
import { tr } from "../i18n/core.js";

/**
 * "Nouveaux devices (7 jours)" (Vue d'ensemble v2, 2026-08-10) — machines dont `firstSeen`
 * (Defender) tombe dans la fenêtre demandée, voir selectors.js::computeNewDevices.
 *
 * `onSelectDevice` (2026-08-20) — même mécanique que RiskDevicesList.jsx (voir son
 * commentaire pour le contexte de la demande) : ligne rendue en `<button>` cliquable/
 * navigable au clavier quand un nom de device valide existe et que le prop est fourni,
 * sinon simple `<div>` non interactif.
 */
export default function NewDevicesList({ devices, onSelectDevice }) {
  const rows = devices || [];

  if (rows.length === 0) {
    return <p className="empty">{tr("overview.noNewDevice")}</p>;
  }

  return (
    <div className="new-list">
      {rows.map((d, i) => {
        const age = formatRelativeDays(d.firstSeen);
        const name = d.computerDnsName;
        const rowContent = (
          <>
            <span className="new-name">
              {name ?? tr("common.unknownDevice")}
              <span className="sub">
                {d.osPlatform ?? tr("common.unknownOs")} · {d.onboardingStatus ?? tr("overview.unknownStatus")}
              </span>
            </span>
            <span className={`age-pill${age === tr("relative.today") ? " today" : ""}`}>{age}</span>
          </>
        );
        const key = d.id ?? name ?? i;
        return name && onSelectDevice ? (
          <button type="button" className="new-row device-row-btn" key={key} onClick={() => onSelectDevice(name)}>
            {rowContent}
          </button>
        ) : (
          <div className="new-row" key={key}>
            {rowContent}
          </div>
        );
      })}
    </div>
  );
}
