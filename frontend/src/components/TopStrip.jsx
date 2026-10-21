import MedallionGauge from "./MedallionGauge.jsx";
import { IconShield, IconLaptop, IconAlertTriangle, IconTarget } from "./icons.jsx";

/**
 * Bandeau compact de tête de la Vue d'ensemble (v2, 2026-08-10) : remplace l'ancien
 * `.hero-panel` (jauge pleine carte + 4 tuiles KPI empilées) par une seule ligne dense —
 * médaillon de score + chips KPI, dont un nouveau chip "Alertes actives" (voir
 * selectors.js::computeTopRiskDevices, qui compte les mêmes alertes pour "Top devices à
 * risque" juste en dessous). Demande explicite de Nicolas : "tt trop gros".
 */
export default function TopStrip({
  score,
  measuredAt,
  exposureError,
  defenderError,
  intuneError,
  totalMachines,
  totalDevices,
  complianceRate,
  nonCompliantCount,
  nonOnboardedCount,
  activeAlertsCount,
}) {
  return (
    <div className="topstrip">
      {exposureError ? (
        <p className="error-note" style={{ margin: 0 }}>
          {exposureError.message}
        </p>
      ) : (
        <>
          <MedallionGauge score={score} />
          <div className="medallion-label">
            <p className="eyebrow">Score global</p>
            <p className="title">Exposure score</p>
            <p className="stamp">{measuredAt ? `màj ${measuredAt}` : "date inconnue"}</p>
          </div>
        </>
      )}

      <div className="chip-row">
        <div className="chip">
          <span className="chip-icon">
            <IconShield />
          </span>
          <div className="chip-text">
            <div className="chip-value">{defenderError ? "—" : totalMachines ?? "—"}</div>
            <div className="chip-title">Machines Defender</div>
          </div>
        </div>

        <div className="chip">
          <span className="chip-icon">
            <IconLaptop />
          </span>
          <div className="chip-text">
            <div className="chip-value">{intuneError ? "—" : totalDevices ?? "—"}</div>
            <div className="chip-title">Appareils Intune{complianceRate ? ` · ${complianceRate}` : ""}</div>
          </div>
        </div>

        <div className={`chip${!intuneError && nonCompliantCount > 0 ? " danger" : ""}`}>
          <span className="chip-icon">
            <IconAlertTriangle />
          </span>
          <div className="chip-text">
            <div className="chip-value">{intuneError ? "—" : nonCompliantCount ?? "—"}</div>
            <div className="chip-title">Non conformes</div>
          </div>
        </div>

        <div className={`chip${!defenderError && nonOnboardedCount > 0 ? " danger" : ""}`}>
          <span className="chip-icon">
            <IconAlertTriangle />
          </span>
          <div className="chip-text">
            <div className="chip-value">{defenderError ? "—" : nonOnboardedCount ?? "—"}</div>
            <div className="chip-title">Non onboardées</div>
          </div>
        </div>

        <div className={`chip${!defenderError && activeAlertsCount > 0 ? " danger" : ""}`}>
          <span className="chip-icon">
            <IconTarget />
          </span>
          <div className="chip-text">
            <div className="chip-value">{defenderError ? "—" : activeAlertsCount ?? "—"}</div>
            <div className="chip-title">Alertes actives</div>
          </div>
        </div>
      </div>
    </div>
  );
}
