import { COMPLIANCE_COLORS, COMPLIANCE_DEFAULT_COLOR, COMPLIANCE_LABEL } from "../theme.js";
import { buildDonutEntries } from "../selectors.js";
import { tr } from "../i18n/core.js";

/**
 * Version compacte de ComplianceOverview.jsx pour la Vue d'ensemble v2 (2026-08-10) : une
 * seule barre segmentée + légende, au lieu de deux camemberts côte à côte (état + échecs
 * par politique). Le détail complet (camemberts, tableau par device) reste dans l'onglet
 * "Conformité Intune" — cette carte ne sert plus qu'à donner le taux d'un coup d'œil.
 */
export default function ComplianceMini({ byState, complianceRate }) {
  const { entries, total } = buildDonutEntries(byState, {
    colors: COMPLIANCE_COLORS,
    labels: COMPLIANCE_LABEL,
    defaultColor: COMPLIANCE_DEFAULT_COLOR,
  });

  if (entries.length === 0) {
    return <p className="empty">{tr("compliance.miniUnavailable")}</p>;
  }

  const compliantEntry = entries.find((e) => e.key === "compliant");
  const rate = complianceRate ?? (compliantEntry && total ? `${((compliantEntry.value / total) * 100).toFixed(1)}%` : "—");

  return (
    <div className="compliance-mini">
      <div className="compliance-rate">
        {rate}
        <span>{tr("compliance.miniCompliant")}</span>
      </div>
      <div className="compliance-bar-wrap">
        <div className="compliance-bar">
          {entries.map((e) => (
            <span key={e.key} style={{ width: `${(e.fraction * 100).toFixed(2)}%`, background: e.color }} />
          ))}
        </div>
        <div className="compliance-legend-row">
          {entries.map((e) => (
            <div className="legend-row" key={e.key}>
              <span className="legend-dot" style={{ background: e.color }} />
              <span className="legend-label" title={e.label}>
                {e.label}
              </span>
              <span className="legend-value">{e.value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
