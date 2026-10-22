import { tr } from "../i18n/core.js";
/** Port de build_recommendations_html() : liste classée, rang mono, badge d'impact
 * (points d'exposure score) en vert mono — même langage que la carte HTML du skill. */
export default function RecommendationsList({ recommendations }) {
  const rows = (recommendations || []).filter((r) => !r?.error);

  if (rows.length === 0) {
    return <p className="empty">{tr("overview.noRecommendation")}</p>;
  }

  return (
    <ul className="reco-list">
      {rows.map((r, i) => {
        const exposed = r.exposedMachinesCount;
        const exposedTxt = exposed != null ? tr("overview.exposedDevices", { count: exposed }) : tr("overview.exposedUnknown");
        const impact = r.exposureImpact;
        return (
          <li className="reco-row" key={r.recommendationName ?? i}>
            <span className="reco-rank">{String(i + 1).padStart(2, "0")}</span>
            <div className="reco-main">
              <span className="reco-name">{r.recommendationName ?? tr("overview.recommendation")}</span>
              <span className="reco-meta">
                {r.recommendationCategory ?? ""} · {exposedTxt}
              </span>
            </div>
            {typeof impact === "number" ? (
              <span className="reco-impact">-{impact.toFixed(1)} pts</span>
            ) : (
              <span className="reco-impact" style={{ color: "var(--ink-dim)" }}>
                {tr("overview.impactUnknown")}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}
