import { isErrorPayload } from "../hooks/useDashboardData.js";
import SummaryCard from "../components/SummaryCard.jsx";
import Donut from "../components/Donut.jsx";
import RecommendationsList from "../components/RecommendationsList.jsx";
import DeviceList from "../components/DeviceList.jsx";
import { IconShield, IconGauge, IconAlertTriangle } from "../components/icons.jsx";

/** Onglet "Defender" — focus sur le parc MDE : onboarding, OS, recommandations, non-onboardées. */
export default function DefenderTab({ data }) {
  const defenderError = isErrorPayload(data.defenderSummary) ? data.defenderSummary : null;
  const exposureError = isErrorPayload(data.exposureScore) ? data.exposureScore : null;
  const nonOnboardedCount = data.nonOnboarded.filter((d) => !d?.error).length;
  const exposureScoreValue = data.exposureScore?.score;

  return (
    <>
      <div className="strip">
        <SummaryCard
          icon={<IconShield />}
          title="Machines Defender"
          value={defenderError ? "—" : data.defenderSummary?.totalMachines ?? "—"}
          hint={defenderError ? defenderError.message : "Onboardées + détectées"}
        />
        <SummaryCard
          icon={<IconGauge />}
          title="Exposure score"
          value={exposureError ? "—" : exposureScoreValue?.toFixed(1) ?? "—"}
          hint="/100 — voir Vue d'ensemble pour le détail"
          // exposureScoreValue absent (fetch échoué mais pas un payload {error:true}, cf.
          // useDashboardData.js) : afficher "good" (vert) dans ce cas laisserait croire le parc
          // sain alors que la donnée est simplement manquante — même garde-fou que IntuneTab.jsx
          // (nonCompliantCount), revue de code du 2026-08-18.
          tone={exposureError || exposureScoreValue == null ? undefined : exposureScoreValue >= 70 ? "danger" : exposureScoreValue >= 30 ? "warning" : "good"}
        />
        <SummaryCard
          icon={<IconAlertTriangle />}
          title="Non onboardées"
          value={defenderError ? "—" : nonOnboardedCount}
          hint="CanBeOnboarded / InsufficientInfo"
          tone={defenderError ? undefined : nonOnboardedCount > 0 ? "danger" : "good"}
        />
      </div>

      <div className="bento-row">
        {defenderError ? (
          <div className="card">
            <div className="card-head">
              <h2>Répartition onboarding</h2>
            </div>
            <p className="error-note">{defenderError.message}</p>
          </div>
        ) : (
          <Donut title="Répartition onboarding (Defender)" data={data.defenderSummary?.byOnboardingStatus} />
        )}

        {defenderError ? (
          <div className="card">
            <div className="card-head">
              <h2>Répartition OS</h2>
            </div>
            <p className="error-note">{defenderError.message}</p>
          </div>
        ) : (
          <Donut title="Répartition OS (Defender)" data={data.defenderSummary?.byOSPlatform} />
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <h2>Top recommandations impactant le score</h2>
          <span className="card-note">exposureImpact décroissant</span>
        </div>
        {exposureError && !data.recommendations.length ? (
          <p className="error-note">{exposureError.message}</p>
        ) : (
          <RecommendationsList recommendations={data.recommendations} />
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <h2>Machines non onboardées</h2>
          <span className="card-note">CanBeOnboarded / InsufficientInfo</span>
        </div>
        {defenderError ? (
          <p className="error-note">{defenderError.message}</p>
        ) : (
          <DeviceList devices={data.nonOnboarded} emptyLabel="Toutes les machines détectées sont onboardées." />
        )}
      </div>
    </>
  );
}
