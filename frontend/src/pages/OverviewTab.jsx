import { useMemo, useState } from "react";
import { isErrorPayload, useOverviewSignals, useHistoryTrend, useDefenderAlerts } from "../hooks/useDashboardData.js";
import useReorderableZone from "../hooks/useReorderableZone.js";
import {
  secureScoreLevel,
  EXPOSURE_LEVEL_COLORS,
  EXPOSURE_LEVEL_LABEL,
  CRITICALITY_LEVELS,
  ALERT_SEVERITY_COLORS,
  ALERT_STATUS_LABEL,
  SECURE_SCORE_CATEGORY_LABEL,
} from "../theme.js";
import { computeTopRiskDevices, computeNewDevices, computeHistoryTrend, buildDonutEntries } from "../selectors.js";
import TopStrip from "../components/TopStrip.jsx";
import RiskDevicesList from "../components/RiskDevicesList.jsx";
import NewDevicesList from "../components/NewDevicesList.jsx";
import ComplianceMini from "../components/ComplianceMini.jsx";
import Donut from "../components/Donut.jsx";
import DonutSvg from "../components/DonutSvg.jsx";
import DonutLegend from "../components/DonutLegend.jsx";
import RecommendationsList from "../components/RecommendationsList.jsx";
import TopAlertsList from "../components/TopAlertsList.jsx";
import { IconGauge, IconTarget, IconBookmark, IconShield, IconGrip } from "../components/icons.jsx";
import { currentLocale, tr } from "../i18n/core.js";

/**
 * Onglet "Vue d'ensemble" — v4 (2026-08-27). Après un aller-retour sur un onglet de test
 * séparé ("Vue d'ensemble (test)", voir CLAUDE.md pour l'historique complet des deux jets) :
 * "j'aime pas le désign mais j'aime bien les fonctionnalités on va sup la page de test mais
 * on va prendre les fonctionnalités qu'on va mettre dans la vue d'ensemble de base. Tu
 * implémenter juste les fonctionnalités pas le visuel." — l'onglet de test est supprimé
 * (`OverviewTestTab.jsx`), ses CAPACITÉS sont fusionnées ICI, dans CET onglet, mais avec le
 * design/les composants VISUELS d'origine intégralement conservés (`.card`/`.signal-card`/
 * `TrendMiniCard`/`RiskDevicesList`/etc. — rien de neuf visuellement, aucune classe de texte
 * réinventée).
 *
 * ── Ce qui a été repris de l'onglet de test (les "fonctionnalités") ──
 * 1. **Glisser-déposer réordonnable, EN DIRECT** (`useReorderableZone`) : les autres cartes se
 *    décalent dès qu'on survole une cible (`onDragEnter`, pas seulement au `drop`), animation
 *    FLIP pour un déplacement fluide. Appliqué à DEUX zones INDÉPENDANTES plutôt qu'une seule
 *    grille globale — décision explicite de Nicolas (`AskUserQuestion`) : garder la colonne
 *    principale (`.ov2-main`) et le rail latéral sticky (`.ov2-rail`) séparés comme
 *    aujourd'hui, réordonner/redimensionner seulement À L'INTÉRIEUR de chacune, jamais de
 *    l'une vers l'autre.
 * 2. **Redimensionnement** — SEULEMENT dans `.ov2-main` (`SIZE_STEPS`, boutons `−`/`+`) : le
 *    rail fait 336px de large et n'affiche qu'UNE colonne (voir `.ov2-rail .signal-grid` dans
 *    styles.css, déjà en place avant ce changement) — redimensionner la LARGEUR n'y a aucun
 *    sens. Le rail garde le réordonnancement seul ; ses 3 tuiles enrichies (voir point 4)
 *    ont un bouton "voir plus/moins" propre à leur contenu à la place d'un resize générique.
 * 3. **Nouvelle tuile "Alertes Defender"** (`.ov2-main`, `useDefenderAlerts` — chargée à la
 *    demande comme le reste du dashboard, bénéficie du cache partagé TTL 2h) : répartition
 *    des alertes actives par sévérité (camembert, réutilise DonutSvg/DonutLegend) et par
 *    statut. N'existait nulle part sur cette page avant.
 * 4. **Listes enrichies** dans les tuiles "Par criticité"/"Suivi CVE"/"ANSSI" (rail) — un
 *    bouton "voir plus" déplie jusqu'à 5-8 éléments au lieu du seul premier ; repliable pour
 *    revenir à l'aperçu compact d'origine.
 *
 * ── Ce qui a été délibérément écarté de l'onglet de test ──
 * Le chrome visuel bento (`.bento-*`, tuiles 170px, titres custom) : entièrement supprimé,
 * jamais réintroduit ici — cet onglet n'utilise QUE des classes déjà existantes
 * (`.card`/`.card-head`/`.signal-card`/`.signal-value`/`.trend-*`) précisément parce que
 * Nicolas a explicitement rejeté le nouveau visuel tout en validant les capacités.
 *
 * ── Retour sur les courbes de tendance (même demande) ──
 * "j'aimerai bien au lieu d'avoir un graph d'avoir juste le score avec une flèche vers le bas
 * [...] et une flèche vers le haut si ça augmente" — le SVG `.trend-mini` (sparkline pleine
 * largeur) est retiré des DEUX `TrendMiniCard` (Conformité Intune/Exposure score) et remplacé
 * par une flèche (`TrendArrow`) à côté du chiffre, colorée comme le badge d'écart déjà en
 * place (vert si la tendance est favorable pour CETTE métrique, rouge sinon — jamais figée
 * sur une seule couleur comme l'était l'ancien sparkline, codé en dur en vert quel que soit
 * le sens). Les badges d'écart 7j/30j (texte) restent inchangés, seul le graphique disparaît.
 * Le sparkline de "Secure Score" (rail, `.signal-sparkline`) N'EST PAS concerné — Nicolas a
 * nommé précisément "la conformité du parc et l'exposure score", pas Secure Score.
 */

/** Une tuile "Signaux" cliquable — même carcasse pour les 4 (Secure Score/Par criticité/Suivi
 * CVE/ANSSI). `<div role="button">` (pour accueillir la poignée de glisser-déposer — du
 * contenu interactif imbriqué n'est pas valide dans un `<button>`, même motif déjà en place
 * ailleurs dans ce dashboard pour `.app-card-row`/`.library-card-clickable`) : `onKeyDown`
 * gère Entrée/Espace à la main pour ne rien perdre côté clavier. `dragHandleProps`/
 * `onDragEnter`/`onDrop`/`tileRef` viennent du réordonnancement (`useReorderableZone`) — la
 * carte entière reste la cible de drop, seule la poignée (`.ov2-grip`) déclenche le drag,
 * `stopPropagation()` dessus pour ne pas aussi naviguer au clic.
 *
 * Toute la carte navigue au clic vers "Voir le détail →", pour les 4 tuiles SANS exception
 * (2026-08-27, retour de Nicolas sur "Par criticité" : "j'ai toujours 'Voir les devices' de
 * cliquable et 'Voir le détail' aussi... qu'un des deux, pas les deux" — un `clickTarget`
 * ("card"/"goto") avait été introduit dans un premier temps pour restreindre le clic au seul
 * lien "Voir le détail →" quand une tuile embarquait AUSSI son propre contrôle imbriqué
 * ("Voir les devices ▾"), mais Nicolas a tranché pour l'option inverse : garder "Voir le
 * détail" et retirer "Voir les devices" de "Par criticité" plutôt que l'inverse — il n'y a
 * donc plus qu'UNE seule tuile candidate à ce mode, "Par criticité" elle-même, qui n'en a
 * justement plus besoin. `clickTarget` retiré entièrement (plus aucun appelant) plutôt que
 * laissé en infrastructure inutilisée. */
function SignalCard({ icon, label, note, onClick, children, tone, tileRef, dragHandleProps, onDragEnter, onDrop }) {
  function handleKeyDown(e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onClick?.();
    }
  }
  return (
    <div
      ref={tileRef}
      role="button"
      tabIndex={0}
      className={`signal-card${tone ? ` tone-${tone}` : ""}`}
      onClick={onClick}
      onKeyDown={handleKeyDown}
      onDragOver={(e) => e.preventDefault()}
      onDragEnter={onDragEnter}
      onDrop={(e) => {
        e.preventDefault();
        onDrop?.();
      }}
    >
      <div className="signal-card-head">
        <span className="signal-icon">{icon}</span>
        <span className="signal-label">{label}</span>
        <span
          className="ov2-grip"
          title={tr("common.dragToReorder")}
          onClick={(e) => e.stopPropagation()}
          {...dragHandleProps}
        >
          <IconGrip />
        </span>
      </div>
      {children}
      {note && <p className="signal-note">{note}</p>}
      <span className="signal-goto">{tr("overview.seeDetail")}</span>
    </div>
  );
}

/** Écart formaté (+2.3 / -1.1 / —) coloré selon si le sens de variation est favorable ou
 * défavorable pour LA métrique concernée — la même hausse est bonne pour le taux de
 * conformité (`favorableDirection="up"`) mais mauvaise pour l'exposure score
 * (`favorableDirection="down"`), donc jamais codée en dur sur le signe seul. */
function DeltaBadge({ delta, unit, favorableDirection }) {
  if (delta == null) return <span className="trend-delta trend-delta-na">—</span>;
  const improved = favorableDirection === "up" ? delta > 0 : delta < 0;
  const worsened = favorableDirection === "up" ? delta < 0 : delta > 0;
  const tone = delta === 0 ? "flat" : improved ? "good" : worsened ? "bad" : "flat";
  const sign = delta > 0 ? "+" : "";
  return (
    <span className={`trend-delta trend-delta-${tone}`}>
      {sign}
      {delta}
      {unit}
    </span>
  );
}

/** Remplace le SVG `.trend-mini` des deux TrendMiniCard (2026-08-27, demande de Nicolas — voir
 * le commentaire d'en-tête de fichier) : une flèche haut/bas à côté du chiffre plutôt qu'une
 * courbe, colorée selon le même sens favorable/défavorable que `DeltaBadge` (jamais fixée sur
 * une seule couleur). Basée sur `delta7` (la tendance la plus récente) ; `flat` (→, gris) si
 * `delta7` est nul ou indisponible. */
/** Libellé d'en-tête de la tuile "Secure Score" (2026-08-27, retour de Nicolas : "mettre le
 * score en vert ou rouge en fonction de si le score augmente ou pas, avec une petite flèche à
 * droite du score de la même taille que le score") — contrairement à `TrendArrow` ci-dessus
 * (flèche 20px, dédiée aux `TrendMiniCard`), ce libellé vit DANS `.signal-label` (mono 11px
 * uppercase, voir styles.css) : `.secure-score-header-value`/`.secure-score-header-arrow`
 * n'ont volontairement PAS de `font-size` propre, pour hériter cette même taille — "de la même
 * taille que le score" demandé littéralement, pas une flèche standard réutilisée telle quelle.
 * Binaire (vert/rouge), pas de 3e état neutre gris comme `TrendArrow` : Nicolas a formulé la
 * demande en "vert ou rouge" selon que le score "augmente ou pas" — un score stable ou en
 * baisse compte donc comme "pas" et reste rouge, contrairement à `TrendArrow`/`DeltaBadge`
 * (Conformité/Exposure) qui traitent un delta nul comme neutre. */
function SecureScoreHeaderLabel({ pct, delta }) {
  if (pct == null) return "Secure Score";
  if (delta == null) return `Secure Score — ${pct}%`;
  const color = delta > 0 ? "var(--low)" : "var(--high)";
  const arrow = delta > 0 ? "↑" : delta < 0 ? "↓" : "→";
  return (
    <>
      Secure Score —{" "}
      <span className="secure-score-header-value" style={{ color }}>
        {pct}%
      </span>
      <span className="secure-score-header-arrow" style={{ color }} aria-hidden="true">
        {arrow}
      </span>
    </>
  );
}

function TrendArrow({ delta, favorableDirection }) {
  if (delta == null || delta === 0) {
    return (
      <span className="trend-arrow trend-arrow-flat" title={tr("overview.stable")}>
        →
      </span>
    );
  }
  const up = delta > 0;
  const improved = favorableDirection === "up" ? up : !up;
  return (
    <span className={`trend-arrow ${improved ? "trend-arrow-good" : "trend-arrow-bad"}`} title={tr(up ? "overview.rising" : "overview.falling")}>
      {up ? "↑" : "↓"}
    </span>
  );
}

// Ordre de sévérité des alertes MDE, dérivé des clés (déjà classées High→UnSpecified) de
// `ALERT_SEVERITY_COLORS` (theme.js) — réutilisé pour trier `topAlerts` (voir plus bas) sans
// dupliquer un 2e classement en dur.
const SEVERITY_ORDER = Object.keys(ALERT_SEVERITY_COLORS);

// Tuile "Secure Score" (2026-08-27, retour de Nicolas : "juste mettre le % des données,
// appareil, applications, identité") — 4 des 5 catégories de `SECURE_SCORE_CATEGORY_LABEL`
// (Infrastructure exclue, pas demandée), dans l'ordre énoncé par Nicolas. Clés Graph
// (`controlCategory`), pas les libellés FR — traduites à l'affichage via
// `SECURE_SCORE_CATEGORY_LABEL`.
const SECURE_SCORE_MINI_CATEGORIES = ["Data", "Device", "Apps", "Identity"];

/** Fenêtre de l'historique des cartes "Tendance" : 90 jours = la totalité de l'historique
 * conservé (un point par jour côté backend, common/history.py). Le sélecteur 7/14/30/90 j
 * (`HistoryRangePicker`, 2026-08-20) a été retiré le 2026-10-21 à la demande de Nicolas — il
 * n'influençait plus rien de visible depuis le retrait du sparkline (2026-08-27) ; 90 j était
 * déjà sa valeur par défaut, l'affichage est donc inchangé. */
const HISTORY_RANGE_DAYS = 90;

/** Poignée + boutons de redimensionnement d'une tuile de `.ov2-main` — voir `useReorderableZone`
 * (`sizeIndex`/`onResize`) et `SIZE_STEPS` ci-dessous. */
function TileControls({ cardKey, sizeIndex, onResize, dragHandleProps }) {
  return (
    <div className="ov2-tile-controls">
      <button
        type="button"
        className="ov2-size-btn"
        onClick={() => onResize(cardKey, -1)}
        disabled={sizeIndex <= 0}
        title={tr("overview.shrinkTile")}
        aria-label={tr("overview.shrinkTile")}
      >
        −
      </button>
      <button
        type="button"
        className="ov2-size-btn"
        onClick={() => onResize(cardKey, 1)}
        disabled={sizeIndex >= SIZE_STEPS.length - 1}
        title={tr("overview.growTile")}
        aria-label={tr("overview.growTile")}
      >
        +
      </button>
      <span className="ov2-grip" title={tr("common.dragToReorder")} {...dragHandleProps}>
        <IconGrip />
      </span>
    </div>
  );
}

function TrendMiniCard({ title, note, unit, favorableDirection, metric, loading, error, emptyHint, cardKey, sizeIndex, onResize, tileRef, dragHandleProps, onDragEnter, onDrop }) {
  return (
    <div
      className="card trend-mini-card"
      ref={tileRef}
      onDragOver={(e) => e.preventDefault()}
      onDragEnter={onDragEnter}
      onDrop={(e) => {
        e.preventDefault();
        onDrop?.();
      }}
    >
      <div className="card-head">
        <h2>{title}</h2>
        <div className="ov2-head-right">
          <span className="card-note">{note}</span>
          <TileControls cardKey={cardKey} sizeIndex={sizeIndex} onResize={onResize} dragHandleProps={dragHandleProps} />
        </div>
      </div>
      {loading ? (
        <p className="signal-loading">{tr("common.loading")}</p>
      ) : error ? (
        <p className="error-note">{error}</p>
      ) : !metric || metric.current == null ? (
        <p className="signal-note-inline">{emptyHint}</p>
      ) : (
        <>
          <div className="signal-value-row">
            <div className="signal-value">
              {metric.current}
              {unit}
            </div>
            <TrendArrow delta={metric.delta7} favorableDirection={favorableDirection} />
          </div>
          <div className="trend-delta-row">
            <span>
              {tr("overview.vs7")} <DeltaBadge delta={metric.delta7} unit={unit} favorableDirection={favorableDirection} />
            </span>
            <span>
              {tr("overview.vs30")} <DeltaBadge delta={metric.delta30} unit={unit} favorableDirection={favorableDirection} />
            </span>
          </div>
        </>
      )}
    </div>
  );
}

/** Deux crans possibles pour une tuile de `.ov2-main` (largeur × hauteur, en unités de grille
 * — voir `.ov2-main-grid`, `grid-auto-rows: 170px`) — même échelle que le premier jet de
 * l'onglet de test, réutilisée sans changement : 1×1 à 4×2. */
const SIZE_STEPS = [
  { c: 1, r: 1 },
  { c: 1, r: 2 },
  { c: 2, r: 1 },
  { c: 2, r: 2 },
  { c: 4, r: 1 },
  { c: 4, r: 2 },
];

const MAIN_DEFAULT_ORDER = ["compliance-trend", "exposure-trend", "onboarding", "os", "top-risk", "new-devices", "defender-alerts", "recommendations"];
// `compliance-trend`/`exposure-trend` en 1×1 (2026-08-27, retour de Nicolas : "les tailles ne
// vont pas") — depuis le retrait du sparkline (voir TrendArrow plus haut), leur contenu réel
// (titre + valeur/flèche + 2 lignes de delta, ~114px) tient largement dans une seule rangée de
// grille (170px) ; le cran 1×2 hérité de l'AVANT-retrait du sparkline (quand la courbe occupait
// la moitié basse de la carte) laissait ~180px de vide sous le texte. `onboarding`/`os` restent
// en 1×2 : ce sont des donuts + légendes multi-lignes, un contenu réellement plus haut.
const MAIN_DEFAULT_SIZES = {
  "compliance-trend": 0,
  "exposure-trend": 0,
  onboarding: 1,
  os: 1,
  "top-risk": 3,
  "new-devices": 3,
  "defender-alerts": 3,
  recommendations: 5,
};
const RAIL_DEFAULT_ORDER = ["secure-score", "criticality", "cve-watch", "anssi", "compliance-state"];

export default function OverviewTab({ data, onNavigate }) {
  const defenderError = isErrorPayload(data.defenderSummary) ? data.defenderSummary : null;
  const intuneError = isErrorPayload(data.intuneSummary) ? data.intuneSummary : null;
  const exposureError = isErrorPayload(data.exposureScore) ? data.exposureScore : null;

  const score = exposureError ? null : data.exposureScore?.score;
  const nonCompliantCount = data.intuneSummary?.nonCompliantCount;
  const nonOnboardedCount = data.nonOnboarded.filter((d) => !d?.error).length;

  const topRiskDevices = useMemo(() => computeTopRiskDevices(data.machines, data.alerts, 50), [data.machines, data.alerts]);
  const newDevices = useMemo(() => computeNewDevices(data.machines, 7, 100), [data.machines]);
  const activeAlertsCount = useMemo(
    () => (data.alerts || []).filter((a) => !a?.error && a.status !== "Resolved").length,
    [data.alerts]
  );

  const topRecommendations = useMemo(() => data.recommendations.filter((r) => !r?.error).slice(0, 3), [data.recommendations]);

  const criticalityCounts = CRITICALITY_LEVELS.map((level) => ({
    level,
    count: data.defenderSummary?.byExposureLevel?.[level] || 0,
  }));
  const criticalityTotal = criticalityCounts.reduce((sum, c) => sum + c.count, 0);
  // Survol croisé bar ↔ légende de "Par criticité" (2026-08-27, retour de Nicolas : "la
  // légende me convient pas") — même mécanique que les donuts Onboarding/OS (Donut.jsx,
  // survol transitoire du graph OU de la légende, l'un met l'autre en évidence), transposée à
  // la barre segmentée : la légende n'était jusqu'ici qu'un simple rappel textuel sans aucune
  // interaction, contrairement au reste du dashboard où survoler une légende répond déjà.
  const [hoveredCriticality, setHoveredCriticality] = useState(null);
  const [cveExpanded, setCveExpanded] = useState(false);
  const [anssiExpanded, setAnssiExpanded] = useState(false);

  const signals = useOverviewSignals();
  // Score global de la tuile "Secure Score" (2026-08-27, retour de Nicolas : "mettre le score
  // en vert ou rouge en fonction de si le score augmente ou pas") — écart entre aujourd'hui et
  // le point le plus ancien de la fenêtre 7 jours déjà chargée par `useOverviewSignals`
  // (`secureScoreTrend`, PAS un nouvel appel réseau). `null` tant que l'historique n'a pas au
  // moins 2 points (rien à comparer) — la tuile retombe alors sur la couleur neutre par défaut.
  const secureScoreDelta =
    signals.secureScoreTrend.length > 1 ? signals.secureScorePct - signals.secureScoreTrend[0] : null;
  const history = useHistoryTrend();
  const historyTrend = useMemo(() => computeHistoryTrend(history.points, HISTORY_RANGE_DAYS), [history.points]);
  // Valeur affichée = taux EN DIRECT (`intuneSummary.complianceRate`, même source que la page
  // Conformité), l'historique ne servant qu'aux écarts 7/30 j (2026-10-21, harmonisation
  // demandée par Nicolas : le Dashboard affichait 86,3 %, le dernier point d'historique vieux
  // d'un mois, quand la page Conformité affichait 92,1 % en direct).
  const intuneComplianceMetric = useMemo(() => {
    const live = parseFloat(data.intuneSummary?.complianceRate);
    return Number.isNaN(live) ? historyTrend.intune : { ...historyTrend.intune, current: live };
  }, [historyTrend.intune, data.intuneSummary?.complianceRate]);

  const watchedExposedCount = useMemo(
    () => signals.watchedCves.filter((e) => !e?.error && (e.result?.affected_count || 0) > 0).length,
    [signals.watchedCves]
  );
  const topWatchedCve = signals.watchedCves.find((e) => !e?.error && (e.result?.affected_count || 0) > 0) || signals.watchedCves[0];

  const topAnssiMatch = signals.anssiMatches[0] || null;

  // "Alertes Defender" (2026-08-27, nouvelle tuile de `.ov2-main`, reprise de l'onglet de
  // test) — chargée à la demande (useDefenderAlerts), même hook que l'onglet "Alertes
  // Defender" existant, bénéficie du cache partagé TTL 2h.
  const alerts = useDefenderAlerts();
  const severityBreakdown = useMemo(() => {
    const counts = {};
    (alerts.alerts || []).forEach((a) => {
      if (a?.error) return;
      const sev = a.severity && ALERT_SEVERITY_COLORS[a.severity] ? a.severity : "UnSpecified";
      counts[sev] = (counts[sev] || 0) + 1;
    });
    return buildDonutEntries(counts, { colors: ALERT_SEVERITY_COLORS });
  }, [alerts.alerts]);
  const statusBreakdown = useMemo(() => {
    const counts = { New: 0, InProgress: 0, Resolved: 0 };
    (alerts.alerts || []).forEach((a) => {
      if (a?.error) return;
      const st = a.status && ALERT_STATUS_LABEL[a.status] ? a.status : "Unknown";
      counts[st] = (counts[st] || 0) + 1;
    });
    return counts;
  }, [alerts.alerts]);
  // "Top alertes" (2026-08-27, retour de Nicolas : "rajouter à la suite les alertes defender
  // qui sont les plus haut en sévérité, top 3 ou 4") — tri par sévérité DESC (ordre déjà
  // sémantique des clés de `ALERT_SEVERITY_COLORS`, High en premier), `alertCreationTime` DESC
  // en départage à sévérité égale (l'alerte la plus récente d'abord, plus utile qu'un ordre
  // arbitraire). 4 retenues (borne haute de la fourchette "top 3 ou 4" de Nicolas).
  const topAlerts = useMemo(() => {
    return (alerts.alerts || [])
      .filter((a) => !a?.error)
      .slice()
      .sort((a, b) => {
        const rankA = SEVERITY_ORDER.indexOf(a.severity) === -1 ? SEVERITY_ORDER.length : SEVERITY_ORDER.indexOf(a.severity);
        const rankB = SEVERITY_ORDER.indexOf(b.severity) === -1 ? SEVERITY_ORDER.length : SEVERITY_ORDER.indexOf(b.severity);
        if (rankA !== rankB) return rankA - rankB;
        return new Date(b.alertCreationTime || 0) - new Date(a.alertCreationTime || 0);
      })
      .slice(0, 4);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alerts.alerts]);

  // Clé bumpée en `-v2` (2026-08-27, correctif de taille ci-dessus) — un `layout.sizes` déjà
  // enregistré dans le localStorage de Nicolas aurait sinon écrasé le nouveau défaut 1×1 en
  // bloc (`saved.sizes || defaultSizes`, pas de fusion clé par clé), le correctif serait donc
  // resté invisible pour lui sans ce changement de clé. Même convention déjà en place dans ce
  // projet pour un changement de FORME du layout persisté (ex. "overviewTestBentoLayout-v2").
  const main = useReorderableZone(MAIN_DEFAULT_ORDER, MAIN_DEFAULT_SIZES, "overviewMainLayout-v2", {
    sizeCount: SIZE_STEPS.length,
    defaultSize: 3,
  });
  const rail = useReorderableZone(RAIL_DEFAULT_ORDER, {}, "overviewRailOrder-v1");

  const mainBody = {
    "compliance-trend": (
      <TrendMiniCard
        title={tr("overview.complianceTrend")}
        note={tr("overview.complianceRate")}
        unit="%"
        favorableDirection="up"
        metric={intuneComplianceMetric}
        loading={history.loading}
        error={history.error}
        emptyHint={tr("overview.historyBuilding")}
        cardKey="compliance-trend"
        sizeIndex={main.sizes["compliance-trend"] ?? 0}
        onResize={main.resize}
        tileRef={(n) => main.registerNode("compliance-trend", n)}
        dragHandleProps={main.dragHandleProps("compliance-trend")}
        onDragEnter={() => main.onDragEnter("compliance-trend")}
        onDrop={main.onDrop}
      />
    ),
    "exposure-trend": (
      <TrendMiniCard
        title="Exposure (Defender)"
        note="/100"
        unit=""
        favorableDirection="down"
        metric={historyTrend.defender}
        loading={history.loading}
        error={history.error}
        emptyHint={tr("overview.historyBuilding")}
        cardKey="exposure-trend"
        sizeIndex={main.sizes["exposure-trend"] ?? 0}
        onResize={main.resize}
        tileRef={(n) => main.registerNode("exposure-trend", n)}
        dragHandleProps={main.dragHandleProps("exposure-trend")}
        onDragEnter={() => main.onDragEnter("exposure-trend")}
        onDrop={main.onDrop}
      />
    ),
    // Onboarding/OS (2026-08-27, correctif "bordure double" — retour de Nicolas) : `Donut`
    // amène déjà son propre `.card` racine — plus d'enveloppe `<div className="card">` en
    // plus autour (c'était ÇA la bordure "dans" la bordure). La ref FLIP et les handlers de
    // glisser-déposer sont maintenant posés DIRECTEMENT sur le `.card` de `Donut` via les
    // nouvelles props `cardRef`/`onDragOver`/`onDragEnter`/`onDrop` (voir Donut.jsx) — un
    // seul `.card` réel dans le DOM, comme partout ailleurs sur cette page. Le cas d'erreur
    // (pas de Donut à afficher) garde, lui, son propre `.card` — c'est le SEUL `.card` de
    // cette branche, pas un doublon.
    onboarding: defenderError ? (
      <div
        className="card"
        ref={(n) => main.registerNode("onboarding", n)}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => main.onDragEnter("onboarding")}
        onDrop={(e) => {
          e.preventDefault();
          main.onDrop();
        }}
      >
        <div className="card-head">
          <h2>Onboarding</h2>
          <TileControls cardKey="onboarding" sizeIndex={main.sizes.onboarding ?? 1} onResize={main.resize} dragHandleProps={main.dragHandleProps("onboarding")} />
        </div>
        <p className="error-note">{defenderError.message}</p>
      </div>
    ) : (
      <Donut
        title="Onboarding"
        data={data.defenderSummary?.byOnboardingStatus}
        compact
        headerExtra={<TileControls cardKey="onboarding" sizeIndex={main.sizes.onboarding ?? 1} onResize={main.resize} dragHandleProps={main.dragHandleProps("onboarding")} />}
        cardRef={(n) => main.registerNode("onboarding", n)}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => main.onDragEnter("onboarding")}
        onDrop={(e) => {
          e.preventDefault();
          main.onDrop();
        }}
      />
    ),
    os: defenderError ? (
      <div
        className="card"
        ref={(n) => main.registerNode("os", n)}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => main.onDragEnter("os")}
        onDrop={(e) => {
          e.preventDefault();
          main.onDrop();
        }}
      >
        <div className="card-head">
          <h2>OS</h2>
          <TileControls cardKey="os" sizeIndex={main.sizes.os ?? 1} onResize={main.resize} dragHandleProps={main.dragHandleProps("os")} />
        </div>
        <p className="error-note">{defenderError.message}</p>
      </div>
    ) : (
      <Donut
        title="OS"
        data={data.defenderSummary?.byOSPlatform}
        compact
        headerExtra={<TileControls cardKey="os" sizeIndex={main.sizes.os ?? 1} onResize={main.resize} dragHandleProps={main.dragHandleProps("os")} />}
        cardRef={(n) => main.registerNode("os", n)}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => main.onDragEnter("os")}
        onDrop={(e) => {
          e.preventDefault();
          main.onDrop();
        }}
      />
    ),
    "top-risk": (
      <div
        className="card"
        ref={(n) => main.registerNode("top-risk", n)}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => main.onDragEnter("top-risk")}
        onDrop={(e) => {
          e.preventDefault();
          main.onDrop();
        }}
      >
        <div className="card-head">
          <h2>{tr("overview.topRisk")}</h2>
          <div className="ov2-head-right">
            <span className="card-note">{tr("overview.topRiskNote")}</span>
            <TileControls cardKey="top-risk" sizeIndex={main.sizes["top-risk"] ?? 3} onResize={main.resize} dragHandleProps={main.dragHandleProps("top-risk")} />
          </div>
        </div>
        {defenderError ? (
          <p className="error-note">{defenderError.message}</p>
        ) : (
          <RiskDevicesList devices={topRiskDevices} onSelectDevice={(name) => onNavigate?.("device-overview", name)} />
        )}
      </div>
    ),
    "new-devices": (
      <div
        className="card"
        ref={(n) => main.registerNode("new-devices", n)}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => main.onDragEnter("new-devices")}
        onDrop={(e) => {
          e.preventDefault();
          main.onDrop();
        }}
      >
        <div className="card-head">
          <h2>{tr("overview.newDevices")}</h2>
          <div className="ov2-head-right">
            <span className="card-note">{tr("overview.newDevicesNote")}</span>
            <TileControls cardKey="new-devices" sizeIndex={main.sizes["new-devices"] ?? 3} onResize={main.resize} dragHandleProps={main.dragHandleProps("new-devices")} />
          </div>
        </div>
        {defenderError ? (
          <p className="error-note">{defenderError.message}</p>
        ) : (
          <NewDevicesList devices={newDevices} onSelectDevice={(name) => onNavigate?.("device-overview", name)} />
        )}
      </div>
    ),
    "defender-alerts": (
      <div
        className="card"
        ref={(n) => main.registerNode("defender-alerts", n)}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => main.onDragEnter("defender-alerts")}
        onDrop={(e) => {
          e.preventDefault();
          main.onDrop();
        }}
      >
        <div className="card-head">
          <h2>{tr("overview.defenderAlerts")}</h2>
          <div className="ov2-head-right">
            <span className="card-note">{tr("overview.activeCount", { count: activeAlertsCount })}</span>
            <TileControls cardKey="defender-alerts" sizeIndex={main.sizes["defender-alerts"] ?? 3} onResize={main.resize} dragHandleProps={main.dragHandleProps("defender-alerts")} />
          </div>
        </div>
        {alerts.error ? (
          <p className="error-note">{alerts.error}</p>
        ) : (
          <>
            <div className="ov2-alerts-donut-row">
              <DonutSvg entries={severityBreakdown.entries} centerText={severityBreakdown.total} ariaLabel={tr("overview.alertsBySeverity")} size="sm" />
              <DonutLegend entries={severityBreakdown.entries} size="sm" />
            </div>
            <div className="ov2-status-row">
              {Object.entries(statusBreakdown).map(([key, count]) => (
                <span key={key} className="ov2-status-chip">
                  <b>{count}</b> {ALERT_STATUS_LABEL[key] || key}
                </span>
              ))}
            </div>
            <p className="filter-chip-group-label ov2-top-alerts-label">{tr("overview.topAlerts")}</p>
            <TopAlertsList alerts={topAlerts} onSelectDevice={(name) => onNavigate?.("device-overview", name)} />
          </>
        )}
      </div>
    ),
    recommendations: (
      <div
        className="card"
        ref={(n) => main.registerNode("recommendations", n)}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => main.onDragEnter("recommendations")}
        onDrop={(e) => {
          e.preventDefault();
          main.onDrop();
        }}
      >
        <div className="card-head">
          <h2>{tr("overview.topRecommendations")}</h2>
          <div className="ov2-head-right">
            <span className="card-note">{tr("overview.topRecommendationsNote")}</span>
            <TileControls cardKey="recommendations" sizeIndex={main.sizes.recommendations ?? 5} onResize={main.resize} dragHandleProps={main.dragHandleProps("recommendations")} />
          </div>
        </div>
        {exposureError ? <p className="error-note">{exposureError.message}</p> : <RecommendationsList recommendations={topRecommendations} />}
      </div>
    ),
  };

  return (
    <>
      <TopStrip
        score={score}
        measuredAt={data.exposureScore?.time ? new Date(data.exposureScore.time).toLocaleTimeString(currentLocale(), { hour: "2-digit", minute: "2-digit" }) : null}
        exposureError={exposureError}
        defenderError={defenderError}
        intuneError={intuneError}
        totalMachines={data.defenderSummary?.totalMachines}
        totalDevices={data.intuneSummary?.totalDevices}
        complianceRate={data.intuneSummary?.complianceRate}
        nonCompliantCount={nonCompliantCount}
        nonOnboardedCount={nonOnboardedCount}
        activeAlertsCount={defenderError ? null : activeAlertsCount}
      />

      <div className="ov2-layout">
        <div className="ov2-main">
          {/* `<div>`, pas `<p>` (revue de bugs du 2026-09-02) — `HistoryRangePicker` rend son
              propre `<div>` : un `<div>` descendant d'un `<p>` est du HTML invalide, que le
              navigateur "corrige" en fermant le `<p>` prématurément avant ce `<div>` (warning
              React `validateDOMNesting` déjà documenté ailleurs dans ce fichier depuis des
              semaines) — le bouton "Réinitialiser" qui suivait se retrouvait alors, dans le
              DOM réel, hors de cet élément plutôt qu'à l'intérieur comme l'écrit ce JSX.
              `.section-title` ne dépend d'aucun style par défaut propre à `<p>` (marge/flex
              déjà posés explicitement dans styles.css), ce changement de balise est purement
              structurel. (Le sélecteur de plage a depuis été retiré, le 2026-10-21 — le `<div>`
              reste, aucune raison de revenir à `<p>`.) */}
          <div className="section-title">
            {tr("overview.trendsTitle")}
            <button type="button" className="ov2-reset-btn" onClick={main.resetLayout}>
              {tr("common.reset")}
            </button>
          </div>
          <div className="ov2-main-grid">
            {main.order.map((key) => {
              const { c, r } = SIZE_STEPS[main.sizes[key] ?? 1];
              return (
                <div
                  key={key}
                  className={`ov2-main-cell${main.draggingKey === key ? " dragging" : ""}`}
                  style={{ gridColumn: `span ${c}`, gridRow: `span ${r}` }}
                >
                  {mainBody[key]}
                </div>
              );
            })}
          </div>
        </div>

        <aside className="ov2-rail">
          <p className="ov2-rail-title">
            {tr("overview.signals")}
            <button type="button" className="ov2-reset-btn" onClick={rail.resetLayout}>
              {tr("common.reset")}
            </button>
          </p>
          <div className="signal-grid">
            {rail.order.map((key) => {
              const tileProps = {
                tileRef: (n) => rail.registerNode(key, n),
                dragHandleProps: rail.dragHandleProps(key),
                onDragEnter: () => rail.onDragEnter(key),
                onDrop: rail.onDrop,
              };
              const wrapperClass = rail.draggingKey === key ? " dragging" : "";

              if (key === "secure-score") {
                return (
                  <div key={key} className={`ov2-rail-cell${wrapperClass}`}>
                    <SignalCard
                      icon={<IconGauge />}
                      label={<SecureScoreHeaderLabel pct={signals.secureScorePct} delta={secureScoreDelta} />}
                      onClick={() => onNavigate?.("secure-score")}
                      tone={signals.secureScorePct != null ? secureScoreLevel(signals.secureScorePct).level : undefined}
                      {...tileProps}
                    >
                      {signals.loading ? (
                        <p className="signal-loading">{tr("common.loading")}</p>
                      ) : signals.errors.secureScore ? (
                        <p className="signal-error">{signals.errors.secureScore}</p>
                      ) : (
                        <div className="secure-score-mini-grid">
                          {SECURE_SCORE_MINI_CATEGORIES.map((catKey) => {
                            const cat = signals.secureScoreCategories.find((c) => c.category === catKey);
                            const pct = cat?.percentage ?? null;
                            return (
                              <div className="secure-score-mini-cell" key={catKey}>
                                <span
                                  className="secure-score-mini-value"
                                  style={{ color: pct != null ? secureScoreLevel(pct).color : undefined }}
                                >
                                  {pct != null ? `${pct}%` : "—"}
                                </span>
                                <span className="secure-score-mini-label">{SECURE_SCORE_CATEGORY_LABEL[catKey]}</span>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </SignalCard>
                  </div>
                );
              }

              if (key === "criticality") {
                return (
                  <div key={key} className={`ov2-rail-cell${wrapperClass}`}>
                    <SignalCard
                      icon={<IconTarget />}
                      label={tr("overview.byCriticality")}
                      onClick={() => onNavigate?.("secure-score")}
                      note={criticalityTotal > 0 ? tr("overview.criticalityNote", { count: criticalityTotal }) : tr("overview.criticalityNone")}
                      {...tileProps}
                    >
                      {defenderError ? (
                        <p className="signal-error">{defenderError.message}</p>
                      ) : (
                        <div className="signal-crit-bar">
                          {criticalityCounts.map((c) => {
                            const isZero = criticalityTotal > 0 && c.count === 0;
                            const isDimmed = hoveredCriticality != null && hoveredCriticality !== c.level;
                            return (
                              <span
                                key={c.level}
                                className={`signal-crit-seg${hoveredCriticality === c.level ? " active" : ""}`}
                                style={{
                                  flexGrow: criticalityTotal > 0 ? c.count : 1,
                                  background: EXPOSURE_LEVEL_COLORS[c.level],
                                  opacity: isZero ? 0.12 : isDimmed ? 0.35 : 1,
                                }}
                                title={`${EXPOSURE_LEVEL_LABEL[c.level]} : ${c.count}`}
                                onMouseEnter={() => setHoveredCriticality(c.level)}
                                onMouseLeave={() => setHoveredCriticality(null)}
                              />
                            );
                          })}
                        </div>
                      )}
                      <div className="signal-crit-legend">
                        {criticalityCounts.map((c) => (
                          <div
                            key={c.level}
                            className={`signal-crit-legend-row${hoveredCriticality === c.level ? " active" : ""}`}
                            onMouseEnter={() => setHoveredCriticality(c.level)}
                            onMouseLeave={() => setHoveredCriticality(null)}
                          >
                            <i style={{ background: EXPOSURE_LEVEL_COLORS[c.level] }} aria-hidden="true" />
                            <span className="signal-crit-legend-label">{EXPOSURE_LEVEL_LABEL[c.level]}</span>
                            <span className="signal-crit-legend-count">{c.count}</span>
                          </div>
                        ))}
                      </div>
                    </SignalCard>
                  </div>
                );
              }

              if (key === "cve-watch") {
                return (
                  <div key={key} className={`ov2-rail-cell${wrapperClass}`}>
                    <SignalCard
                      icon={<IconBookmark />}
                      label={tr("overview.cveWatch")}
                      onClick={() => onNavigate?.("cve-watch")}
                      note={
                        signals.watchedCves.length === 0
                          ? tr("overview.noWatchedCve")
                          : tr("overview.watchedCves", { count: signals.watchedCves.length })
                      }
                      tone={watchedExposedCount > 0 ? "high" : undefined}
                      {...tileProps}
                    >
                      {signals.loading ? (
                        <p className="signal-loading">{tr("common.loading")}</p>
                      ) : signals.errors.watchedCves ? (
                        <p className="signal-error">{signals.errors.watchedCves}</p>
                      ) : signals.watchedCves.length === 0 ? (
                        <p className="signal-note-inline">{tr("overview.pinCveHint")}</p>
                      ) : (
                        <>
                          <div className="signal-body-row">
                            <div className="signal-value">{watchedExposedCount}</div>
                            <div className="signal-value-caption">
                              {tr("overview.exposedOnFleet", { count: watchedExposedCount })}
                              {topWatchedCve ? <span className="signal-mono"> · {topWatchedCve.cve_code}</span> : null}
                            </div>
                          </div>
                          {signals.watchedCves.length > 1 && (
                            <>
                              <button
                                type="button"
                                className="ov2-expand-btn"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setCveExpanded((v) => !v);
                                }}
                              >
                                {cveExpanded ? tr("common.seeLess") : tr("overview.seeAllCves")}
                              </button>
                              {cveExpanded && (
                                <ul className="ov2-mini-list" onClick={(e) => e.stopPropagation()}>
                                  {signals.watchedCves.slice(0, 8).map((e) => (
                                    <li key={e.cve_code}>
                                      <span className="ov2-mono">{e.cve_code}</span>
                                      <span className={(e.result?.affected_count || 0) > 0 ? "ov2-tag-high" : "ov2-tag-ok"}>
                                        {e.error ? tr("common.error") : tr("common.devices", { count: e.result?.affected_count ?? 0 })}
                                      </span>
                                    </li>
                                  ))}
                                </ul>
                              )}
                            </>
                          )}
                        </>
                      )}
                    </SignalCard>
                  </div>
                );
              }

              if (key === "anssi") {
                return (
                  <div key={key} className={`ov2-rail-cell${wrapperClass}`}>
                    <SignalCard
                      icon={<IconShield />}
                      label="ANSSI / CERT-FR"
                      onClick={() => onNavigate?.("vulnerabilities")}
                      note={tr("overview.anssiNote")}
                      tone={signals.anssiMatches.length > 0 ? "med" : undefined}
                      {...tileProps}
                    >
                      {signals.loading ? (
                        <p className="signal-loading">{tr("common.loading")}</p>
                      ) : signals.errors.anssiMatches ? (
                        <p className="signal-error">{signals.errors.anssiMatches}</p>
                      ) : signals.anssiMatches.length === 0 ? (
                        <p className="signal-note-inline">{tr("overview.noAnssiMatch")}</p>
                      ) : (
                        <>
                          <div className="signal-body-row">
                            <div className="signal-value">{signals.anssiMatches.length}</div>
                            <div className="signal-value-caption">
                              {tr("overview.anssiMatches", { count: signals.anssiMatches.length })}
                              {topAnssiMatch ? <span className="signal-mono"> · {topAnssiMatch.certfr_ref}</span> : null}
                            </div>
                          </div>
                          {signals.anssiMatches.length > 1 && (
                            <>
                              <button
                                type="button"
                                className="ov2-expand-btn"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setAnssiExpanded((v) => !v);
                                }}
                              >
                                {anssiExpanded ? tr("common.seeLess") : tr("overview.seeAllAdvisories")}
                              </button>
                              {anssiExpanded && (
                                <ul className="ov2-mini-list" onClick={(e) => e.stopPropagation()}>
                                  {signals.anssiMatches.slice(0, 8).map((m, i) => (
                                    <li key={m.certfr_ref ?? i}>
                                      <span className="ov2-mono">{m.certfr_ref}</span>
                                      <span className="ov2-tag-med">{m.matched_software || m.title || tr("overview.fleetSoftware")}</span>
                                    </li>
                                  ))}
                                </ul>
                              )}
                            </>
                          )}
                        </>
                      )}
                    </SignalCard>
                  </div>
                );
              }

              // "compliance-state" — pas un SignalCard (pas de navigation associée, motif
              // déjà distinct dans l'original : `.ov2-compliance-card`), même mécanisme de
              // drag/drop posé directement sur son enveloppe.
              return (
                <div
                  key={key}
                  className={`ov2-rail-cell${wrapperClass}`}
                  ref={tileProps.tileRef}
                  onDragOver={(e) => e.preventDefault()}
                  onDragEnter={tileProps.onDragEnter}
                  onDrop={(e) => {
                    e.preventDefault();
                    tileProps.onDrop();
                  }}
                >
                  <div className="ov2-compliance-card">
                    <div className="ov2-compliance-head">
                      <h2>{tr("overview.fleetCompliance")}</h2>
                      <span className="ov2-grip" title={tr("common.dragToReorder")} {...tileProps.dragHandleProps}>
                        <IconGrip />
                      </span>
                    </div>
                    {intuneError ? (
                      <p className="error-note">{intuneError.message}</p>
                    ) : (
                      <ComplianceMini byState={data.intuneSummary?.byComplianceState} complianceRate={data.intuneSummary?.complianceRate} />
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </aside>
      </div>
    </>
  );
}
