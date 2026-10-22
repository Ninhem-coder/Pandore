import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  useVanitasAgentEol,
  useVanitasAgents,
  useVanitasComplianceSummary,
  useVanitasCommands,
  useVanitasGroups,
  useVanitasHistory,
  useVanitasPatchStatus,
  useVanitasRecentAlerts,
  useVanitasSuspiciousEvents,
  useVanitasSuspiciousEventsSummary,
  useVanitasTopVulnerabilities,
} from "../hooks/useDashboardData.js";
import { computeVanitasTrend } from "../selectors.js";
import {
  CERT_WARNING_DAYS,
  COMMAND_LABELS,
  STALE_HOURS,
  certTone,
  daysUntil,
  fmtRelative,
  isOnline,
  severityLabelFr,
  severityTone,
  toneVar,
} from "./vanitasShared.jsx";
import { currentLocale, localizedTable, tr } from "../i18n/core.js";

const ALERTS_MAX = 6;

// new_eol_finding: revue EOL comparative (2026-09-10) — l'EOL branché sur l'infra d'alertes diff
// existante. agent_update_available: purement informatif (cadrage explicite de Nicolas).
const ALERT_TYPE_LABEL = localizedTable("vo.alert", [
  "stale",
  "new_critical_vuln",
  "new_compliance_failure",
  "cert_expiring",
  "new_eol_finding",
  "agent_update_available",
]);

// Même vocabulaire que `SIGNAL_TYPE_LABEL_FR` (VanitasSuspiciousActivityTab.jsx) — dupliqué en
// petit ici plutôt que d'importer une page dans une autre pour 4 libellés.
const SUSPICIOUS_SIGNAL_LABEL = localizedTable("vo.signal", ["process", "event_log", "network", "usb"]);

const WATCHLIST_MAX = 8;
const SIGNALS_MAX = 8;
const FEED_MAX = 9;
const RECENT_DAYS = 7;
const CHART_W = 560;
const CHART_H = 220;
const DAY_MS = 86_400_000;

/** Tracé lissé (Catmull-Rom → bézier cubique) — un simple polyligne droit entre 7 points donne
 * un aspect "graphique de tableur compressé" (retour de Nicolas, "on dirait un vieux jpeg") ;
 * la courbe lissée se lit mieux sur une série aussi courte. */
function buildActivityChart(values, width, height) {
  const max = Math.max(1, ...values);
  const stepX = values.length > 1 ? width / (values.length - 1) : width;
  const points = values.map((v, i) => [i * stepX, height - 10 - (v / max) * (height - 30)]);

  let line = `M${points[0][0].toFixed(1)},${points[0][1].toFixed(1)}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[i - 1] || points[i];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[i + 2] || p2;
    const c1x = p1[0] + (p2[0] - p0[0]) / 6;
    const c1y = p1[1] + (p2[1] - p0[1]) / 6;
    const c2x = p2[0] - (p3[0] - p1[0]) / 6;
    const c2y = p2[1] - (p3[1] - p1[1]) / 6;
    line += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  const area = `${line} L${width.toFixed(1)},${height} L0,${height} Z`;
  return { line, area, points };
}

/**
 * "Vanitas" > Vue d'ensemble — refonte HUD (2026-09-06), maquette validée par Nicolas ("ca me
 * va met ca en place"). Remplace l'ancien bandeau KPI seul (`.strip`/`SummaryCard`, motif
 * générique du reste du dashboard) par l'identité HUD déjà établie sur "Postes" (jalon 8,
 * `.vanitas-hud`) — explicitement demandé "en te basant sur les informations qu'on prend sur
 * les postes" : mêmes dimensions (certificat, statut en ligne, dernière commande), pas de
 * nouvelle donnée inventée pour le bandeau/la liste de surveillance/le flux d'activité.
 *
 * Seule vraie nouveauté de données : "Top 5 vulnérabilités" — agrégat fleet-wide (CVE la plus
 * répandue par nombre d'agents distincts touchés), servi par un nouvel endpoint dédié côté
 * serveur Vanitas (`GET /vulnerabilities/top`, voir `endpoint-agent/server/app/routes/
 * vulnerabilities.py`) plutôt que calculé ici en récupérant le détail CVE de chaque agent un
 * par un (chaque agent peut avoir des centaines de CVE, voir VanitasDeviceDetail.jsx — agréger
 * côté client aurait demandé de tout retélécharger pour rien).
 *
 * Trois listes fleet-wide déjà chargées ailleurs (`useVanitasAgents`/`useVanitasCommands`,
 * réutilisées telles quelles) suffisent pour tout le reste — aucune nouvelle route pour le
 * bandeau KPI/la liste de surveillance/le flux/la répartition/les expirations/les statuts de
 * commande, tout est dérivé côté client en `useMemo`.
 *
 * Reskin (2026-09-09, maquette "Vanitas Overwatch" approuvée par Nicolas) : cartes arrondies +
 * halo doux (`.vanitas-ov`, scopé à CETTE page — "Postes"/"Commandes"/"Conformité" gardent le
 * cadre à coins bracket `.vanitas-hud-frame`, non touché) plutôt qu'un reskin global de
 * "Vanitas". Deux ajouts, tous deux dérivés de données déjà chargées, AUCUN nouvel appel réseau :
 * hero "Posture" (rail, synthèse des signaux déjà calculés — silencieux/certificat/EOL — dans
 * un vrai texte, pas une valeur inventée) et graphique "Activité" (main, volume de commandes
 * RÉEL par jour sur `RECENT_DAYS`, agrégé côté client depuis `commands.state.data` déjà chargé
 * pour "Activité récente" juste en dessous).
 */
/** Mini-courbe SVG normalisée (jalon "tendances Vanitas", 2026-09-17) — monochrome, hérite de la
 * couleur du conteneur via `currentColor`, donc thème-safe sans lib de graphe. Une série plate
 * (min == max) est tracée en ligne médiane plutôt que de diviser par zéro. */
function Sparkline({ series, width = 132, height = 34 }) {
  const pad = 3;
  if (!Array.isArray(series) || series.length < 2) return null;
  const min = Math.min(...series);
  const max = Math.max(...series);
  const span = max - min || 1;
  const stepX = (width - pad * 2) / (series.length - 1);
  const points = series
    .map((v, i) => {
      const x = pad + i * stepX;
      const y = pad + (height - pad * 2) * (1 - (v - min) / span);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const lastX = pad + (series.length - 1) * stepX;
  const lastY = pad + (height - pad * 2) * (1 - (series[series.length - 1] - min) / span);
  return (
    <svg className="vanitas-trend-spark" viewBox={`0 0 ${width} ${height}`} width={width} height={height} aria-hidden="true">
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={lastX.toFixed(1)} cy={lastY.toFixed(1)} r="2.4" fill="currentColor" />
    </svg>
  );
}

/** Une carte de tendance : libellé, valeur courante, delta sur 7 j (coloré selon que la direction
 * est FAVORABLE ou non — hausse de conformité = bon/vert, hausse d'événements suspects = mauvais/
 * rouge), et la mini-courbe. `favorable` : "up" (monter est bon) ou "down" (baisser est bon). */
function TrendSparkCard({ label, metric, unit = "", favorable, tone }) {
  const { current, delta7, series } = metric || {};
  if (current == null) return null;
  let deltaClass = "flat";
  if (typeof delta7 === "number" && delta7 !== 0) {
    const good = favorable === "up" ? delta7 > 0 : delta7 < 0;
    deltaClass = good ? "good" : "bad";
  }
  const deltaLabel =
    typeof delta7 === "number" && delta7 !== 0
      ? tr("vo.deltaWeek", { arrow: delta7 > 0 ? "▲" : "▼", value: Math.abs(delta7), unit: unit ?? "" })
      : tr("vo.stableWeek");
  return (
    <div className="vanitas-trend-card" style={tone ? { "--tone": tone } : undefined}>
      <div className="vanitas-trend-card-head">
        <span className="vanitas-trend-card-label">{label}</span>
        <span className={`vanitas-trend-delta ${deltaClass}`}>{deltaLabel}</span>
      </div>
      <div className="vanitas-trend-card-value">
        {current}
        {unit}
      </div>
      <Sparkline series={series} />
    </div>
  );
}

export default function VanitasOverviewTab({ onNavigateVanitas }) {
  const agents = useVanitasAgents();
  const commands = useVanitasCommands();
  const topVulns = useVanitasTopVulnerabilities(5);
  const alerts = useVanitasRecentAlerts(ALERTS_MAX);
  const eol = useVanitasAgentEol();
  const groups = useVanitasGroups();
  // Jalon "détection d'activités suspectes" (2026-09-14) — jusqu'ici absent de la Vue
  // d'ensemble alors que c'est la nouveauté la plus récente du produit (retour de Nicolas,
  // "mettre à jour les infos avec les nouvelles fonctionnalités"). Compte des événements au
  // statut "new" (non traités), même notion que la tuile "Non traités" de l'onglet transverse.
  const suspiciousSummary = useVanitasSuspiciousEventsSummary();
  // Liste (pas seulement le compteur) des événements non traités — matière première de
  // "Signaux à traiter" ci-dessous. Filtre côté serveur (`status: "new"`), pas de tri/filtre
  // supplémentaire à charge du client.
  const suspiciousNew = useVanitasSuspiciousEvents({ status: "new" });
  // Refonte "Vue d'ensemble" (2026-09-14, retour de Nicolas sur la maquette validée) — taux de
  // conformité fleet-wide, seule tuile KPI qui manquait encore d'un signal de sécurité déjà
  // affiché ailleurs (Conformité a sa propre page depuis longtemps, jamais résumé ici jusque-là).
  // Calculé depuis `GET /compliance/summary` (agrégat PAR RÈGLE déjà existant, un seul appel
  // léger) plutôt que de reproduire ici la boucle par-poste-par-règle de VanitasComplianceTab.jsx
  // (coûteuse, un aller-retour par agent) — le taux obtenu est donc "part des évaluations
  // conformes, tous postes et toutes règles confondus", pas "part des postes 100% conformes" :
  // une lecture légèrement différente mais honnête et représentative, pour le prix d'un seul appel.
  const complianceSummary = useVanitasComplianceSummary();
  // Tendances (jalon 2026-09-17) — historique quotidien du parc, pour voir l'évolution et pas
  // seulement l'instantané des tuiles KPI ci-dessus.
  const history = useVanitasHistory();
  // Posture de patch (refonte overview 2026-09-17) — répartition à jour / en attente / hors
  // politique, fleet-wide (`GET /patch-status`), pour la carte-signal "Posture de patch" du rail.
  const patch = useVanitasPatchStatus();

  // Interactivité (2026-09-11, "les blocs sont juste là mais ne renvoie sur aucune page") —
  // navigue vers "Postes" en pré-sélectionnant directement la fiche du poste (par id, jamais
  // par hostname : l'id est déjà disponible sur toutes les sources de lignes de cette page,
  // pas besoin d'une résolution supplémentaire côté page cible).
  function gotoAgent(agentId) {
    onNavigateVanitas?.("vanitas-devices", { selectAgentId: agentId });
  }

  // Le graphique "Activité" doit épouser la largeur RÉELLE de la carte (pas une largeur de
  // viewBox arbitraire étirée non-uniformément via `preserveAspectRatio="none"`, qui donnait
  // un tracé flou/"jpeg" — retour de Nicolas). Mesure SYNCHRONE (`useLayoutEffect` +
  // `getBoundingClientRect`, pas `ResizeObserver` seul) : la 1ʳᵉ observation d'un
  // `ResizeObserver` n'est pas garantie de se déclencher avant la peinture sur toutes les
  // implémentations, ce qui aurait laissé la valeur de repli (`CHART_W`) — et donc la
  // distorsion — sur le tout premier rendu. `ResizeObserver` reste branché en complément pour
  // les redimensionnements ultérieurs (fenêtre, repli de la sidebar).
  const chartWrapRef = useRef(null);
  const [chartWidth, setChartWidth] = useState(CHART_W);
  useLayoutEffect(() => {
    const el = chartWrapRef.current;
    if (el) setChartWidth(el.getBoundingClientRect().width);
  }, []);
  useEffect(() => {
    const el = chartWrapRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect?.width;
      if (w) setChartWidth(w);
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    agents.ensureLoaded();
    commands.ensureLoaded();
    topVulns.ensureLoaded();
    alerts.ensureLoaded();
    groups.ensureLoaded();
    suspiciousSummary.ensureLoaded();
    complianceSummary.ensureLoaded();
    history.ensureLoaded();
    patch.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 30 derniers points, calculés une fois par changement d'historique (voir computeVanitasTrend).
  const trend = useMemo(() => computeVanitasTrend(history.state.data ?? [], 30), [history.state.data]);
  // Au moins 2 points sur une métrique = une vraie courbe à montrer ; sinon la section reste
  // masquée (un seul jour d'historique ne raconte aucune tendance).
  const hasTrend = useMemo(
    () => Object.values(trend).some((m) => (m.series?.length ?? 0) >= 2),
    [trend]
  );

  // Bloc de synthèse (2026-09-08, demande de Nicolas — "un bloc dans la vue d'ensemble pour
  // voir les informations aussi") : tuiles "Postes silencieux (alerte)"/"Logiciels EOL" +
  // liste "Alertes récentes", voir plus bas dans le JSX.
  useEffect(() => {
    for (const agent of agents.state.data ?? []) {
      eol.ensureLoaded(agent.id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents.state.data]);

  // Seuil d'ALERTE (12h par défaut), volontairement DISTINCT du seuil "watchlist" de 7 jours
  // (STALE_HOURS, tuile "Silencieux" déjà existante ci-dessous) — voir vanitasShared.jsx et
  // _vanitas_agent_health_loop (api_server.py). Vient du backend (`stale_threshold_hours`)
  // plutôt que d'un seuil dupliqué en dur ici, pour ne jamais diverger silencieusement.
  const alertStaleCount = useMemo(() => {
    const threshold = alerts.state.staleThresholdHours;
    if (threshold === null || threshold === undefined) return null;
    return (agents.state.data ?? []).filter((a) => {
      if (!a.last_seen) return true;
      return (Date.now() - new Date(a.last_seen).getTime()) / 3_600_000 > threshold;
    }).length;
  }, [agents.state.data, alerts.state.staleThresholdHours]);

  const eolCount = useMemo(() => {
    let total = 0;
    for (const agent of agents.state.data ?? []) {
      total += eol.state[agent.id]?.data?.length ?? 0;
    }
    return total;
  }, [agents.state.data, eol.state]);

  const counts = useMemo(() => {
    const list = agents.state.data ?? [];
    const total = list.length;
    const online = list.filter(isOnline).length;
    const cert = list.filter((a) => {
      const d = daysUntil(a.cert_not_after);
      return d !== null && d < CERT_WARNING_DAYS;
    }).length;
    const stale = list.filter((a) => {
      if (!a.last_seen) return true;
      return (Date.now() - new Date(a.last_seen).getTime()) / 3_600_000 > STALE_HOURS;
    }).length;
    return { total, online, cert, stale };
  }, [agents.state.data]);

  const recentCommands = useMemo(() => {
    return (commands.state.data ?? []).filter(
      (c) => (Date.now() - new Date(c.created_at).getTime()) / 86_400_000 <= RECENT_DAYS
    );
  }, [commands.state.data]);


  const watchlist = useMemo(() => {
    const rows = [];
    for (const a of agents.state.data ?? []) {
      const days = daysUntil(a.cert_not_after);
      const hoursSince = a.last_seen ? (Date.now() - new Date(a.last_seen).getTime()) / 3_600_000 : Infinity;
      const stale = hoursSince > STALE_HOURS;
      const certWarn = days !== null && days < CERT_WARNING_DAYS;
      if (!stale && !certWarn) continue;

      const tone = stale || certTone(days) === "high" ? "high" : "warn";
      const parts = [];
      if (stale) parts.push(tr("vo.silentFor", { days: Math.round(hoursSince / 24) }));
      if (certWarn) parts.push(days < 0 ? tr("vo.certExpired") : tr("vo.certRenew", { days: CERT_WARNING_DAYS }));

      rows.push({
        id: a.id,
        hostname: a.hostname,
        online: isOnline(a),
        tone,
        stale,
        reason: parts.join(" · "),
        metric: tr("vo.metricDays", { n: stale ? Math.round(hoursSince / 24) : Math.max(0, Math.round(days)) }),
      });
    }
    return rows.sort((x, y) => (x.tone === y.tone ? 0 : x.tone === "high" ? -1 : 1)).slice(0, WATCHLIST_MAX);
  }, [agents.state.data]);


  // "Logiciels EOL — détail" (2026-09-11) — même agrégation que VanitasEolTab.jsx::allRows
  // (le plus urgent en premier), réduite aux quelques premières lignes pour cette carte
  // compacte ; aucun nouvel appel réseau, `eol.state` est déjà chargé par l'effet ci-dessus.
  const eolFindings = useMemo(() => {
    const rows = [];
    for (const agent of agents.state.data ?? []) {
      const entry = eol.state[agent.id];
      if (!entry || entry.loading) continue;
      for (const finding of entry.data ?? []) {
        rows.push({ ...finding, agentId: agent.id, hostname: agent.hostname });
      }
    }
    rows.sort((a, b) => {
      if (a.is_eol !== b.is_eol) return a.is_eol ? -1 : 1;
      return (a.days_until_eol ?? 0) - (b.days_until_eol ?? 0);
    });
    return rows.slice(0, 4);
  }, [agents.state.data, eol.state]);

  const complianceRate = useMemo(() => {
    const rows = complianceSummary.state.data ?? [];
    if (!rows.length) return null;
    let ok = 0;
    let total = 0;
    for (const r of rows) {
      ok += r.compliant_count ?? 0;
      total += (r.compliant_count ?? 0) + (r.non_compliant_count ?? 0) + (r.error_count ?? 0);
    }
    return total ? Math.round((ok / total) * 100) : null;
  }, [complianceSummary.state.data]);

  // "Signaux à traiter" (refonte 2026-09-14, maquette validée par Nicolas) — remplace les 3
  // cartes séparées "Postes à surveiller" / "Top vulnérabilités" / "Logiciels EOL" (comparées
  // côte à côte à l'œil) par UNE liste triée par urgence réelle, tous types de signaux
  // confondus, activités suspectes incluses (absentes de ces 3 cartes jusqu'ici). Aucune
  // nouvelle donnée : mêmes `watchlist`/`topVulns`/`eolFindings` déjà calculés plus haut, plus
  // la liste (pas seulement le compteur) des activités suspectes non traitées.
  const TONE_RANK = { high: 0, warn: 1, good: 2 };
  const signals = useMemo(() => {
    const rows = [];
    for (const e of suspiciousNew.state.data ?? []) {
      const tone = e.severity === "high" ? "high" : e.severity === "low" ? "good" : "warn";
      rows.push({
        key: `sus-${e.id}`,
        category: SUSPICIOUS_SIGNAL_LABEL[e.signal_type] ?? e.signal_type,
        host: e.hostname,
        detail: e.summary,
        tone,
        sevLabel: tr(tone === "high" ? "vo.sev.high" : tone === "warn" ? "vo.sev.med" : "vo.sev.low"),
        time: e.occurred_at,
        onClick: () => onNavigateVanitas?.("vanitas-suspicious-activity"),
      });
    }
    for (const w of watchlist) {
      rows.push({
        key: `watch-${w.id}`,
        category: tr(w.stale ? "vo.cat.silent" : "vo.cat.certificate"),
        host: w.hostname,
        detail: w.reason,
        tone: w.tone === "high" ? "high" : "warn",
        sevLabel: tr(w.tone === "high" ? "vo.sev.high" : "vo.sev.med"),
        time: null,
        metric: w.metric,
        onClick: () => gotoAgent(w.id),
      });
    }
    for (const v of topVulns.state.data ?? []) {
      const vTone = severityTone(v.severity);
      const tone = vTone === "high" ? "high" : vTone === "low" ? "good" : "warn";
      rows.push({
        key: `cve-${v.cve_id}`,
        category: "CVE",
        host: v.product_name,
        detail: tr("vo.cveExposed", { cve: v.cve_id, count: v.device_count }),
        tone,
        sevLabel: severityLabelFr(v.severity),
        time: null,
        onClick: () => onNavigateVanitas?.("vanitas-vulnerabilities", { cveId: v.cve_id }),
      });
    }
    for (const f of eolFindings) {
      rows.push({
        key: `eol-${f.agentId}-${f.type}-${f.name}`,
        category: "EOL",
        host: f.hostname,
        detail: `${f.name} — ${f.message}`,
        tone: f.is_eol ? "high" : "warn",
        sevLabel: tr(f.is_eol ? "vo.sev.high" : "vo.sev.med"),
        time: null,
        onClick: () => onNavigateVanitas?.("vanitas-eol", { query: f.hostname }),
      });
    }
    rows.sort((a, b) => (TONE_RANK[a.tone] ?? 3) - (TONE_RANK[b.tone] ?? 3));
    return rows.slice(0, SIGNALS_MAX);
  }, [suspiciousNew.state.data, watchlist, topVulns.state.data, eolFindings]);

  // "Groupes" (rail, 2026-09-11) — état vide honnête tant qu'aucun groupe n'est créé, jamais
  // masqué (même philosophie que "Alertes récentes" juste en dessous).
  const groupRows = (groups.state.data ?? []).slice(0, 5);

  // Postes sous isolement réseau (jalon confinement) — état courant `network_isolated`, exposé
  // sur `AgentSummary`. Pilier du hero de posture + tuile-signal dédiée.
  const isolatedCount = useMemo(
    () => (agents.state.data ?? []).filter((a) => a.network_isolated).length,
    [agents.state.data]
  );

  // Événements suspects ÉLEVÉS ET non traités — croise sévérité (high) et statut (new, déjà
  // filtré côté serveur par le hook). Distinct du total "high" (`by_severity.high`) qui inclut
  // les événements déjà triés : c'est le non-traité qui appelle une action.
  const highUntreated = useMemo(
    () => (suspiciousNew.state.data ?? []).filter((e) => e.severity === "high").length,
    [suspiciousNew.state.data]
  );

  // Répartition de la sévérité des activités suspectes (carte "Par criticité" du rail) — depuis
  // le résumé fleet-wide déjà chargé (`by_severity`), objet creux (clé absente = 0).
  const sevCounts = useMemo(() => {
    const s = suspiciousSummary.state.data?.by_severity ?? {};
    return { high: s.high ?? 0, med: s.med ?? 0, low: s.low ?? 0 };
  }, [suspiciousSummary.state.data]);

  // Posture de patch (carte donut du rail) — comptage par statut calculé côté serveur
  // (`_display_status`) : "ok" à jour, "off" hors politique, tout le reste = cycle en cours.
  const patchCounts = useMemo(() => {
    const list = patch.state.data ?? [];
    const ok = list.filter((e) => e.status === "ok").length;
    const off = list.filter((e) => e.status === "off").length;
    return { total: list.length, ok, off, pending: list.length - ok - off };
  }, [patch.state.data]);

  // Score de posture (0-100) — heuristique INDICATIVE, transparente : on part de 100 et on
  // retranche par famille de signal (chaque retrait est aussi listé en toutes lettres sous le
  // score, donc aucun chiffre "magique" opaque). Bornée [0,100].
  const posture = useMemo(() => {
    let score = 100;
    score -= Math.min(36, highUntreated * 6);
    score -= isolatedCount * 8;
    score -= counts.stale * 5;
    score -= counts.cert * 3;
    score -= Math.min(15, eolCount * 2);
    if (complianceRate !== null) score -= Math.round((100 - complianceRate) * 0.25);
    score = Math.max(0, Math.min(100, Math.round(score)));

    const issues = [];
    if (highUntreated > 0) issues.push(tr("vo.issue.highUntreated", { count: highUntreated }));
    if (isolatedCount > 0) issues.push(tr("vo.issue.isolated", { count: isolatedCount }));
    if (counts.stale > 0) issues.push(tr("vo.issue.stale", { count: counts.stale }));
    if (counts.cert > 0) issues.push(tr("vo.issue.cert", { count: counts.cert, days: CERT_WARNING_DAYS }));
    if (eolCount > 0) issues.push(tr("vo.issue.eol", { count: eolCount }));

    const tone = score >= 85 ? "good" : score >= 60 ? "warn" : "high";
    const word = tr(`vo.word.${tone}`);
    const sub =
      issues.length === 0 ? tr("vo.noSignal") : tr("vo.signalsSummary", { count: issues.length, list: issues.join(", ") });
    return { score, tone, word, sub };
  }, [highUntreated, isolatedCount, counts, eolCount, complianceRate]);

  // Graphique "Activité" (main) — commandes RÉELLES par jour sur RECENT_DAYS, agrégées côté
  // client depuis `commands.state.data` déjà chargé (aucun nouvel appel réseau).
  const activitySeries = useMemo(() => {
    const days = RECENT_DAYS;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const buckets = Array.from({ length: days }, (_, i) => {
      const d = new Date(today.getTime() - (days - 1 - i) * DAY_MS);
      return { date: d, count: 0 };
    });
    for (const c of commands.state.data ?? []) {
      const t = new Date(c.created_at);
      t.setHours(0, 0, 0, 0);
      const idx = buckets.findIndex((b) => b.date.getTime() === t.getTime());
      if (idx >= 0) buckets[idx].count++;
    }
    return buckets;
  }, [commands.state.data]);

  const activityChart = useMemo(
    () => buildActivityChart(activitySeries.map((b) => b.count), chartWidth, CHART_H),
    [activitySeries, chartWidth]
  );
  const activityTotal = activitySeries.reduce((sum, b) => sum + b.count, 0);


  const loading = agents.state.status === "loading" || commands.state.status === "loading";
  const error = agents.state.error || commands.state.error || topVulns.state.error;

  if (loading) {
    return (
      <div className="vanitas-hud vanitas-ov">
        <p className="vanitas-hud-empty-note">{tr("vo.loading")}</p>
      </div>
    );
  }

  return (
    <div className="vanitas-hud vanitas-ov">
      {error && <p className="vanitas-hud-error">{error}</p>}

      {/* Bande de posture (refonte 2026-09-17, maquette validée par Nicolas) — verdict glanceable
          en tête : un anneau de score + les signaux qui pèsent. Principe SOC : l'overview doit
          dire en 2 s si le parc va bien, avant le détail. Score = heuristique indicative dont les
          facteurs sont listés en toutes lettres juste dessous (voir le memo `posture`). */}
      <div className="vanitas-ov-posture-band">
        <div className="vanitas-hud-card vanitas-ov-posture" style={{ "--tone": toneVar(posture.tone) }}>
          <div className="vanitas-ov-ring">
            <svg width="84" height="84" viewBox="0 0 84 84">
              <circle cx="42" cy="42" r="36" fill="none" stroke="var(--hud-line)" strokeWidth="8" />
              <circle
                cx="42"
                cy="42"
                r="36"
                fill="none"
                stroke="var(--tone)"
                strokeWidth="8"
                strokeLinecap="round"
                strokeDasharray="226.2"
                strokeDashoffset={226.2 * (1 - posture.score / 100)}
                transform="rotate(-90 42 42)"
              />
            </svg>
            <div className="score">
              <b>{posture.score}</b>
              <small>{tr("vo.posture")}</small>
            </div>
          </div>
          <div className="vanitas-ov-posture-txt">
            <div className="vanitas-ov-posture-word">{posture.word}</div>
            <div className="vanitas-ov-posture-sub">{posture.sub}</div>
          </div>
        </div>

        <div className="vanitas-ov-signal-tiles">
          <div
            className="vanitas-hud-kpi"
            style={{ "--tone": highUntreated > 0 ? "var(--hud-high)" : "var(--hud-good)" }}
            role="button"
            tabIndex={0}
            onClick={() => onNavigateVanitas?.("vanitas-suspicious-activity")}
          >
            <div className="label"><span className="label-text">{tr("vo.highSuspects")}</span><span className="tag">{tr("vo.untriaged")}</span></div>
            <div className="value">{highUntreated}</div>
            <div className="kpi-sub">{tr("vo.investigateFirst")}</div>
          </div>
          <div
            className="vanitas-hud-kpi"
            style={{ "--tone": isolatedCount > 0 ? "var(--hud-high)" : "var(--hud-ink-faint)" }}
            role="button"
            tabIndex={0}
            onClick={() => onNavigateVanitas?.("vanitas-suspicious-activity")}
          >
            <div className="label"><span className="label-text">{tr("vo.isolated")}</span><span className="tag">{tr("vo.containment")}</span></div>
            <div className="value">{isolatedCount}</div>
            <div className="kpi-sub">{tr("vo.cutOff")}</div>
          </div>
          <div
            className="vanitas-hud-kpi"
            style={{ "--tone": counts.stale > 0 ? "var(--hud-warn)" : "var(--hud-good)" }}
            role="button"
            tabIndex={0}
            onClick={() => onNavigateVanitas?.("vanitas-devices", { filter: "offline" })}
          >
            <div className="label"><span className="label-text">{tr("vo.silent")}</span><span className="tag">&gt; {STALE_HOURS}H</span></div>
            <div className="value">{counts.stale}</div>
            <div className="kpi-sub">{tr("vo.noRecentContact")}</div>
          </div>
        </div>
      </div>

      {/* Bandeau KPI resserré à 6 tuiles (refonte 2026-09-14, maquette validée par Nicolas —
          en était à 9, illisible en desktop large, voir historique de ce fichier). Ne garde que
          ce qui appelle une décision ; "Commandes" et "Applications" redescendent en stats
          secondaires dans le rail plutôt que d'occuper une tuile héros chacune. */}
      <div className="vanitas-hud-strip">
        <div
          className="vanitas-hud-kpi"
          style={{ "--tone": "var(--hud-accent)" }}
          role="button"
          tabIndex={0}
          onClick={() => onNavigateVanitas?.("vanitas-devices")}
        >
          <div className="label">
            <span className="label-text">{tr("vo.endpoints")}</span><span className="tag">{tr("vo.total")}</span><span className="tag-hover">{tr("vo.toEndpoints")}</span>
          </div>
          <div className="value">{counts.total}</div>
          <div className="kpi-sub">{tr("vo.online", { count: counts.online })}</div>
        </div>
        <div
          className="vanitas-hud-kpi"
          style={{ "--tone": (suspiciousSummary.state.data?.by_severity?.high ?? 0) > 0 ? "var(--hud-high)" : "var(--hud-warn)" }}
          role="button"
          tabIndex={0}
          onClick={() => onNavigateVanitas?.("vanitas-suspicious-activity")}
        >
          <div className="label">
            <span className="label-text">{tr("vo.suspicious")}</span><span className="tag">{tr("vo.untriaged")}</span><span className="tag-hover">{tr("vo.toActivity")}</span>
          </div>
          <div className="value">
            {/* `by_status`/`by_severity` sont des objets creux (clé absente = zéro, pas de zéros
                explicites — voir routes/suspicious_activity.py) : un simple `?? "—"` afficherait
                un tiret tant que le parc n'a JAMAIS eu d'événement, au lieu d'un vrai "0". On ne
                retombe sur "—" que si le résumé n'est pas encore chargé du tout. */}
            {suspiciousSummary.state.data ? suspiciousSummary.state.data.by_status?.new ?? 0 : "—"}
          </div>
          <div className="kpi-sub">
            {(suspiciousSummary.state.data?.by_severity?.high ?? 0) > 0
              ? tr("vo.highCount", { count: suspiciousSummary.state.data.by_severity.high })
              : tr("vo.noHigh")}
          </div>
        </div>
        <div
          className="vanitas-hud-kpi"
          style={{ "--tone": "var(--hud-high)" }}
          role="button"
          tabIndex={0}
          onClick={() => onNavigateVanitas?.("vanitas-devices", { filter: "offline" })}
        >
          <div className="label">
            <span className="label-text">{tr("vo.silent")}</span>
            <span className="tag">{alertStaleCount === null ? "…" : `< ${alerts.state.staleThresholdHours}H`}</span>
            <span className="tag-hover">{tr("vo.toEndpoints")}</span>
          </div>
          <div className="value">{alertStaleCount ?? "—"}</div>
          <div className="kpi-sub">{tr("vo.alertThreshold")}</div>
        </div>
        <div
          className="vanitas-hud-kpi"
          style={{ "--tone": "var(--hud-warn)" }}
          role="button"
          tabIndex={0}
          onClick={() => onNavigateVanitas?.("vanitas-devices", { filter: "cert" })}
        >
          <div className="label">
            <span className="label-text">{tr("vo.certificate")}</span><span className="tag">{tr("vo.certTag", { days: CERT_WARNING_DAYS })}</span><span className="tag-hover">{tr("vo.toEndpoints")}</span>
          </div>
          <div className="value">{counts.cert}</div>
          <div className="kpi-sub">{tr("vo.renewSoon")}</div>
        </div>
        <div
          className="vanitas-hud-kpi"
          style={{ "--tone": "var(--hud-warn)" }}
          role="button"
          tabIndex={0}
          onClick={() => onNavigateVanitas?.("vanitas-eol")}
        >
          <div className="label">
            <span className="label-text">{tr("vo.eolSoftware")}</span><span className="tag">{tr("vo.fleet")}</span><span className="tag-hover">{tr("vo.toEol")}</span>
          </div>
          <div className="value">{eolCount}</div>
          <div className="kpi-sub">{tr("vo.eolSub")}</div>
        </div>
        <div
          className="vanitas-hud-kpi"
          style={{ "--tone": "var(--hud-good)" }}
          role="button"
          tabIndex={0}
          onClick={() => onNavigateVanitas?.("vanitas-compliance")}
        >
          <div className="label">
            <span className="label-text">{tr("vo.compliance")}</span><span className="tag">{tr("vo.rate")}</span><span className="tag-hover">{tr("vo.toCompliance")}</span>
          </div>
          <div className="value">{complianceRate === null ? "—" : `${complianceRate}%`}</div>
          <div className="kpi-sub">{tr("vo.compliantEvals")}</div>
        </div>
      </div>

      {hasTrend && (
        <div className="vanitas-hud-card vanitas-trend-band">
          <div className="vanitas-hud-card-head">
            <h2>{tr("vo.trends")}</h2>
            <span className="vanitas-hud-card-note">{tr("vo.trendsNote")}</span>
          </div>
          <div className="vanitas-trend-grid">
            <TrendSparkCard label={tr("vo.compliance")} metric={trend.complianceRate} unit="%" favorable="up" tone="var(--hud-good)" />
            <TrendSparkCard label={tr("vo.trend.suspiciousNew")} metric={trend.suspiciousNew} favorable="down" tone="var(--hud-high)" />
            <TrendSparkCard label={tr("vo.eolSoftware")} metric={trend.eolOccurrences} favorable="down" tone="var(--hud-warn)" />
            <TrendSparkCard label={tr("vo.trend.online")} metric={trend.onlineAgents} favorable="up" tone="var(--hud-accent)" />
          </div>
        </div>
      )}

      <div className="vanitas-hud-layout">
        <div className="vanitas-hud-main">
          <div className="vanitas-hud-card">
            <div className="vanitas-hud-card-head">
              <h2>{tr("vo.activityCommands")}</h2>
              <span className="vanitas-hud-card-note">
                {tr("vo.activityCount", { count: activityTotal, days: RECENT_DAYS })}
              </span>
            </div>
            <div className="vanitas-ov-chart-body">
              <svg
                ref={chartWrapRef}
                className="vanitas-ov-chart"
                viewBox={`0 0 ${chartWidth} ${CHART_H}`}
                shapeRendering="geometricPrecision"
              >
                <defs>
                  <linearGradient id="ovActivityFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--hud-accent)" stopOpacity="0.32" />
                    <stop offset="100%" stopColor="var(--hud-accent)" stopOpacity="0" />
                  </linearGradient>
                </defs>
                <g stroke="var(--hud-line)" strokeWidth="1">
                  <line x1="0" y1={CHART_H * 0.25} x2={chartWidth} y2={CHART_H * 0.25} />
                  <line x1="0" y1={CHART_H * 0.65} x2={chartWidth} y2={CHART_H * 0.65} />
                </g>
                <path d={activityChart.area} fill="url(#ovActivityFill)" />
                <path
                  d={activityChart.line}
                  fill="none"
                  stroke="var(--hud-accent)"
                  strokeWidth="2.6"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                />
                {activityChart.points.map((p, i) => (
                  <circle key={i} cx={p[0]} cy={p[1]} r="4" fill="var(--hud-panel)" stroke="var(--hud-accent)" strokeWidth="2.4" />
                ))}
              </svg>
              <div className="vanitas-ov-chart-axis">
                {activitySeries.map((b, i) => (
                  <span key={i}>{b.date.toLocaleDateString(currentLocale(), { weekday: "short" }).replace(".", "").slice(0, 3).toUpperCase()}</span>
                ))}
              </div>
            </div>
          </div>

          {/* "Signaux à traiter" (refonte 2026-09-14) — remplace les 3 cartes séparées
              "Postes à surveiller" / "Top vulnérabilités" / "Logiciels EOL" par une seule liste
              triée par urgence réelle, activités suspectes incluses. Un seul canal de couleur
              par ligne (la sévérité, liseré gauche + mot coloré) — le type de signal reste
              neutre pour ne pas faire concurrence à la sévérité (retour de Nicolas sur la
              maquette : "deux badges qui se battent"). */}
          <div className="vanitas-hud-card">
            <div className="vanitas-hud-card-head">
              <h2>{tr("vo.signalsTitle")}</h2>
              <span className="vanitas-hud-card-note">
                {tr("vo.signalsNote", { count: signals.length })}
              </span>
            </div>
            {signals.length === 0 ? (
              <p className="vanitas-hud-empty-note">{tr("vo.noSignalToHandle")}</p>
            ) : (
              <div>
                {signals.map((s) => (
                  <div
                    className="vanitas-ov-signal-row"
                    key={s.key}
                    style={{ "--tone": toneVar(s.tone) }}
                    role="button"
                    tabIndex={0}
                    onClick={s.onClick}
                  >
                    <span className="vanitas-ov-signal-type">{s.category}</span>
                    <div className="vanitas-ov-signal-main">
                      <span className="host">{s.host}</span>
                      <span className="detail">{s.detail}</span>
                    </div>
                    <div className="vanitas-ov-signal-side">
                      <span className={`vanitas-ov-sev-word ${s.tone}`}>{s.sevLabel}</span>
                      <span className="vanitas-ov-signal-time">{s.time ? fmtRelative(s.time) : (s.metric ?? "")}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="vanitas-hud-card">
            <div className="vanitas-hud-card-head">
              <h2>{tr("vo.recentActivity")}</h2>
              <button type="button" className="vanitas-hud-card-link" onClick={() => onNavigateVanitas?.("vanitas-commands")}>
                {tr("vo.seeLog")}
              </button>
            </div>
            {recentCommands.length === 0 ? (
              <p className="vanitas-hud-empty-note">{tr("vo.noCommand", { days: RECENT_DAYS })}</p>
            ) : (
              <div>
                {recentCommands.slice(0, FEED_MAX).map((c) => (
                  <div
                    className="vanitas-hud-feed-row"
                    key={c.id}
                    role="button"
                    tabIndex={0}
                    onClick={() => gotoAgent(c.agent_id)}
                  >
                    <span className="vanitas-hud-feed-time">{fmtRelative(c.created_at)}</span>
                    <span className="vanitas-hud-feed-host">{c.hostname}</span>
                    <span className="vanitas-hud-feed-cmd">{COMMAND_LABELS[c.command_type] ?? c.command_type}</span>
                    <span
                      className={`vanitas-hud-status-pill ${
                        c.status === "pending" || c.status === "running" ? "pending" : c.success ? "ok" : "bad"
                      }`}
                    >
                      {tr(c.status === "pending" || c.status === "running" ? "vo.inProgress" : c.success ? "vo.ok" : "vo.failed")}
                    </span>
                    <span className="vanitas-hud-chev">›</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <aside className="vanitas-hud-rail">
          <div className="vanitas-hud-rail-title">{tr("vo.signals")}</div>

          {/* Cartes-signaux façon rail "Signaux" de la Vue d'ensemble Pandore (2026-09-17) :
              répartitions/agrégats fleet-wide déjà chargés, aucun nouvel appel. */}
          <div className="vanitas-hud-card vanitas-ov-rail-card">
            <div className="vanitas-ov-rail-section">
              <div className="vanitas-ov-rail-head">
                <h3>{tr("vo.patchPosture")}</h3>
                <button type="button" className="vanitas-hud-card-link" onClick={() => onNavigateVanitas?.("vanitas-patch")}>→</button>
              </div>
              <div className="vanitas-hud-donut-wrap">
                <div
                  className="vanitas-hud-donut"
                  role="button"
                  tabIndex={0}
                  onClick={() => onNavigateVanitas?.("vanitas-patch")}
                  style={{
                    background: patchCounts.total
                      ? `conic-gradient(var(--hud-good) 0 ${(patchCounts.ok / patchCounts.total) * 360}deg, var(--hud-warn) ${(patchCounts.ok / patchCounts.total) * 360}deg ${((patchCounts.ok + patchCounts.pending) / patchCounts.total) * 360}deg, rgba(255,255,255,.08) ${((patchCounts.ok + patchCounts.pending) / patchCounts.total) * 360}deg 360deg)`
                      : "rgba(255,255,255,.08)",
                  }}
                >
                  <div className="vanitas-hud-donut-center"><b>{patchCounts.total}</b><span>{tr("vo.endpointsWord")}</span></div>
                </div>
                <div className="vanitas-hud-donut-legend">
                  <div className="vanitas-hud-donut-legend-row"><span className="vanitas-hud-donut-dot" style={{ background: "var(--hud-good)" }} />
                    {tr("vo.upToDate")}
                    <span className="n">{patchCounts.ok}</span></div>
                  <div className="vanitas-hud-donut-legend-row"><span className="vanitas-hud-donut-dot" style={{ background: "var(--hud-warn)" }} />
                    {tr("vo.pending")}
                    <span className="n">{patchCounts.pending}</span></div>
                  <div className="vanitas-hud-donut-legend-row"><span className="vanitas-hud-donut-dot" style={{ background: "rgba(255,255,255,.25)" }} />
                    {tr("vo.offPolicy")}
                    <span className="n">{patchCounts.off}</span></div>
                </div>
              </div>
            </div>

            <div className="vanitas-ov-rail-section">
              <div className="vanitas-ov-rail-head">
                <h3>{tr("vo.byCriticality")}</h3>
                <button type="button" className="vanitas-hud-card-link" onClick={() => onNavigateVanitas?.("vanitas-suspicious-activity")}>→</button>
              </div>
              <div className="vanitas-hud-stat-bars">
                {[
                  { k: "high", label: tr("vo.sev.high"), tone: "var(--hud-high)", n: sevCounts.high },
                  { k: "med", label: tr("vo.sev.med"), tone: "var(--hud-warn)", n: sevCounts.med },
                  { k: "low", label: tr("vo.sev.low"), tone: "var(--hud-good)", n: sevCounts.low },
                ].map((r) => {
                  const max = Math.max(1, sevCounts.high, sevCounts.med, sevCounts.low);
                  return (
                    <div className="vanitas-hud-stat-row" key={r.k} style={{ color: r.tone }}>
                      <span className="vanitas-hud-stat-label">{r.label}</span>
                      <div className="vanitas-hud-stat-track"><div className="vanitas-hud-stat-fill" style={{ width: `${Math.round((r.n / max) * 100)}%`, background: r.tone }} /></div>
                      <span className="vanitas-hud-stat-n">{r.n}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="vanitas-ov-rail-section">
              <div className="vanitas-ov-rail-head">
                <h3>{tr("vo.topVulns")}</h3>
                <button type="button" className="vanitas-hud-card-link" onClick={() => onNavigateVanitas?.("vanitas-vulnerabilities")}>→</button>
              </div>
              {(topVulns.state.data ?? []).length === 0 ? (
                <p className="vanitas-hud-empty-note">{tr("vo.noCve")}</p>
              ) : (
                <div className="vanitas-hud-stat-bars">
                  {(() => {
                    const rows = topVulns.state.data ?? [];
                    const max = Math.max(1, ...rows.map((v) => v.device_count ?? 0));
                    return rows.map((v) => {
                      const t = toneVar(severityTone(v.severity));
                      return (
                        <div
                          className="vanitas-hud-stat-row"
                          key={v.cve_id}
                          style={{ color: t, cursor: "pointer" }}
                          role="button"
                          tabIndex={0}
                          onClick={() => onNavigateVanitas?.("vanitas-vulnerabilities", { cveId: v.cve_id })}
                        >
                          <span className="vanitas-hud-stat-label">{v.cve_id}</span>
                          <div className="vanitas-hud-stat-track"><div className="vanitas-hud-stat-fill" style={{ width: `${Math.round(((v.device_count ?? 0) / max) * 100)}%`, background: t }} /></div>
                          <span className="vanitas-hud-stat-n">{v.device_count}</span>
                        </div>
                      );
                    });
                  })()}
                </div>
              )}
            </div>
          </div>

          {/* Carte consolidée "contexte" — Groupes + Alertes récentes. UNE carte à sections
              divisées (retour de Nicolas : "une seule source de lumière"). */}
          <div className="vanitas-hud-card vanitas-ov-rail-card">
            <div className="vanitas-ov-rail-section">
              <div className="vanitas-ov-rail-head">
                <h3>{tr("vo.groups")}</h3>
                <button type="button" className="vanitas-hud-card-link" onClick={() => onNavigateVanitas?.("vanitas-groups")}>
                  →
                </button>
              </div>
              {groupRows.length === 0 ? (
                <p className="vanitas-hud-empty-note">{tr("vo.noGroup")}</p>
              ) : (
                <div>
                  {groupRows.map((g) => (
                    <div
                      className="vanitas-hud-group-row"
                      key={g.id}
                      onClick={() => onNavigateVanitas?.("vanitas-groups")}
                    >
                      <span className="vanitas-hud-group-dot" />
                      <span className="vanitas-hud-group-name">{g.name}</span>
                      <span className="vanitas-hud-group-n">
                        {tr("vo.groupCount", { count: g.device_count })}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* "Alertes récentes" (2026-09-08) — journal des alertes déclenchées par les
                boucles de fond (agent silencieux / nouvelle vuln critique / nouvel échec de
                conformité, voir vanitas/alert_state.py). C'est la SEULE surface visible tant que
                le SMTP n'est pas configuré (backend/common/notify.py) — jamais laisser cette
                section disparaître silencieusement, un état vide explicite vaut mieux que rien. */}
            <div className="vanitas-ov-rail-section">
              <div className="vanitas-ov-rail-head">
                <h3>{tr("vo.recentAlerts")}</h3>
              </div>
              {alerts.state.status === "loading" ? (
                <p className="vanitas-hud-empty-note">{tr("vo.loading")}</p>
              ) : (alerts.state.recent ?? []).length === 0 ? (
                <p className="vanitas-hud-empty-note">{tr("vo.noRecentAlert")}</p>
              ) : (
                <div>
                  {alerts.state.recent.map((a, i) => (
                    <div
                      className="vanitas-hud-feed-row"
                      key={`${a.agent_id}-${a.at}-${i}`}
                      role="button"
                      tabIndex={0}
                      onClick={() => gotoAgent(a.agent_id)}
                    >
                      <span className="vanitas-hud-feed-time">{fmtRelative(a.at)}</span>
                      <span className="vanitas-hud-feed-host">{a.hostname}</span>
                      <span className="vanitas-hud-feed-cmd">{ALERT_TYPE_LABEL[a.type] ?? a.type}</span>
                      <span className="vanitas-hud-chev">›</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
}
