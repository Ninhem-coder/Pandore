import { useEffect, useMemo, useRef, useState } from "react";
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
import useReorderableZone from "../hooks/useReorderableZone.js";
import { IconGrip } from "../components/icons.jsx";
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
const DAY_MS = 86_400_000;

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
 *
 * Refonte "bento" (2026-10-23, maquette canvas validée par Nicolas après plusieurs passes de
 * densité — "les blocs sont trop gros") : PRÉSENTATION seule, mêmes hooks et mêmes calculs.
 * En tête, fixe : posture (score + 2 sous-signaux) et 6 tuiles KPI qui absorbent l'ancien
 * bandeau "Tendances" (variation 7 j + mini-courbe dans la tuile mesurée). Dessous, deux zones
 * réordonnables comme la Vue d'ensemble Pandore (`useReorderableZone`) : colonne principale
 * (activité, top CVE, signaux, flux — largeur réglable) et colonne de droite (patch,
 * criticité, groupes, alertes — ordre seul). Classes `.vov-*`, scopées à cette page.
 */
// Zones réordonnables (refonte bento 2026-10-23) — même mécanique que la Vue d'ensemble Pandore
// (`useReorderableZone`, poignée + aperçu en direct + persistance par navigateur) : la colonne
// principale se réordonne ET se redimensionne (largeur en sixièmes : 1/3, 1/2, 2/3, pleine),
// la colonne de droite se réordonne seule (une colonne, une largeur fixe).
const MAIN_SPANS = [2, 3, 4, 6];
const MAIN_DEFAULT_ORDER = ["activity", "top-vulns", "signals", "feed"];
// Activité en 1/3 (7 barres tiennent largement), top CVE en 2/3 (ID + produit + CVSS + postes).
const MAIN_DEFAULT_SIZES = { activity: 0, "top-vulns": 2, signals: 3, feed: 3 };
const RAIL_DEFAULT_ORDER = ["patch", "criticality", "groups", "alerts"];

/** Mini-courbe d'une tuile KPI — étirée sur la largeur restante (`preserveAspectRatio="none"`
 * + `vectorEffect` pour garder un trait net), couleur héritée (`currentColor`). Une série plate
 * (min == max) est tracée en ligne médiane plutôt que de diviser par zéro. */
function Sparkline({ series, title }) {
  if (!Array.isArray(series) || series.length < 2) return null;
  const min = Math.min(...series);
  const max = Math.max(...series);
  const span = max - min || 1;
  const points = series
    .map((v, i) => `${((i / (series.length - 1)) * 96 + 2).toFixed(1)},${(28 - ((v - min) / span) * 24).toFixed(1)}`)
    .join(" ");
  return (
    <svg className="vov-spark" viewBox="0 0 100 30" preserveAspectRatio="none" role="img" aria-label={title}>
      <title>{title}</title>
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** Tuile KPI du bento : libellé + étiquette (remplacée au survol par la destination), valeur et
 * mini-courbe sur la même ligne, puis sous-titre et variation sur 7 j. La tendance (jalon
 * 2026-09-17, ancien bandeau "Tendances") est fusionnée ICI dans la tuile qu'elle mesure :
 * `metric` = `{ current, delta7, series }` de `computeVanitasTrend`, `favorable` "up"/"down"
 * décide si une hausse est verte ou rouge. Le dernier relevé historique (`current`) reste
 * lisible dans l'infobulle de la courbe. `extra` remplace la courbe quand la tuile n'en a pas. */
function KpiTile({ label, tag, dest, value, tone, quiet, sub, metric, favorable, unit = "", extra, onClick }) {
  const { current, delta7, series } = metric || {};
  const hasSeries = Array.isArray(series) && series.length >= 2;
  let deltaClass = "flat";
  if (typeof delta7 === "number" && delta7 !== 0) {
    const good = favorable === "up" ? delta7 > 0 : delta7 < 0;
    deltaClass = good ? "good" : "bad";
  }
  const deltaLabel =
    typeof delta7 === "number" && delta7 !== 0
      ? tr("vo.deltaWeek", { arrow: delta7 > 0 ? "▲" : "▼", value: Math.abs(delta7), unit })
      : tr("vo.stableWeek");
  return (
    <button type="button" className="vov-card vov-kpi" style={{ "--tone": tone }} onClick={onClick}>
      <span className="vov-kpi-head">
        <span className="vov-lbl">{label}</span>
        <span className="vov-tag">{tag}</span>
        <span className="vov-tag vov-tag-hover">{dest}</span>
      </span>
      <span className="vov-kpi-main">
        <span className={`vov-val${quiet ? " quiet" : ""}`}>{value}</span>
        {extra && <span className="vov-kpi-extra">{extra}</span>}
        {!extra && hasSeries && <Sparkline series={series} title={tr("vo.lastSnapshot", { value: `${current}${unit}` })} />}
      </span>
      <span className="vov-kpi-foot">
        <span className="vov-sub">{sub}</span>
        {hasSeries && <span className={`vov-chip ${deltaClass}`}>{deltaLabel}</span>}
      </span>
    </button>
  );
}

/** Coque d'une tuile de zone (colonne principale ou de droite) : titre, badge/lien optionnels,
 * boutons de largeur (zone principale seulement) et poignée de glisser-déposer. Toute la carte
 * est la cible de drop, seule la poignée démarre le drag. */
function ZoneTile({ zone, tileKey, title, badge, action, span, sizeIndex, children }) {
  const resizable = typeof sizeIndex === "number";
  return (
    <section
      ref={(node) => zone.registerNode(tileKey, node)}
      className={`vov-card vov-tile${zone.draggingKey === tileKey ? " dragging" : ""}`}
      style={span ? { gridColumn: `span ${span}` } : undefined}
      aria-label={title}
      onDragOver={(e) => e.preventDefault()}
      onDragEnter={() => zone.onDragEnter(tileKey)}
      onDrop={(e) => {
        e.preventDefault();
        zone.onDrop();
      }}
    >
      <div className="vov-tile-head">
        <span className="vov-tile-title">
          <h2 className="vov-h2">{title}</h2>
          {badge}
        </span>
        <span className="vov-tile-ctls">
          {action}
          {resizable && (
            <>
              <button
                type="button"
                className="vov-ctl vov-size-btn"
                onClick={() => zone.resize(tileKey, -1)}
                disabled={sizeIndex <= 0}
                title={tr("overview.shrinkTile")}
                aria-label={tr("overview.shrinkTile")}
              >
                −
              </button>
              <button
                type="button"
                className="vov-ctl vov-size-btn"
                onClick={() => zone.resize(tileKey, 1)}
                disabled={sizeIndex >= MAIN_SPANS.length - 1}
                title={tr("overview.growTile")}
                aria-label={tr("overview.growTile")}
              >
                +
              </button>
            </>
          )}
          <span className="vov-ctl vov-grip" title={tr("common.dragToReorder")} {...zone.dragHandleProps(tileKey)}>
            <IconGrip />
          </span>
        </span>
      </div>
      {children}
    </section>
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

  const activityTotal = activitySeries.reduce((sum, b) => sum + b.count, 0);
  const activityMax = Math.max(1, ...activitySeries.map((b) => b.count));

  // Zones réordonnables — hooks appelés AVANT le retour anticipé de chargement (règle des hooks).
  const main = useReorderableZone(MAIN_DEFAULT_ORDER, MAIN_DEFAULT_SIZES, "vanitasOverviewMain-v1", {
    sizeCount: MAIN_SPANS.length,
    defaultSize: 1,
  });
  const rail = useReorderableZone(RAIL_DEFAULT_ORDER, {}, "vanitasOverviewRail-v1");

  const loading = agents.state.status === "loading" || commands.state.status === "loading";
  const error = agents.state.error || commands.state.error;

  // Points de rupture sur la largeur RÉELLE de la page (pas celle de la fenêtre : la sidebar
  // repliable la change à fenêtre égale) — `data-size` lu par styles.css (`.vov[data-size]`).
  // Re-branché quand le squelette de chargement laisse place à la page (autre nœud racine).
  const rootRef = useRef(null);
  const [size, setSize] = useState("l");
  useEffect(() => {
    const el = rootRef.current;
    if (!el || typeof ResizeObserver === "undefined") return undefined;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect?.width ?? 0;
      setSize(w < 480 ? "xs" : w < 700 ? "s" : w < 1000 ? "m" : "l");
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [loading]);

  // Chargement : squelettes au gabarit des vraies cartes (charte §10 — pulsation cyan, coupée
  // par prefers-reduced-motion) plutôt qu'un simple texte, pour que la page ne "saute" pas.
  if (loading) {
    return (
      <div className="vanitas-hud vov" aria-busy="true" ref={rootRef} data-size={size}>
        <p className="vov-sr">{tr("vo.loading")}</p>
        <div className="vov-bento">
          <div className="vov-card vov-posture">
            <span className="vov-sk" style={{ width: 68, height: 68, borderRadius: 999 }} />
            <span className="vov-sk" style={{ flex: 1, height: 52 }} />
          </div>
          {Array.from({ length: 6 }, (_, i) => (
            <div className="vov-card vov-kpi" key={i}>
              <span className="vov-sk" style={{ width: "50%", height: 12 }} />
              <span className="vov-sk" style={{ width: "70%", height: 28 }} />
              <span className="vov-sk" style={{ width: "60%", height: 12 }} />
            </div>
          ))}
        </div>
      </div>
    );
  }

  const suspiciousHigh = suspiciousSummary.state.data?.by_severity?.high ?? 0;
  // `by_status`/`by_severity` sont des objets creux (clé absente = zéro) : on n'affiche "—" que
  // si le résumé n'est pas encore chargé du tout, jamais pour un parc sans aucun événement.
  const suspiciousUntriaged = suspiciousSummary.state.data ? suspiciousSummary.state.data.by_status?.new ?? 0 : null;
  const patchArc = (n) => (patchCounts.total ? (n / patchCounts.total) * 226.2 : 0);
  const sevMax = Math.max(1, sevCounts.high, sevCounts.med, sevCounts.low);

  const mainBody = {
    activity: (
      <>
        <div className="vov-bars" role="img" aria-label={tr("vo.chartAria", { list: activitySeries.map((b) => b.count).join(", ") })}>
          {activitySeries.map((b) => (
            <div className="vov-bar" key={b.date.getTime()}>
              <span className="vov-tip">
                {tr("vo.barTip", {
                  count: b.count,
                  date: b.date.toLocaleDateString(currentLocale(), { weekday: "short", day: "numeric", month: "short" }),
                })}
              </span>
              <i style={{ height: `${Math.max(4, Math.round((b.count / activityMax) * 100))}%` }} />
            </div>
          ))}
        </div>
        <div className="vov-axis">
          {activitySeries.map((b) => (
            <span key={b.date.getTime()}>
              {b.date.toLocaleDateString(currentLocale(), { weekday: "short" }).replace(".", "").slice(0, 3).toUpperCase()}
            </span>
          ))}
        </div>
      </>
    ),
    "top-vulns": topVulns.state.error ? (
      <p className="vov-error" role="alert">{topVulns.state.error}</p>
    ) : (topVulns.state.data ?? []).length === 0 ? (
      <p className="vov-empty">{tr("vo.noCve")}</p>
    ) : (
      <div>
        {topVulns.state.data.map((v) => (
          <button
            type="button"
            className="vov-row vov-cve-row"
            key={v.cve_id}
            onClick={() => onNavigateVanitas?.("vanitas-vulnerabilities", { cveId: v.cve_id })}
          >
            <span className="vov-mono">{v.cve_id}</span>
            <span className="vov-ellipsis">{v.product_name}</span>
            <span className="vov-mono vov-muted">{v.cvss_score != null ? tr("vo.cvss", { score: v.cvss_score }) : "—"}</span>
            <span className={`vov-chip ${severityTone(v.severity)}`}>{tr("vo.groupCount", { count: v.device_count })}</span>
          </button>
        ))}
      </div>
    ),
    // "Signaux à traiter" — un seul canal de couleur par ligne (la sévérité : liseré + mot
    // coloré), le type de signal reste neutre (retour de Nicolas : "deux badges qui se battent").
    signals:
      signals.length === 0 ? (
        <p className="vov-empty">{tr("vo.noSignalToHandle")}</p>
      ) : (
        <div>
          {signals.map((s) => (
            <button type="button" className="vov-row vov-signal-row" key={s.key} style={{ "--tone": toneVar(s.tone) }} onClick={s.onClick}>
              <span className="vov-type">{s.category}</span>
              <span className="vov-signal-main">
                <span className="vov-mono">{s.host}</span>
                <span className="vov-ellipsis vov-muted">{s.detail}</span>
              </span>
              <span className={`vov-sev ${s.tone}`}>{s.sevLabel}</span>
              <span className="vov-time">{s.time ? fmtRelative(s.time) : s.metric ?? ""}</span>
            </button>
          ))}
        </div>
      ),
    feed:
      recentCommands.length === 0 ? (
        <p className="vov-empty">{tr("vo.noCommand", { days: RECENT_DAYS })}</p>
      ) : (
        <div>
          {recentCommands.slice(0, FEED_MAX).map((c) => {
            const state = c.status === "pending" || c.status === "running" ? "pending" : c.success ? "ok" : "bad";
            return (
              <button type="button" className="vov-row vov-feed-row" key={c.id} onClick={() => gotoAgent(c.agent_id)}>
                <span className="vov-time">{fmtRelative(c.created_at)}</span>
                <span className="vov-mono">{c.hostname}</span>
                <span className="vov-ellipsis">{COMMAND_LABELS[c.command_type] ?? c.command_type}</span>
                <span className={`vanitas-hud-status-pill ${state}`}>
                  {tr(state === "pending" ? "vo.inProgress" : state === "ok" ? "vo.ok" : "vo.failed")}
                </span>
              </button>
            );
          })}
        </div>
      ),
  };

  const mainMeta = {
    activity: { title: tr("vo.activityCommands"), badge: <span className="vov-note">{tr("vo.activityCount", { count: activityTotal, days: RECENT_DAYS })}</span> },
    "top-vulns": {
      title: tr("vo.topVulns"),
      action: (
        <button type="button" className="vov-link" onClick={() => onNavigateVanitas?.("vanitas-vulnerabilities")}>
          {tr("vo.seeAll")}
        </button>
      ),
    },
    signals: { title: tr("vo.signalsTitle"), badge: <span className="vov-note">{tr("vo.signalsNote", { count: signals.length })}</span> },
    feed: {
      title: tr("vo.recentActivity"),
      action: (
        <button type="button" className="vov-link" onClick={() => onNavigateVanitas?.("vanitas-commands")}>
          {tr("vo.seeJournal")}
        </button>
      ),
    },
  };

  const arrow = (dest, label) => (
    <button type="button" className="vov-link" aria-label={label} title={label} onClick={() => onNavigateVanitas?.(dest)}>
      →
    </button>
  );

  const railBody = {
    patch: (
      <div className="vov-patch">
        <svg
          width="64"
          height="64"
          viewBox="0 0 92 92"
          role="img"
          aria-label={tr("vo.patchAria", { ok: patchCounts.ok, pending: patchCounts.pending, off: patchCounts.off, total: patchCounts.total })}
        >
          <circle cx="46" cy="46" r="36" fill="none" stroke="var(--hud-line)" strokeWidth="11" />
          <circle cx="46" cy="46" r="36" fill="none" stroke="var(--hud-good)" strokeWidth="11" strokeDasharray={`${patchArc(patchCounts.ok)} 226.2`} transform="rotate(-90 46 46)" />
          <circle cx="46" cy="46" r="36" fill="none" stroke="var(--hud-warn)" strokeWidth="11" strokeDasharray={`${patchArc(patchCounts.pending)} 226.2`} strokeDashoffset={-patchArc(patchCounts.ok)} transform="rotate(-90 46 46)" />
          <circle cx="46" cy="46" r="36" fill="none" stroke="var(--vov-neutral)" strokeWidth="11" strokeDasharray={`${patchArc(patchCounts.off)} 226.2`} strokeDashoffset={-patchArc(patchCounts.ok + patchCounts.pending)} transform="rotate(-90 46 46)" />
          <text x="46" y="50" textAnchor="middle" className="vov-donut-n">{patchCounts.total}</text>
          <text x="46" y="64" textAnchor="middle" className="vov-donut-l">{tr("vo.endpointsWord").toUpperCase()}</text>
        </svg>
        <div className="vov-legend">
          <span><i style={{ background: "var(--hud-good)" }} />{tr("vo.upToDate")} <b>{patchCounts.ok}</b></span>
          <span><i style={{ background: "var(--hud-warn)" }} />{tr("vo.pending")} <b>{patchCounts.pending}</b></span>
          <span><i style={{ background: "var(--vov-neutral)" }} />{tr("vo.offPolicy")} <b>{patchCounts.off}</b></span>
        </div>
      </div>
    ),
    criticality: (
      <div className="vov-crit">
        {[
          { k: "high", label: tr("vo.sev.high"), tone: "var(--hud-high)", n: sevCounts.high },
          { k: "med", label: tr("vo.sev.med"), tone: "var(--hud-warn)", n: sevCounts.med },
          { k: "low", label: tr("vo.sev.low"), tone: "var(--hud-good)", n: sevCounts.low },
        ].map((r) => (
          <div className="vov-crit-row" key={r.k}>
            <span className="vov-muted">{r.label}</span>
            <span className="vov-track"><i style={{ width: `${Math.round((r.n / sevMax) * 100)}%`, background: r.tone }} /></span>
            <b>{r.n}</b>
          </div>
        ))}
      </div>
    ),
    groups:
      groupRows.length === 0 ? (
        <button type="button" className="vov-empty vov-empty-link" onClick={() => onNavigateVanitas?.("vanitas-groups")}>
          {tr("vo.noGroup")}
        </button>
      ) : (
        <div>
          {groupRows.map((g) => (
            <button type="button" className="vov-row" key={g.id} onClick={() => onNavigateVanitas?.("vanitas-groups")}>
              <span className="vov-ellipsis">{g.name}</span>
              <span className="vov-mono vov-muted">{tr("vo.groupCount", { count: g.device_count })}</span>
            </button>
          ))}
        </div>
      ),
    // "Alertes récentes" — SEULE surface visible tant que le SMTP n'est pas configuré
    // (backend/common/notify.py) : jamais masquée, un état vide explicite plutôt que rien.
    alerts:
      alerts.state.status === "loading" ? (
        <p className="vov-empty">{tr("vo.loading")}</p>
      ) : (alerts.state.recent ?? []).length === 0 ? (
        <p className="vov-empty">{tr("vo.noRecentAlert")}</p>
      ) : (
        <div>
          {alerts.state.recent.map((a, i) => (
            <button type="button" className="vov-row vov-alert-row" key={`${a.agent_id}-${a.at}-${i}`} onClick={() => gotoAgent(a.agent_id)}>
              <span className="vov-time">{fmtRelative(a.at)}</span>
              <span className="vov-alert-main">
                <span>{ALERT_TYPE_LABEL[a.type] ?? a.type}</span>
                <span className="vov-mono vov-muted">{a.hostname}</span>
              </span>
            </button>
          ))}
        </div>
      ),
  };

  const railMeta = {
    patch: { title: tr("vo.patchPosture"), action: arrow("vanitas-patch", tr("vo.openPatch")) },
    criticality: { title: tr("vo.byCriticality"), action: arrow("vanitas-suspicious-activity", tr("vo.openSuspicious")) },
    groups: { title: tr("vo.groups"), action: arrow("vanitas-groups", tr("vo.openGroups")) },
    alerts: { title: tr("vo.recentAlerts") },
  };

  return (
    <div className="vanitas-hud vov" ref={rootRef} data-size={size}>
      {error && <p className="vanitas-hud-error">{error}</p>}

      {/* Bento (refonte 2026-10-23, maquette validée par Nicolas) — posture + 6 tuiles KPI, fixe :
          c'est le résumé qu'on lit en premier, il ne se réordonne pas. */}
      <section className="vov-bento" aria-label={tr("vo.fleetPosture")}>
        <div className="vov-card vov-posture" style={{ "--tone": toneVar(posture.tone) }}>
          <div className="vov-posture-main">
            <svg width="68" height="68" viewBox="0 0 84 84" role="img" aria-label={tr("vo.scoreAria", { score: posture.score })}>
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
              <text x="42" y="47" textAnchor="middle" className="vov-score">{posture.score}</text>
            </svg>
            <div className="vov-posture-txt">
              <span className="vov-lbl">{tr("vo.fleetPosture")}</span>
              <span className="vov-posture-word">{posture.word}</span>
              <span className="vov-sub">{posture.sub}</span>
            </div>
          </div>
          <div className="vov-posture-sigs">
            <button type="button" className="vov-sig" onClick={() => onNavigateVanitas?.("vanitas-suspicious-activity")}>
              <span className={`vov-val${highUntreated > 0 ? "" : " quiet"}`} style={{ "--tone": "var(--hud-high)" }}>{highUntreated}</span>
              <span className="vov-sig-txt"><span className="vov-lbl">{tr("vo.highSuspects")}</span><span className="vov-sub">{tr("vo.untriagedLower")}</span></span>
            </button>
            <button type="button" className="vov-sig" onClick={() => onNavigateVanitas?.("vanitas-suspicious-activity")}>
              <span className={`vov-val${isolatedCount > 0 ? "" : " quiet"}`} style={{ "--tone": "var(--hud-accent2)" }}>{isolatedCount}</span>
              <span className="vov-sig-txt"><span className="vov-lbl">{tr("vo.isolated")}</span><span className="vov-sub">{tr("vo.cutOffShort")}</span></span>
            </button>
          </div>
        </div>

        <KpiTile
          label={tr("vo.endpoints")}
          tag={tr("vo.total")}
          dest={tr("vo.toEndpoints")}
          value={counts.total}
          tone="var(--hud-accent)"
          sub={tr("vo.online", { count: counts.online })}
          metric={trend.onlineAgents}
          favorable="up"
          onClick={() => onNavigateVanitas?.("vanitas-devices")}
        />
        <KpiTile
          label={tr("vo.compliance")}
          tag={tr("vo.rate")}
          dest={tr("vo.toCompliance")}
          value={complianceRate === null ? "—" : `${complianceRate}%`}
          tone="var(--hud-good)"
          sub={tr("vo.compliantEvals")}
          metric={trend.complianceRate}
          unit="%"
          favorable="up"
          onClick={() => onNavigateVanitas?.("vanitas-compliance")}
        />
        <KpiTile
          label={tr("vo.suspicious")}
          tag={tr("vo.untriaged")}
          dest={tr("vo.toActivity")}
          value={suspiciousUntriaged ?? "—"}
          quiet={!suspiciousUntriaged}
          tone={suspiciousHigh > 0 ? "var(--hud-high)" : "var(--hud-warn)"}
          sub={suspiciousHigh > 0 ? tr("vo.highCount", { count: suspiciousHigh }) : tr("vo.noHigh")}
          metric={trend.suspiciousNew}
          favorable="down"
          onClick={() => onNavigateVanitas?.("vanitas-suspicious-activity")}
        />
        <KpiTile
          label={tr("vo.eolSoftware")}
          tag={tr("vo.fleet")}
          dest={tr("vo.toEol")}
          value={eolCount}
          quiet={!eolCount}
          tone="var(--hud-warn)"
          sub={tr("vo.eolSub")}
          metric={trend.eolOccurrences}
          favorable="down"
          onClick={() => onNavigateVanitas?.("vanitas-eol")}
        />
        {/* Les DEUX seuils "silencieux" réunis dans une seule tuile (ils s'affichaient avant
            dans deux tuiles séparées, source de confusion) : le seuil d'ALERTE (backend,
            `stale_threshold_hours`, 12 h par défaut) en valeur, le seuil de surveillance
            (`STALE_HOURS`, 7 j) en complément. */}
        <KpiTile
          label={tr("vo.silent")}
          tag={alertStaleCount === null ? "…" : `< ${alerts.state.staleThresholdHours}H`}
          dest={tr("vo.toEndpoints")}
          value={alertStaleCount ?? "—"}
          quiet={!alertStaleCount}
          tone="var(--hud-high)"
          sub={tr("vo.alertThreshold")}
          extra={tr("vo.staleLong", { count: counts.stale, hours: STALE_HOURS })}
          onClick={() => onNavigateVanitas?.("vanitas-devices", { filter: "offline" })}
        />
        <KpiTile
          label={tr("vo.certificate")}
          tag={tr("vo.certTag", { days: CERT_WARNING_DAYS })}
          dest={tr("vo.toEndpoints")}
          value={counts.cert}
          quiet={!counts.cert}
          tone="var(--hud-warn)"
          sub={tr("vo.renewSoon")}
          onClick={() => onNavigateVanitas?.("vanitas-devices", { filter: "cert" })}
        />
      </section>

      <div className="vov-layout-bar">
        <p className="vov-hint">
          <IconGrip />
          {tr("vo.layoutHint")}
        </p>
        <button
          type="button"
          className="vov-link"
          onClick={() => {
            main.resetLayout();
            rail.resetLayout();
          }}
        >
          {tr("vo.resetLayout")}
        </button>
      </div>

      <div className="vov-zones">
        <div className="vov-main">
          {main.order.map((key) => {
            const sizeIndex = main.sizes[key] ?? 1;
            return (
              <ZoneTile key={key} zone={main} tileKey={key} span={MAIN_SPANS[sizeIndex]} sizeIndex={sizeIndex} {...mainMeta[key]}>
                {mainBody[key]}
              </ZoneTile>
            );
          })}
        </div>

        <aside className="vov-rail" aria-label={tr("vo.signals")}>
          {rail.order.map((key) => (
            <ZoneTile key={key} zone={rail} tileKey={key} {...railMeta[key]}>
              {railBody[key]}
            </ZoneTile>
          ))}
        </aside>
      </div>
    </div>
  );
}
