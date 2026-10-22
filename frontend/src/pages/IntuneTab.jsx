import { useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { isErrorPayload, useComplianceDetail, useHistoryTrend } from "../hooks/useDashboardData.js";
import ComplianceDeviceTable from "../components/ComplianceDeviceTable.jsx";
import { computeSettingsState } from "../components/ComplianceOsGrid.jsx";
import { OsGridSkeleton } from "../components/ComplianceSkeleton.jsx";
import {
  OS_COLORS,
  OS_DEFAULT_COLOR,
  SEVERITY,
  FAILING_CATEGORIES,
  POLICY_STATUS_COLORS,
  secureScoreLevel,
  formatRelativeDays,
  categoryLabel,
} from "../theme.js";
import { groupComplianceDetailByOS, computeHistoryTrend } from "../selectors.js";
import { currentLocale, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

/**
 * Onglet "Conformité" — refonte du 2026-08-28 (skill frontend-design, maquette HTML validée
 * par Nicolas : "j'adore [...] met en place la maquette à l'identique"), inspirée des consoles
 * antivirus/EDR de référence (CrowdStrike Falcon, Microsoft Defender, Qualys, Tenable) :
 * - hero : score de posture (jauge radiale) + tendance non-conformes + politiques suivies ;
 * - file "À traiter en priorité" : postes en échec depuis le plus longtemps ;
 * - "Politiques en échec — classées par impact" (remplace la grille de cartes par OS) ;
 * - rail : répartition par OS, tendance 90 jours, correctif recommandé, réconciliation des
 *   chiffres repliée par défaut (`<details>`) ;
 * - table de postes filtrable par OS puis par politique (`ComplianceDeviceTable.jsx`).
 *
 * Remplace l'ancienne mise en page "panorama à 3 camemberts + grille de cartes par OS"
 * (ex-`ComplianceOsGrid` par défaut, voir ce fichier — les 4 exports nommés dont dépend la
 * réconciliation Graph/réglages restent utilisés ici et par `DeviceOverviewTab.jsx`).
 *
 * La logique de réconciliation "un device ne sort du compte que si TOUTES ses occurrences en
 * échec sont vérifiées conformes" (ex-`liveCount` de `OsCard`) est reprise à l'identique mais
 * PAGE-LEVEL plutôt que par carte OS (`liveStats` ci-dessous) : un seul cache de détail par
 * réglage (`detailCache`), partagé par la file de priorité, la liste de politiques et la table,
 * pour ne jamais refetcher deux fois le même couple device/politique.
 */

// Retire un préfixe d'organisation entre crochets, quel qu'il soit ("[ORG] Windows - …"), suivi
// de l'OS — convention de nommage courante des politiques Intune, pas propre à un tenant.
const OS_NAME_PREFIX_RE = /^\[[^\]]+\]\s*(Android|Windows|macOS|iOS|Linux)\s*-\s*/i;

function shortPolicyName(displayName) {
  return (displayName || "").replace(OS_NAME_PREFIX_RE, "");
}

/** Chemin SVG ligne + aire (fermée sur la base) pour un tracé de tendance, dans une zone w×h —
 * renvoie un `<path>` refermé pour permettre un remplissage en dégradé (jauge/aire). */
function buildTrendPaths(values, w, h) {
  if (!values || values.length === 0) return null;
  if (values.length === 1) {
    const y = h / 2;
    return { line: `M0,${y} L${w},${y}`, area: `M0,${y} L${w},${y} L${w},${h} L0,${h} Z` };
  }
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - ((v - min) / span) * h;
    return [x, y];
  });
  const line = "M" + pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" L");
  return { line, area: `${line} L${w.toFixed(1)},${h} L0,${h} Z` };
}

/** `goodWhenUp` sépare le SENS ("une hausse est-elle une bonne nouvelle ?") de l'UNITÉ
 * affichée (`suffix`) — les deux étaient conflées dans un seul prop `tone` au premier jet,
 * ce qui colorait à tort en rouge une hausse du taux de conformité (toujours une bonne
 * nouvelle) faute de tone "up-good" explicite. */
function TrendArrowBadge({ delta, goodWhenUp = true, suffix = "" }) {
  if (delta == null) return null;
  const up = delta > 0;
  const good = delta === 0 ? null : goodWhenUp ? up : !up;
  const color = good == null ? "var(--ink-dim)" : good ? "var(--low)" : "var(--high)";
  return (
    <span className="hero-delta" style={{ color }}>
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {up ? <path d="M10 15V5M5 10l5-5 5 5" /> : <path d="M10 5v10M5 10l5 5 5-5" />}
      </svg>
      {delta > 0 ? "+" : ""}
      {delta}
      {suffix}
    </span>
  );
}

export default function IntuneTab({ data }) {
  const compliance = useComplianceDetail();
  const history = useHistoryTrend();
  const intuneError = isErrorPayload(data.intuneSummary) ? data.intuneSummary : null;

  const [tableFilter, setTableFilter] = useState({ os: "all", policyId: null });
  const [expandedPolicyKey, setExpandedPolicyKey] = useState(null);

  // Cache par couple device×politique PARTAGÉ par toute la page (file de priorité, liste de
  // politiques, table) — un seul endroit qui fetch/mémorise le détail par réglage, plus jamais
  // par carte OS séparée comme avant.
  const [openRowKey, setOpenRowKey] = useState(null);
  const [detailCache, setDetailCache] = useState({});
  const requestedRef = useRef(new Set());

  function fetchDetail(entry) {
    const { key, policy, device } = entry;
    if (!device.deviceId || requestedRef.current.has(key)) return;
    requestedRef.current.add(key);
    setDetailCache((prev) => ({ ...prev, [key]: { loading: true } }));
    api
      .deviceComplianceStatus(device.deviceId, policy.id)
      .then((result) => {
        if (Array.isArray(result)) {
          setDetailCache((prev) => ({ ...prev, [key]: { settings: result } }));
        } else {
          setDetailCache((prev) => ({ ...prev, [key]: { error: result?.message || tr("common.unknownError") } }));
        }
      })
      .catch((err) => setDetailCache((prev) => ({ ...prev, [key]: { error: err.message } })));
  }

  function toggleRow(entry) {
    setOpenRowKey((prev) => (prev === entry.key ? null : entry.key));
    fetchDetail(entry);
  }

  function focusTable(os, policyId) {
    setTableFilter({ os, policyId });
    // `setTimeout(…, 0)` plutôt que `requestAnimationFrame` : ce dernier ne se déclenche pas
    // de façon fiable sur un onglet en arrière-plan/non composité (constaté en testant cette
    // session — voir CLAUDE.md, piège déjà documenté pour ce même environnement de test) ;
    // un timer classique, lui, ne dépend pas du cycle de peinture.
    setTimeout(() => {
      document.getElementById("compliance-table-section")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 0);
  }

  const {
    osGroups,
    distinctDevices,
    retrievedTotal,
    aggregateTotal,
    placeholderRows,
    resolvedFromPlaceholders,
    unresolvedPlaceholderRows,
    reclassifiedByDeviceState,
    platformMismatchCount,
    unverifiedCandidates,
    placeholderOnlyPolicies,
    missingPolicies,
    byCategory,
  } = useMemo(() => groupComplianceDetailByOS(compliance.complianceDetail), [compliance.complianceDetail]);
  const unavailablePolicies = compliance.complianceDetail?.unavailablePolicies || [];

  // Toutes les occurrences device × politique, toutes catégories confondues (même structure
  // que l'ex-`allEntries` d'`OsCard`, mais TOUS les groupes OS aplatis en une seule fois).
  const allEntries = useMemo(() => {
    const list = [];
    (osGroups || []).forEach((g) => {
      g.policies.forEach((p) => {
        p.devices.forEach((d, i) => {
          list.push({ key: `${g.os}::${p.id}::${i}`, os: g.os, policy: p, device: d });
        });
      });
    });
    return list;
  }, [osGroups]);

  const failingEntries = useMemo(
    () => allEntries.filter((e) => FAILING_CATEGORIES.includes(e.device.complianceCategory || "Non conforme")),
    [allEntries]
  );

  // Exclut les occurrences reclassées "conforme" en direct (détail par réglage) — même
  // garde-fou que l'ex-`visibleEntries` d'`OsCard`.
  const visibleFailingEntries = useMemo(
    () =>
      failingEntries.filter((e) => {
        if (!e.device.deviceId) return true;
        return computeSettingsState(detailCache[e.key]) !== "compliant";
      }),
    [failingEntries, detailCache]
  );

  // Total "en direct" (page entière + par OS) — même algorithme que l'ex-`liveCount` d'`OsCard`
  // ("un device ne sort du compte que si TOUTES ses occurrences en échec sont vérifiées
  // conformes"), étendu au niveau page plutôt que par carte.
  const liveStats = useMemo(() => {
    const perDevice = new Map();
    allEntries.forEach((entry) => {
      const { os, device: d, key } = entry;
      const dedupeKey = `${os}::${(d.deviceName || "").trim().toLowerCase() || d.deviceId}`;
      const cat = d.complianceCategory || "Non conforme";
      const isEntryFailing = FAILING_CATEGORIES.includes(cat);
      const resolvedCompliant = isEntryFailing && d.deviceId && computeSettingsState(detailCache[key]) === "compliant";
      const prev = perDevice.get(dedupeKey) || { os, worstCat: cat, stillFailing: false };
      const worstCat = SEVERITY.indexOf(cat) < SEVERITY.indexOf(prev.worstCat) ? cat : prev.worstCat;
      const stillFailing = prev.stillFailing || (isEntryFailing && !resolvedCompliant);
      perDevice.set(dedupeKey, { os, worstCat, stillFailing });
    });
    const byOs = {};
    let total = 0;
    perDevice.forEach(({ os, worstCat, stillFailing }) => {
      if (FAILING_CATEGORIES.includes(worstCat) && stillFailing) {
        byOs[os] = (byOs[os] || 0) + 1;
        total += 1;
      }
    });
    return { total, byOs };
  }, [allEntries, detailCache]);

  // Politiques classées par impact, tous OS aplatis, triées par nombre d'occurrences en échec.
  const rankedPolicies = useMemo(() => {
    const list = [];
    (osGroups || []).forEach((g) => {
      g.policies.forEach((p) => {
        list.push({ os: g.os, id: p.id, key: `${g.os}::${p.id}`, displayName: p.displayName, count: p.count, devices: p.devices });
      });
    });
    return list.sort((a, b) => b.count - a.count);
  }, [osGroups]);

  const topPolicy = rankedPolicies[0] || null;

  // File "À traiter en priorité" — postes en échec depuis le plus longtemps (pas de notion de
  // sévérité par politique côté Intune/Graph, donc classement par ancienneté plutôt qu'une
  // criticité inventée).
  const priorityQueue = useMemo(() => {
    return visibleFailingEntries
      .slice()
      .sort((a, b) => {
        const ta = a.device.lastReportedDateTime ? new Date(a.device.lastReportedDateTime).getTime() : 0;
        const tb = b.device.lastReportedDateTime ? new Date(b.device.lastReportedDateTime).getTime() : 0;
        return ta - tb; // plus ancien d'abord
      })
      .slice(0, 5);
  }, [visibleFailingEntries]);

  const historyTrend = useMemo(() => computeHistoryTrend(history.points, 90), [history.points]);

  if (intuneError) {
    return (
      <div className="card">
        <div className="card-head">
          <h2>{tr("compliance.title")}</h2>
        </div>
        <p className="error-note">{intuneError.message}</p>
      </div>
    );
  }

  const complianceRatePct = (() => {
    const v = parseFloat(data.intuneSummary?.complianceRate);
    return Number.isNaN(v) ? null : v;
  })();
  const gaugeLevel = complianceRatePct != null ? secureScoreLevel(complianceRatePct) : null;
  const gaugeCircumference = 2 * Math.PI * 54;
  const gaugeOffset =
    complianceRatePct != null ? gaugeCircumference * (1 - Math.max(0, Math.min(100, complianceRatePct)) / 100) : gaugeCircumference;

  const totalDevices = data.intuneSummary?.totalDevices ?? null;
  // `compliantCount` vient du backend (2026-10-21, taux STRICT : seuls les appareils
  // `compliant`, voir intune/devices.py::get_intune_summary) — plus `total - nonCompliant`,
  // qui comptait les appareils en période de grâce et inconnus comme conformes.
  const compliantCount = data.intuneSummary?.compliantCount ?? null;

  const policiesTotal = data.policySummary ? data.policySummary.length : null;
  const scannedPolicies = compliance.complianceDetail?.scannedPolicies;
  const policiesOsCounts = (osGroups || []).map((g) => ({ os: g.os, count: g.policies.length }));

  const nonCompliantSpark = buildTrendPaths(historyTrend.intuneNonCompliant.series, 240, 46);
  const trendChart = buildTrendPaths(historyTrend.intune.series, 300, 92);

  // Répartition par OS (rail) : total du parc par OS (get_intune_summary().byOperatingSystem,
  // fleet entier — voir intune/devices.py) vs non conformes EN DIRECT (liveStats.byOs) — deux
  // sources différentes, comme partout ailleurs sur cette page, jamais mélangées sans le dire.
  const byOperatingSystem = data.intuneSummary?.byOperatingSystem || {};
  const osSplitRows = Object.entries(byOperatingSystem)
    .filter(([, total]) => total > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([os, total]) => ({ os, total, nonCompliant: liveStats.byOs[os] || 0 }));

  // Rendu en pastilles colorées par OS (2026-08-31, retour de Nicolas : "tu peux pas me mettre
  // les android, windows et macOS pas dans le même format") plutôt qu'une seule ligne de texte
  // gris uniforme — même motif `.os-dots`/`.os-dot-chip` déjà utilisé par la tuile "Politiques
  // suivies" juste à côté (policiesOsCounts, plus bas), pas un nouveau composant.
  const nonCompliantByOs = Object.entries(liveStats.byOs)
    .sort((a, b) => b[1] - a[1])
    .map(([os, n]) => ({ os, n }));

  return (
    <>
      {/* ── Hero : score de posture + tendance non-conformes + politiques suivies ── */}
      <section className="hero-grid">
        <div className="card posture-card">
          <div className="gauge-wrap">
            <svg viewBox="0 0 128 128">
              <circle className="gauge-track" cx="64" cy="64" r="54" />
              {complianceRatePct != null && (
                <circle
                  className="gauge-value"
                  cx="64"
                  cy="64"
                  r="54"
                  stroke={gaugeLevel?.color || "var(--low)"}
                  style={{ filter: `drop-shadow(0 0 10px ${gaugeLevel?.color || "#48c98a"}88)` }}
                  strokeDasharray={gaugeCircumference}
                  strokeDashoffset={gaugeOffset}
                />
              )}
            </svg>
            <div className="gauge-center">
              <span className="num">{complianceRatePct != null ? complianceRatePct.toLocaleString(currentLocale(), { minimumFractionDigits: 1, maximumFractionDigits: 1 }) : "—"}</span>
              <span className="pct">{tr("compliance.pctCompliant")}</span>
            </div>
          </div>
          <div className="posture-detail">
            <p className="lbl">{tr("compliance.rateWholeFleet")}</p>
            <div className="posture-trend">
              <TrendArrowBadge delta={historyTrend.intune.delta30} goodWhenUp suffix=" pt" />
              <span className="period">{tr("compliance.vs30")}</span>
            </div>
            <p className="posture-sub">
              {compliantCount != null && totalDevices != null ? (
                <>
                  {trRich("compliance.compliantOfTracked", { compliant: <strong>{compliantCount}</strong>, total: <strong>{totalDevices}</strong> })}{" "}
                </>
              ) : null}
              {!compliance.loading && !compliance.error && (
                <>
                  {trRich("compliance.realNonCompliance", { n: <strong>{liveStats.total}</strong> })}
                </>
              )}
            </p>
          </div>
        </div>

        <div className="card kpi-card">
          <div className="kpi-top">
            <div>
              <p className="kpi-label">{tr("compliance.nonCompliant")}</p>
              <div className="kpi-value tone-high">{compliance.loading ? "—" : liveStats.total}</div>
            </div>
            <TrendArrowBadge delta={historyTrend.intuneNonCompliant.delta7} goodWhenUp={false} />
          </div>
          {!compliance.loading && nonCompliantByOs.length > 0 && (
            <div className="os-dots">
              {nonCompliantByOs.map(({ os, n }) => (
                <span className="os-dot-chip" key={os}>
                  <span className="dot" style={{ background: OS_COLORS[os] || OS_DEFAULT_COLOR }} />
                  {os} · {n}
                </span>
              ))}
            </div>
          )}
          {nonCompliantSpark && (
            <svg className="spark" viewBox="0 0 240 46" preserveAspectRatio="none">
              <defs>
                <linearGradient id="sparkFillHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="rgba(234,92,92,0.35)" />
                  <stop offset="100%" stopColor="rgba(234,92,92,0)" />
                </linearGradient>
              </defs>
              <line className="spark-grid" x1="0" y1="23" x2="240" y2="23" />
              <path className="area" d={nonCompliantSpark.area} />
              <path className="line" d={nonCompliantSpark.line} />
            </svg>
          )}
        </div>

        <div className="card kpi-card">
          <div className="kpi-top">
            <div>
              <p className="kpi-label">{tr("compliance.trackedPolicies")}</p>
              <div className="kpi-value">{policiesTotal ?? "—"}</div>
            </div>
            {scannedPolicies != null && <span className="kpi-delta-neutral">{tr("compliance.failingCount", { count: scannedPolicies })}</span>}
          </div>
          {policiesTotal != null && scannedPolicies != null && (
            <>
              <p className="kpi-sub">
                {tr("compliance.catalogNoFailure", { pct: Math.round(((policiesTotal - scannedPolicies) / Math.max(policiesTotal, 1)) * 100) })}
              </p>
              <div className="policies-mini-bar">
                <span
                  style={{ width: `${((policiesTotal - scannedPolicies) / Math.max(policiesTotal, 1)) * 100}%`, background: "var(--low)" }}
                  title={tr("compliance.policiesNoFailure", { count: policiesTotal - scannedPolicies })}
                />
                <span
                  style={{ width: `${(scannedPolicies / Math.max(policiesTotal, 1)) * 100}%`, background: "var(--high)" }}
                  title={tr("compliance.policiesWithFailure", { count: scannedPolicies })}
                />
              </div>
              {/* Légende TOUJOURS visible (2026-08-31, retour de Nicolas : "j'ai rien quand je
                  survole" — le `title` HTML posé juste au-dessus ne s'affichait pas de façon
                  fiable dans son navigateur) : les deux chiffres sont maintenant écrits en
                  toutes lettres sous la barre plutôt que de dépendre d'un survol. */}
              <p className="policies-mini-bar-legend">
                <span style={{ color: "var(--low)" }}>{tr("compliance.noFailureCount", { count: policiesTotal - scannedPolicies })}</span>
                {" · "}
                <span style={{ color: "var(--high)" }}>{tr("compliance.failingCount", { count: scannedPolicies })}</span>
              </p>
            </>
          )}
          {policiesOsCounts.length > 0 && (
            <div className="os-dots">
              {policiesOsCounts.map(({ os, count }) => (
                <span className="os-dot-chip" key={os}>
                  <span className="dot" style={{ background: OS_COLORS[os] || OS_DEFAULT_COLOR }} />
                  {os} · {count}
                </span>
              ))}
            </div>
          )}
        </div>
      </section>

      {compliance.loading ? (
        <OsGridSkeleton />
      ) : compliance.error ? (
        <p className="error-note">{compliance.error}</p>
      ) : (
        <>
          {/* ── File "À traiter en priorité" ── */}
          {priorityQueue.length > 0 && (
            <section className="priority-section">
              <div className="priority-head">
                <h2>{tr("compliance.priority")}</h2>
                <span className="note">{tr("compliance.priorityNote")}</span>
              </div>
              <div className="priority-row">
                {priorityQueue.map((entry) => {
                  const color = POLICY_STATUS_COLORS[entry.device.status] || POLICY_STATUS_COLORS.nonCompliant;
                  return (
                    <button
                      key={entry.key}
                      type="button"
                      className="priority-card"
                      style={{ borderLeftColor: color }}
                      onClick={() => focusTable(entry.os, entry.policy.id)}
                    >
                      <div className="priority-card-top">
                        <span className="priority-device">{entry.device.deviceName || "—"}</span>
                        <span className="os-badge" style={{ color: OS_COLORS[entry.os] || OS_DEFAULT_COLOR, background: `${OS_COLORS[entry.os] || OS_DEFAULT_COLOR}24` }}>
                          {entry.os}
                        </span>
                      </div>
                      <p className="priority-policy">{shortPolicyName(entry.policy.displayName)}</p>
                      <div className="priority-meta">
                        <span className="age" style={{ color }}>
                          {formatRelativeDays(entry.device.lastReportedDateTime)}
                        </span>
                        <span>{entry.device.userPrincipalName || "—"}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </section>
          )}

          {/* ── Colonne principale (politiques par impact) + rail (répartition OS, tendance,
              correctif recommandé, réconciliation repliée) ── */}
          <div className="main-layout">
            <div className="main-col">
              <div className="card policy-card">
                <div className="card-head">
                  <h2>{tr("compliance.rankedPolicies")}</h2>
                </div>
                <p className="card-note" style={{ marginTop: 8 }}>
                  {tr("compliance.rankedPoliciesNote", { count: rankedPolicies.length })}
                </p>

                {rankedPolicies.length === 0 ? (
                  <p className="empty" style={{ marginTop: 14 }}>
                    {tr("compliance.noFailingPolicy")}
                  </p>
                ) : (
                  <div className="policy-list">
                    {rankedPolicies.map((p, i) => {
                      const total = byOperatingSystem[p.os];
                      const pctOfOs = total ? Math.min(100, (p.count / total) * 100) : null;
                      const open = expandedPolicyKey === p.key;
                      const previewDevices = p.devices
                        .filter((d) => FAILING_CATEGORIES.includes(d.complianceCategory || "Non conforme"))
                        .slice(0, 3);
                      const remaining = p.count - previewDevices.length;
                      return (
                        <div className={`policy-row${open ? " open" : ""}`} key={p.key}>
                          <div
                            className="policy-row-top"
                            role="button"
                            tabIndex={0}
                            aria-expanded={open}
                            onClick={() => setExpandedPolicyKey(open ? null : p.key)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter" || e.key === " ") {
                                e.preventDefault();
                                setExpandedPolicyKey(open ? null : p.key);
                              }
                            }}
                          >
                            <span className="policy-rank">{String(i + 1).padStart(2, "0")}</span>
                            <span className="policy-os-dot" style={{ background: OS_COLORS[p.os] || OS_DEFAULT_COLOR }} />
                            <span className="policy-name" title={p.displayName}>
                              {shortPolicyName(p.displayName)}
                            </span>
                            <span className="policy-count">
                              {p.count}
                              <span className="unit">{tr("compliance.devicesUnit", { count: p.count })}</span>
                            </span>
                            <svg className="policy-chevron" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                              <path d="M7 4l6 6-6 6" />
                            </svg>
                          </div>
                          {pctOfOs != null && (
                            <>
                              <div className="policy-bar-track">
                                <span
                                  className="policy-bar-seg-ok"
                                  style={{ width: `${100 - pctOfOs}%` }}
                                  title={tr("compliance.osCompliantWithPolicy", { count: total - p.count, os: p.os })}
                                />
                                <span
                                  className="policy-bar-seg-bad"
                                  style={{ width: `${pctOfOs}%` }}
                                  title={tr("compliance.osFailingPolicy", { count: p.count, os: p.os })}
                                />
                              </div>
                              <p className="policy-bar-label">
                                {tr("compliance.assignedFailing", { count: p.count, total, os: p.os })}
                              </p>
                            </>
                          )}
                          {open && (
                            <div className="policy-detail">
                              {previewDevices.length === 0 ? (
                                <p className="policy-detail-empty">{tr("compliance.noPolicyDetail")}</p>
                              ) : (
                                previewDevices.map((d, di) => (
                                  <div className="policy-detail-row" key={di}>
                                    <span className="dname">{d.deviceName || "—"}</span>
                                    <span className="duser">{d.userPrincipalName || "—"}</span>
                                    <span
                                      className="status-chip"
                                      style={{
                                        color: POLICY_STATUS_COLORS[d.status] || POLICY_STATUS_COLORS.unknown,
                                        background: `${POLICY_STATUS_COLORS[d.status] || POLICY_STATUS_COLORS.unknown}24`,
                                      }}
                                    >
                                      <span className="dot" style={{ background: POLICY_STATUS_COLORS[d.status] || POLICY_STATUS_COLORS.unknown }} />
                                      {categoryLabel(d.complianceCategory)}
                                    </span>
                                    <span className="duetime">{formatRelativeDays(d.lastReportedDateTime)}</span>
                                  </div>
                                ))
                              )}
                              <button type="button" className="policy-detail-link" onClick={() => focusTable(p.os, p.id)}>
                                {remaining > 0 ? tr("compliance.moreDevices", { count: remaining }) : ""}
                                {tr("compliance.seeFullTable")}
                              </button>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            <aside className="rail-col">
              {osSplitRows.length > 0 && (
                <div className="card">
                  <div className="card-head">
                    <h2>{tr("compliance.byOs")}</h2>
                    {/* Légende TOUJOURS visible (2026-08-31, retour de Nicolas : "j'ai rien
                        quand je survole" — le `title` posé sur chaque segment ci-dessous ne
                        s'affichait pas de façon fiable dans son navigateur) : plutôt que de
                        répéter la légende sur les 7 lignes, un seul rappel ici en tête de
                        carte — les comptes eux-mêmes restent affichés en clair à droite de
                        chaque barre (`.os-split-count`, déjà présent avant ce correctif). */}
                    <span className="card-note">
                      <span style={{ color: "var(--low)" }}>{tr("compliance.legendGreen")}</span> {tr("compliance.legendCompliant")}{" "}
                      <span style={{ color: "var(--high)" }}>{tr("compliance.legendRed")}</span> {tr("compliance.legendNonCompliant")}
                    </span>
                  </div>
                  {osSplitRows.map(({ os, total, nonCompliant }) => {
                    const okPct = total > 0 ? ((total - nonCompliant) / total) * 100 : 100;
                    const badPct = 100 - okPct;
                    return (
                      <div className="os-split-row" key={os}>
                        <span className="os-split-label">{os}</span>
                        <div className="os-split-track">
                          {/* `data-tip` + tooltip CSS pur au lieu de `title` (2026-08-31,
                              retour de Nicolas : "ce que je voulais [...] c'est qu'en survol ça
                              me montre le nombre" — le `title` HTML natif posé au tour
                              précédent ne s'affichait pas de façon fiable chez lui ; un
                              tooltip construit en CSS `::after` s'affiche, lui, immédiatement
                              et de façon garantie, sans dépendre du comportement du
                              navigateur). */}
                          <span className="seg-ok" style={{ width: `${okPct}%` }} data-tip={tr("compliance.osCompliant", { count: total - nonCompliant, os })} />
                          <span className="seg-bad" style={{ width: `${badPct}%` }} data-tip={tr("compliance.osNonCompliant", { count: nonCompliant, os })} />
                        </div>
                        <span className="os-split-count">
                          {nonCompliant}/{total}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}

              {trendChart && (
                <div className="card">
                  <div className="card-head">
                    <h2>{tr("compliance.trend90")}</h2>
                  </div>
                  <div className="trend-chart-wrap">
                    <svg viewBox="0 0 300 92" preserveAspectRatio="none">
                      <defs>
                        <linearGradient id="trendFillCompliance" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="rgba(72,201,138,0.30)" />
                          <stop offset="100%" stopColor="rgba(72,201,138,0)" />
                        </linearGradient>
                      </defs>
                      <line x1="0" y1="23" x2="300" y2="23" stroke="var(--line)" strokeWidth="1" />
                      <line x1="0" y1="46" x2="300" y2="46" stroke="var(--line)" strokeWidth="1" />
                      <line x1="0" y1="69" x2="300" y2="69" stroke="var(--line)" strokeWidth="1" />
                      <path fill="url(#trendFillCompliance)" d={trendChart.area} />
                      <path fill="none" stroke="var(--low)" strokeWidth="1.8" d={trendChart.line} />
                    </svg>
                  </div>
                  <div className="trend-legend">
                    <span>
                      {tr("compliance.daysAgo", {
                        value: historyTrend.intune.series[0] != null ? `${historyTrend.intune.series[0].toFixed(1)} %` : "—",
                        days: historyTrend.intune.series.length,
                      })}
                    </span>
                    <span style={{ color: "var(--low)" }}>{tr("compliance.today", { value: complianceRatePct != null ? `${complianceRatePct.toFixed(1)} %` : "—" })}</span>
                  </div>
                </div>
              )}

              {topPolicy && aggregateTotal > 0 && (
                <div className="card quickwin-card">
                  <div className="quickwin-icon">
                    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M10 2.5v3M10 14.5v3M3.5 10h3M13.5 10h3M5.6 5.6l2.1 2.1M12.3 12.3l2.1 2.1M14.4 5.6l-2.1 2.1M7.7 12.3l-2.1 2.1" />
                      <circle cx="10" cy="10" r="2.3" />
                    </svg>
                  </div>
                  <p>
                    <strong>{tr("compliance.recommendedFix")}</strong>
                  </p>
                  <p>
                    {tr("compliance.fixOccurrences", { count: topPolicy.count, policy: shortPolicyName(topPolicy.displayName), os: topPolicy.os })}
                  </p>
                  <p className="impact">
                    {tr("compliance.fixPotential", { pct: Math.round((topPolicy.count / aggregateTotal) * 100), total: aggregateTotal })}
                  </p>
                  <button type="button" className="quickwin-link" onClick={() => focusTable(topPolicy.os, topPolicy.id)}>
                    {tr("compliance.seeDevices", { count: topPolicy.count })}
                    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M7 4l6 6-6 6" />
                    </svg>
                  </button>
                </div>
              )}

              <div className="card">
                <details className="reconcile">
                  <summary>{tr("compliance.readingFigures")}</summary>
                  <p>
                    {trRich("compliance.reconcileIntro", {
                      byState: <strong>{tr("compliance.byStateLabel")}</strong>,
                      devicesEm: <em>{tr("compliance.devicesWord")}</em>,
                      total: totalDevices ?? "?",
                      distinctEm: <em>{tr("compliance.distinctDevicesWord")}</em>,
                      distinct: <strong>{distinctDevices}</strong>,
                      rows: retrievedTotal,
                    })}
                    {aggregateTotal > 0 && (
                      <>
                        {" "}
                        {tr("compliance.aggregateIntro", { total: aggregateTotal })}
                        {aggregateTotal === (byCategory["Non conforme"] || 0) + (byCategory["Erreur"] || 0)
                          ? tr("compliance.aggregateSame")
                          : tr("compliance.aggregateGap", { count: (byCategory["Non conforme"] || 0) + (byCategory["Erreur"] || 0) })}
                      </>
                    )}
                    {reclassifiedByDeviceState > 0 && (
                      <>
                        {" "}
                        {trRich("compliance.reclassified", {
                          count: reclassifiedByDeviceState,
                          n: <strong>{reclassifiedByDeviceState}</strong>,
                          compliantEm: <em>{tr("compliance.compliantWord")}</em>,
                        })}
                      </>
                    )}
                    {platformMismatchCount > 0 && (
                      <>
                        {" "}
                        {trRich("compliance.platformMismatch", {
                          count: platformMismatchCount,
                          n: <strong>{platformMismatchCount}</strong>,
                          platformEm: <em>{tr("compliance.platformWord")}</em>,
                        })}
                      </>
                    )}
                    {unverifiedCandidates > 0 && (
                      <>
                        {" "}
                        {trRich("compliance.unverified", { count: unverifiedCandidates, n: <strong>{unverifiedCandidates}</strong> })}
                      </>
                    )}
                    {placeholderRows > 0 && (
                      <>
                        {" "}
                        {trRich("compliance.placeholders", {
                          count: placeholderRows,
                          n: <strong>{placeholderRows}</strong>,
                          resolved: <strong>{resolvedFromPlaceholders}</strong>,
                        })}
                        {unresolvedPlaceholderRows > 0 && (
                          <>
                            {" "}
                            {trRich("compliance.unresolved", { count: unresolvedPlaceholderRows, n: <strong>{unresolvedPlaceholderRows}</strong> })}
                          </>
                        )}
                      </>
                    )}
                  </p>
                </details>
              </div>

              {(unavailablePolicies.length > 0 || placeholderOnlyPolicies.length > 0 || missingPolicies.length > 0) && (
                <div className="card">
                  <p className="rail-warning-title">{tr("compliance.toCheck")}</p>
                  {unavailablePolicies.length > 0 && (
                    <p className="error-note compliance-unavailable-note">
                      {tr("compliance.unavailablePolicies", { count: unavailablePolicies.length })}{" "}
                      {unavailablePolicies.map((p, i) => (
                        <span key={p.id ?? i}>
                          {i > 0 ? ", " : ""}
                          <strong>{p.displayName}</strong> ({tr("compliance.devicesCount", { count: p.failedCount })})
                        </span>
                      ))}
                      .
                    </p>
                  )}
                  {placeholderOnlyPolicies.length > 0 && (
                    <p className="error-note compliance-unavailable-note">
                      {tr("compliance.placeholderOnly", { count: placeholderOnlyPolicies.length })}{" "}
                      {placeholderOnlyPolicies.map((p, i) => (
                        <span key={p.id ?? i}>
                          {i > 0 ? ", " : ""}
                          <strong>{p.displayName}</strong> ({tr("compliance.announced", { count: p.aggregateFailedCount })})
                        </span>
                      ))}
                      .
                    </p>
                  )}
                  {missingPolicies.length > 0 && (
                    <p className="error-note compliance-unavailable-note">
                      {tr("compliance.missingPolicies", { count: missingPolicies.length })}{" "}
                      {missingPolicies.map((p, i) => (
                        <span key={p.id ?? i}>
                          {i > 0 ? ", " : ""}
                          <strong>{p.displayName}</strong> ({tr("compliance.announced", { count: p.failedCount })})
                        </span>
                      ))}
                      .
                    </p>
                  )}
                </div>
              )}
            </aside>
          </div>

          <ComplianceDeviceTable
            entries={visibleFailingEntries}
            osGroups={osGroups}
            detailCache={detailCache}
            onRowVisible={fetchDetail}
            openRowKey={openRowKey}
            onToggleRow={toggleRow}
            filterOs={tableFilter.os}
            filterPolicyId={tableFilter.policyId}
            onFilterChange={setTableFilter}
          />
        </>
      )}
    </>
  );
}
