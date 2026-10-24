import { useEffect, useMemo, useRef, useState } from "react";
import SortMenu from "../components/SortMenu.jsx";
import { api } from "../api.js";
import { IconDownload } from "../components/icons.jsx";
import { exportVulnerabilitiesToExcel } from "../export.js";
import { isErrorPayload, useVanitasAgents, useVanitasCveAvis } from "../hooks/useDashboardData.js";
import { VanitasWizardShell, fmtDate, severityLabelFr, severityTone } from "./vanitasShared.jsx";
import { CVE_SEVERITY_COLORS } from "../theme.js";
import { currentLocale, tr } from "../i18n/core.js";

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
// "Concerné" (bad) avant "Indéterminé" (warn) avant "Exclu" (good) — le plus urgent d'abord,
// même logique déjà établie pour les cartes de poste ("Applications déployées"/EOL).
const STATUS_ORDER = { bad: 0, warn: 1, good: 2 };

function affectedStatus(versionAffected) {
  if (versionAffected === true) return "bad";
  if (versionAffected === false) return "good";
  return "warn";
}
function affectedLabel(versionAffected) {
  return tr(`vv.affected.${affectedStatus(versionAffected)}`);
}

/** Une carte par poste exposé, dans le détail d'une CVE — même gabarit quel que soit le
 * statut (retour de Nicolas déjà appliqué ailleurs sur ce dashboard : "pk celui en attente est
 * différent de celui qui est réussi ?", voir VanitasEolTab.jsx/"Applications déployées"). */
function DeviceRow({ device }) {
  const status = affectedStatus(device.version_affected);
  return (
    <div className={`vanitas-vuln-device-row ${status}`}>
      <div className="vanitas-vuln-device-main">
        <span className="vanitas-vuln-device-host">{device.hostname}</span>
        <span className={`vanitas-hud-compliance-pill ${status}`}>{affectedLabel(device.version_affected)}</span>
      </div>
      <div className="vanitas-vuln-device-meta">
        <span>{device.product_name}</span>
        <span>v{device.installed_version || "—"}</span>
      </div>
    </div>
  );
}

// Couleur par sévérité CVE — palette PARTAGÉE avec la page Vulnérabilités de Pandore
// (`CVE_SEVERITY_COLORS`, theme.js), jamais une palette propre à cette page.
const SEVERITY_THEME_KEY = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low" };
function severityColor(severity) {
  return CVE_SEVERITY_COLORS[SEVERITY_THEME_KEY[(severity || "").toUpperCase()]] ?? CVE_SEVERITY_COLORS.Unknown;
}

function fmtCvss(score) {
  return score == null ? "—" : Number(score).toLocaleString(currentLocale(), { minimumFractionDigits: 1, maximumFractionDigits: 1 });
}

/**
 * Détail d'une CVE (2026-09-10, maquette validée par Nicolas puis enrichie "description, plan
 * d'action en se basant sur le cert-fr") : produit(s) concerné(s), description/plan d'action tiré
 * d'un avis CERT-FR s'il en existe un (voir `useVanitasCveAvis` / `defender/anssi.py::
 * get_cve_avis` — recherche DIRECTE par CVE, indépendante du rapprochement par nom de logiciel
 * déjà utilisé côté Pandore), et les appareils exposés (filtrables par statut + recherche si la
 * liste est longue). Deux habillages (refonte 2026-10-23) :
 * - `variant="modal"` : popup `VanitasWizardShell`, EXPORTÉE (`CveDetailModal`) et réutilisée
 *   par `VanitasDeviceDetail.jsx` avec `deviceScope` (nom d'hôte) qui masque "Appareils
 *   exposés" — sur la fiche d'UN SEUL poste, cette section serait redondante ;
 * - `variant="panel"` : panneau latéral de la page "Vulnérabilités" (liste + détail).
 */
function CveDetail({ group, onClose, deviceScope, variant }) {
  const avis = useVanitasCveAvis();
  const [statusFilter, setStatusFilter] = useState("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    avis.ensureLoaded(group.cve_id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [group.cve_id]);

  const entry = avis.state[group.cve_id];
  const certfr = entry?.data ?? null;
  const certfrLoading = !entry || entry.loading;

  const counts = useMemo(() => {
    const c = { bad: 0, warn: 0, good: 0 };
    group.devices.forEach((d) => {
      c[affectedStatus(d.version_affected)]++;
    });
    return c;
  }, [group.devices]);

  const sorted = useMemo(
    () =>
      [...group.devices].sort(
        (a, b) => STATUS_ORDER[affectedStatus(a.version_affected)] - STATUS_ORDER[affectedStatus(b.version_affected)]
      ),
    [group.devices]
  );

  const filteredDevices = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sorted.filter((d) => {
      if (statusFilter !== "all" && affectedStatus(d.version_affected) !== statusFilter) return false;
      if (q && !d.hostname.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [sorted, statusFilter, query]);

  function pill(status, label, count) {
    return (
      <button
        type="button"
        className={`vanitas-vuln-pill ${status}${statusFilter === status ? " active" : ""}`}
        aria-pressed={statusFilter === status}
        onClick={() => setStatusFilter(status)}
      >
        <span className="dot" />
        {count} {label}
      </button>
    );
  }

  const products = (
    <div>
      <p className="filter-chip-group-label">{tr("vv.products")}</p>
      <div className="vanitas-vuln-product-list">
        {group.products.map((p) => (
          <div key={`${p.name}-${p.version}`} className="vanitas-vuln-product-row">
            <b>{p.name}</b> <span>{tr("vv.refVersion", { version: p.version || "—" })}</span>
          </div>
        ))}
      </div>
    </div>
  );

  const certfrBlock = (
    <div>
      <p className="filter-chip-group-label">{tr("vv.certfrTitle")}</p>
      {certfrLoading ? (
        <p className="vanitas-hud-empty-note" style={{ padding: "8px 0" }}>
          {tr("vv.certfrLoading")}
        </p>
      ) : certfr ? (
        <div className="vanitas-vuln-certfr-block">
          <div className="vanitas-vuln-certfr-ref-row">
            <span className="vanitas-vuln-certfr-ref">{certfr.certfr_ref}</span>
            <span className="cve-small">{tr("vv.certfrPublished", { date: fmtDate(certfr.published) })}</span>
          </div>
          <div className="vanitas-vuln-certfr-title">{certfr.title}</div>
          {certfr.summary && (
            <>
              <p className="vanitas-vuln-certfr-sub">{tr("vv.summary")}</p>
              <p className="vanitas-vuln-certfr-text">{certfr.summary}</p>
            </>
          )}
          {certfr.solution && (
            <>
              <p className="vanitas-vuln-certfr-sub">{tr("vv.actionPlan")}</p>
              <p className="vanitas-vuln-certfr-solution">{certfr.solution}</p>
            </>
          )}
          <a className="vanitas-vuln-certfr-link" href={certfr.url} target="_blank" rel="noopener noreferrer">
            {tr("vv.originalAdvisory")}
          </a>
        </div>
      ) : (
        <p className="vanitas-hud-empty-note" style={{ padding: "8px 0" }}>
          {tr("vv.noCertfr")}
        </p>
      )}
    </div>
  );

  const devices = !deviceScope && (
    <div>
      <p className="filter-chip-group-label">{tr("vv.exposedDevices", { count: group.devices.length })}</p>
      <div className="vanitas-vuln-summary">
        {pill("all", tr("vv.pill.all"), group.devices.length)}
        {pill("bad", tr("vv.pill.bad", { count: counts.bad }), counts.bad)}
        {pill("warn", tr("vv.pill.warn"), counts.warn)}
        {pill("good", tr("vv.pill.good", { count: counts.good }), counts.good)}
      </div>
      {group.devices.length > 4 && (
        <div className="vanitas-hud-search vanitas-vuln-search">
          <span className="prompt">&gt;</span>
          <input
            type="text"
            placeholder={tr("vv.searchDevice")}
            aria-label={tr("vv.searchDevice")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
          />
        </div>
      )}
      <div className="vanitas-vuln-device-list">
        {filteredDevices.length === 0 ? (
          <p className="vanitas-hud-empty-note" style={{ padding: "8px 0" }}>
            {tr("vv.noDeviceMatch")}
          </p>
        ) : (
          filteredDevices.map((d) => <DeviceRow key={`${d.agentId}-${d.product_name}`} device={d} />)
        )}
      </div>
    </div>
  );

  const nvdLink = (
    <a className="vanitas-vuln-nvd-link" href={`https://nvd.nist.gov/vuln/detail/${group.cve_id}`} target="_blank" rel="noopener noreferrer">
      {tr("vv.viewNvd")}
    </a>
  );

  if (variant === "panel") {
    const color = severityColor(group.severity);
    return (
      <aside className="vvp-card vvp-detail" aria-label={tr("vv.detailAria")} style={{ "--sev": color }}>
        <div className="vvp-detail-head">
          <div className="vvp-detail-title">
            <h2>{group.cve_id}</h2>
            <span className="vvp-sub">{tr("vv.publishedOn", { date: fmtDate(group.published) })}</span>
          </div>
          <span className="vvp-score">CVSS {fmtCvss(group.cvss_score)}</span>
          <span className="vvp-sev">{severityLabelFr(group.severity)}</span>
        </div>
        {products}
        {certfrBlock}
        {devices}
        <div className="vvp-detail-foot">{nvdLink}</div>
      </aside>
    );
  }

  return (
    <VanitasWizardShell onClose={onClose} wide>
      <div className="vanitas-wiz-header">
        <div className="vanitas-wiz-header-icon">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
            <path d="M10 3l8 14H2z" />
            <path d="M10 8v4" />
          </svg>
        </div>
        <div className="vanitas-wiz-header-text">
          <h2>{group.cve_id}</h2>
          <p>Vanitas · {deviceScope ? deviceScope : tr("vv.module")}</p>
        </div>
      </div>

      <div className="vanitas-wiz-body">
        <div className="vanitas-vuln-meta-row">
          <span className="vanitas-vuln-meta-badge">CVSS {group.cvss_score ?? "—"}</span>
          <span className={`vanitas-hud-sev-pill ${severityTone(group.severity)}`}>{severityLabelFr(group.severity)}</span>
          <span className="vanitas-vuln-meta-badge">{tr("vv.publishedOn", { date: fmtDate(group.published) })}</span>
        </div>
        {products}
        {certfrBlock}
        {devices}
        <div className="vanitas-vuln-modal-foot">
          {nvdLink}
          <button type="button" className="vanitas-ghost-btn" onClick={onClose}>
            {tr("vv.close")}
          </button>
        </div>
      </div>
    </VanitasWizardShell>
  );
}

/** Popup de détail d'une CVE — fiche poste Vanitas (voir `CveDetail`). */
export function CveDetailModal(props) {
  return <CveDetail {...props} variant="modal" />;
}

// Ordre naturel de chaque critère (SortMenu) — celui de l'ancien <select>, conservé.
const SORTS = [
  { value: "sev", dir: "desc" },
  { value: "cvss", dir: "desc" },
  { value: "exposed", dir: "desc" },
  { value: "recent", dir: "desc" },
];

/**
 * "Vanitas" > Sécurité > Vulnérabilités (2026-09-09, "toutes les vulnérabilités de tous les
 * postes"). Réécrite le 2026-09-10 (demande de Nicolas — "que ça concerne que les
 * vulnérabilités, les postes sont dans les appareils exposés pas dans le tableau directement") :
 * UNE LIGNE PAR CVE (dédupliquée sur tout le parc), les postes n'apparaissent que dans le détail.
 *
 * Refonte liste + détail (2026-10-23, maquette canvas validée par Nicolas) : bandeau de synthèse
 * (CVE distinctes, répartition par sévérité — légende cliquable —, postes concernés, exposition
 * moyenne), liste filtrable/triable à gauche, détail de la CVE sélectionnée dans un panneau
 * latéral (plus de popup). Classes `.vvp-*`.
 *
 * Pas de route serveur "toutes les vulnérabilités du parc en une fois" côté `endpoint-agent/
 * server/app/routes/vulnerabilities.py` (seulement un agrégat top-N fleet-wide ET un détail par
 * agent) — même limite déjà rencontrée pour "Conformité" (`VanitasComplianceTab.jsx`), résolue
 * par le même motif : un appel `api.vanitas.agentVulnerabilities(id)` par agent connu, en état
 * LOCAL, proportionné à l'échelle de ce projet personnel.
 */
export default function VanitasVulnerabilitiesTab({ vanitasNav }) {
  const agents = useVanitasAgents();
  const [byAgent, setByAgent] = useState({}); // { [agentId]: { status, data: [] } }
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sort, setSort] = useState("sev");
  const [sortDir, setSortDir] = useState("desc");
  const [selectedCveId, setSelectedCveId] = useState(null);
  // Navigation depuis la Vue d'ensemble (2026-09-11) — "Top vulnérabilités" transmet une CVE à
  // sélectionner directement, mais la collecte par agent (byAgent, ci-dessus) est encore en vol
  // au moment du clic : `pendingCveId` retente à chaque mise à jour de `groups` (useEffect plus
  // bas) plutôt que d'échouer silencieusement si la CVE n'est pas encore chargée — même
  // correctif déjà appliqué côté Pandore (VulnerabilitiesTab.jsx::pendingCveQuery, revue de
  // sécurité du 2026-09-02).
  const [pendingCveId, setPendingCveId] = useState(null);
  const detailRef = useRef(null);

  useEffect(() => {
    agents.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    for (const agent of agents.state.data ?? []) {
      if (byAgent[agent.id]) continue;
      setByAgent((prev) => ({ ...prev, [agent.id]: { status: "loading", data: [] } }));
      api.vanitas.agentVulnerabilities(agent.id).then(
        (payload) => {
          if (isErrorPayload(payload)) {
            setByAgent((prev) => ({ ...prev, [agent.id]: { status: "error", data: [] } }));
          } else {
            setByAgent((prev) => ({ ...prev, [agent.id]: { status: "done", data: payload } }));
          }
        },
        () => setByAgent((prev) => ({ ...prev, [agent.id]: { status: "error", data: [] } }))
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents.state.data]);

  // Regroupe par CVE — une ligne = une vulnérabilité, sur TOUT le parc (pas une occurrence
  // poste × CVE). `products` déduplique par (nom, version) : la même CVE peut toucher le même
  // produit à des versions différentes selon les postes.
  const groups = useMemo(() => {
    const byCve = new Map();
    for (const agent of agents.state.data ?? []) {
      const entry = byAgent[agent.id];
      if (entry?.status !== "done") continue;
      for (const v of entry.data) {
        if (!v.cve_id) continue;
        let g = byCve.get(v.cve_id);
        if (!g) {
          g = {
            cve_id: v.cve_id,
            cvss_score: v.cvss_score,
            severity: v.severity,
            published: v.published,
            products: [],
            productKeys: new Set(),
            devices: [],
          };
          byCve.set(v.cve_id, g);
        }
        const productKey = `${v.product_name}::${v.installed_version || ""}`;
        if (!g.productKeys.has(productKey)) {
          g.productKeys.add(productKey);
          g.products.push({ name: v.product_name, version: v.installed_version });
        }
        g.devices.push({
          agentId: agent.id,
          hostname: agent.hostname,
          product_name: v.product_name,
          installed_version: v.installed_version,
          version_affected: v.version_affected,
        });
      }
    }
    return [...byCve.values()];
  }, [agents.state.data, byAgent]);

  // Arrivée depuis la Vue d'ensemble ("Top vulnérabilités") — arme `pendingCveId`, jamais
  // directement `selectedCveId` (la CVE peut ne pas encore être dans `groups`, voir plus bas).
  useEffect(() => {
    if (!vanitasNav?.payload?.cveId) return;
    setPendingCveId(vanitasNav.payload.cveId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vanitasNav?.token]);

  // Retente à chaque mise à jour de `groups` (chaque agent termine sa collecte l'un après
  // l'autre) tant que la CVE demandée n'y est pas encore — s'arrête dès qu'elle y apparaît.
  useEffect(() => {
    if (!pendingCveId) return;
    const found = groups.find((g) => g.cve_id === pendingCveId);
    if (found) {
      setSeverityFilter("all");
      setQuery("");
      setSelectedCveId(pendingCveId);
      setPendingCveId(null);
    }
  }, [groups, pendingCveId]);

  const severityCounts = useMemo(() => {
    const counts = { all: groups.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const g of groups) {
      const s = (g.severity || "").toUpperCase();
      if (counts[s] !== undefined) counts[s]++;
    }
    return counts;
  }, [groups]);

  const [exportState, setExportState] = useState({ status: "idle", error: null });
  async function handleExport() {
    setExportState({ status: "exporting", error: null });
    try {
      await exportVulnerabilitiesToExcel(groups);
      setExportState({ status: "idle", error: null });
    } catch (err) {
      setExportState({ status: "idle", error: err.message || tr("v.exportFailed") });
    }
  }

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = groups.filter((g) => {
      if (severityFilter !== "all" && (g.severity || "").toUpperCase() !== severityFilter) return false;
      if (!q) return true;
      return g.cve_id.toLowerCase().includes(q) || g.products.some((p) => p.name?.toLowerCase().includes(q));
    });
    const sevRank = (g) => {
      const i = SEVERITY_ORDER.indexOf((g.severity || "").toUpperCase());
      return i === -1 ? SEVERITY_ORDER.length : i;
    };
    const natural = [...filtered].sort((a, b) => {
      if (sort === "cvss") return (b.cvss_score ?? -1) - (a.cvss_score ?? -1);
      if (sort === "exposed") return b.devices.length - a.devices.length || (b.cvss_score ?? -1) - (a.cvss_score ?? -1);
      if (sort === "recent") return new Date(b.published || 0) - new Date(a.published || 0);
      return sevRank(a) - sevRank(b) || (b.cvss_score ?? -1) - (a.cvss_score ?? -1);
    });
    const naturalDir = SORTS.find((s) => s.value === sort)?.dir ?? "desc";
    return sortDir === naturalDir ? natural : natural.reverse();
  }, [groups, query, severityFilter, sort, sortDir]);

  const affectedHostCount = useMemo(() => {
    const hosts = new Set();
    groups.forEach((g) => g.devices.forEach((d) => hosts.add(d.hostname)));
    return hosts.size;
  }, [groups]);
  const avgExposure = groups.length
    ? (groups.reduce((sum, g) => sum + g.devices.length, 0) / groups.length).toLocaleString(currentLocale(), {
        minimumFractionDigits: 1,
        maximumFractionDigits: 1,
      })
    : "0";

  const selectedGroup = rows.find((g) => g.cve_id === selectedCveId) ?? rows[0] ?? null;

  function selectCve(id) {
    setSelectedCveId(id);
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  const loading = agents.state.status === "loading";
  const stillCollecting = (agents.state.data ?? []).some((a) => byAgent[a.id]?.status === "loading");
  const error = agents.state.error;

  if (loading) {
    return (
      <div className="vanitas-hud vvp">
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      </div>
    );
  }

  const agentTotal = (agents.state.data ?? []).length;
  const presentSeverities = SEVERITY_ORDER.filter((s) => severityCounts[s] > 0);

  return (
    <div className="vanitas-hud vvp">
      {error && <p className="vanitas-hud-error">{error}</p>}

      <section className="vvp-card vvp-sum" aria-label={tr("vv.sumAria")}>
        <div className="vvp-sum-col">
          <span className="vvp-lbl">{tr("vv.kpi.distinct")}</span>
          <span className="vvp-val accent">{groups.length}</span>
          <span className="vvp-sub vvp-small">{stillCollecting ? tr("vv.collecting") : tr("vv.fleetWide")}</span>
        </div>
        <div className="vvp-sum-sev">
          <span className="vvp-lbl">{tr("vv.bySeverity")}</span>
          <span
            className="vvp-sum-bar"
            role="img"
            aria-label={presentSeverities.map((s) => tr(`vv.leg.${s}`, { count: severityCounts[s] })).join(", ")}
          >
            {presentSeverities.map((s) => (
              <i key={s} style={{ flex: severityCounts[s], background: severityColor(s) }} />
            ))}
          </span>
          <div className="vvp-legend">
            {presentSeverities.length === 0
              ? <span className="vvp-sub">—</span>
              : presentSeverities.map((s) => (
                  <button key={s} type="button" className="vvp-leg" onClick={() => setSeverityFilter(s)}>
                    <i style={{ background: severityColor(s) }} />
                    {tr(`vv.leg.${s}`, { count: severityCounts[s] })}
                  </button>
                ))}
          </div>
        </div>
        <div className="vvp-sum-col vvp-sum-third">
          <span className="vvp-lbl">{tr("vv.kpi.affected")}</span>
          <span className="vvp-val">
            {affectedHostCount} <small>/ {agentTotal}</small>
          </span>
          <span className="vvp-sub vvp-small">{tr("vv.atLeastOne")}</span>
        </div>
        <div className="vvp-sum-col vvp-sum-fourth">
          <span className="vvp-lbl">{tr("vv.kpi.avg")}</span>
          <span className="vvp-val">{avgExposure}</span>
          <span className="vvp-sub vvp-small">{tr("vv.perCve")}</span>
        </div>
      </section>

      <div className="vvp-split">
        <section className="vvp-card vvp-list" aria-label={tr("vv.listTitle")}>
          <div className="vvp-list-head">
            <h2 className="vvp-h2">{tr("vv.listTitle")}</h2>
            <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting"}>
              <IconDownload />
              {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
            </button>
          </div>
          {exportState.error && <p className="error-note" style={{ margin: 0 }}>{exportState.error}</p>}
          <div className="vvp-toolbar">
            <label className="vvp-search-wrap">
              <span className="vvp-sr">{tr("vv.searchShort")}</span>
              <input type="search" className="vvp-search" placeholder={tr("vv.searchShort")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
            </label>
            <SortMenu
              options={SORTS.map((s) => ({ ...s, label: tr(`vv.sort.${s.value}`), hint: tr(`vv.sortHint.${s.value}`) }))}
              value={sort}
              dir={sortDir}
              onChange={(v, d) => {
                setSort(v);
                setSortDir(d);
              }}
            />
          </div>
          <div className="vvp-chips" role="group" aria-label={tr("vv.sevAria")}>
            <button type="button" className={`vvp-chip${severityFilter === "all" ? " on" : ""}`} aria-pressed={severityFilter === "all"} onClick={() => setSeverityFilter("all")}>
              {tr("vv.allF")} <b>{severityCounts.all}</b>
            </button>
            {SEVERITY_ORDER.map((s) => (
              <button key={s} type="button" className={`vvp-chip${severityFilter === s ? " on" : ""}`} aria-pressed={severityFilter === s} onClick={() => setSeverityFilter(s)}>
                <span className="dot" style={{ background: severityColor(s) }} />
                {severityLabelFr(s)} <b>{severityCounts[s]}</b>
              </button>
            ))}
          </div>

          {agentTotal === 0 ? (
            <p className="vvp-empty">{tr("vv.noAgent")}</p>
          ) : rows.length === 0 ? (
            <p className="vvp-empty">{groups.length === 0 ? (stillCollecting ? tr("vv.collecting") : tr("vv.noVuln")) : tr("vv.noResult")}</p>
          ) : (
            <div className="vvp-rows">
              {rows.map((g) => {
                const isSel = selectedGroup?.cve_id === g.cve_id;
                return (
                  <button
                    key={g.cve_id}
                    type="button"
                    className={`vvp-cve${isSel ? " sel" : ""}`}
                    style={{ "--sev": severityColor(g.severity) }}
                    aria-pressed={isSel}
                    onClick={() => selectCve(g.cve_id)}
                  >
                    <span className="vvp-cve-stripe" />
                    <span className="vvp-cve-id">{g.cve_id}</span>
                    <span className="vvp-score">{fmtCvss(g.cvss_score)}</span>
                    <span className="vvp-cve-meta">
                      <span className="vvp-ink">{g.products.map((p) => p.name).join(", ")}</span>
                      <span>·</span>
                      <span>{severityLabelFr(g.severity)}</span>
                      <span>·</span>
                      <span>{tr("vv.endpoints", { count: g.devices.length })}</span>
                      <span>·</span>
                      <span>{tr("vv.publishedLower", { date: fmtDate(g.published) })}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        <div ref={detailRef} className="vvp-detail-slot">
          {selectedGroup ? (
            <CveDetail key={selectedGroup.cve_id} group={selectedGroup} variant="panel" />
          ) : (
            <div className="vvp-card vvp-empty-panel">
              <p className="vvp-sub">{tr("vv.pickCve")}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
