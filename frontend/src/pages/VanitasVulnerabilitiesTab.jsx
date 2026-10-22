import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { IconDownload } from "../components/icons.jsx";
import { exportVulnerabilitiesToExcel } from "../export.js";
import { isErrorPayload, useVanitasAgents, useVanitasCveAvis } from "../hooks/useDashboardData.js";
import { VanitasWizardShell, fmtDate, severityLabelFr, severityTone } from "./vanitasShared.jsx";
import { tr } from "../i18n/core.js";

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

/**
 * Popup de détail d'une CVE (2026-09-10, maquette validée par Nicolas puis enrichie
 * "description, plan d'action en se basant sur le cert-fr") — même chrome `VanitasWizardShell`
 * que les autres popups Vanitas. Trois sections : produit(s) concerné(s), description/plan
 * d'action tiré d'un avis CERT-FR s'il en existe un (voir `useVanitasCveAvis` /
 * `defender/anssi.py::get_cve_avis` — recherche DIRECTE par CVE, indépendante du rapprochement
 * par nom de logiciel déjà utilisé côté Pandore), et les appareils exposés (filtrables par
 * statut + recherche si la liste est longue).
 *
 * EXPORTÉE (2026-09-11) et réutilisée TELLE QUELLE par `VanitasDeviceDetail.jsx` — même motif
 * déjà établi côté Pandore (`VulnerabilitiesTab.jsx::CveDetailModal` réutilisée par
 * `DeviceOverviewTab.jsx` avec une prop `deviceScope`) : `deviceScope` (nom d'hôte) masque la
 * section "Appareils exposés" — sur la fiche d'UN SEUL poste, cette section serait redondante
 * (le lecteur est déjà sur ce poste) — le reste (produits concernés, description/plan CERT-FR,
 * lien NVD) reste identique dans les deux contextes.
 */
export function CveDetailModal({ group, onClose, deviceScope }) {
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
        onClick={() => setStatusFilter(status)}
      >
        <span className="dot" />
        {count} {label}
      </button>
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

        {!deviceScope && (
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
        )}

        <div className="vanitas-vuln-modal-foot">
          <a
            className="vanitas-vuln-nvd-link"
            href={`https://nvd.nist.gov/vuln/detail/${group.cve_id}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            {tr("vv.viewNvd")}
          </a>
          <button type="button" className="vanitas-ghost-btn" onClick={onClose}>
            {tr("vv.close")}
          </button>
        </div>
      </div>
    </VanitasWizardShell>
  );
}

/**
 * "Vanitas" > Sécurité > Vulnérabilités (2026-09-09, "toutes les vulnérabilités de tous les
 * postes"). Réécrite le 2026-09-10 (demande de Nicolas — "que ça concerne que les
 * vulnérabilités, les postes sont dans les appareils exposés pas dans le tableau directement" ;
 * maquette validée puis enrichie d'une description/plan d'action CERT-FR) : la table liste
 * maintenant UNE LIGNE PAR CVE (dédupliquée sur tout le parc), les postes n'apparaissent plus
 * qu'en cliquant une ligne — popup `CveDetailModal` ci-dessus.
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
  const [selectedCveId, setSelectedCveId] = useState(null);
  // Navigation depuis la Vue d'ensemble (2026-09-11) — "Top vulnérabilités" transmet une CVE à
  // ouvrir directement, mais la collecte par agent (byAgent, ci-dessus) est encore en vol au
  // moment du clic : `pendingCveId` retente à chaque mise à jour de `groups` (useEffect plus
  // bas) plutôt que d'échouer silencieusement si la CVE n'est pas encore chargée — même
  // correctif déjà appliqué côté Pandore (VulnerabilitiesTab.jsx::pendingCveQuery, revue de
  // sécurité du 2026-09-02).
  const [pendingCveId, setPendingCveId] = useState(null);

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
  // poste × CVE comme avant cette réécriture). `products` déduplique par (nom, version) : la
  // même CVE peut toucher le même produit à des versions différentes selon les postes.
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
      return (
        g.cve_id.toLowerCase().includes(q) ||
        g.products.some((p) => p.name?.toLowerCase().includes(q))
      );
    });
    return [...filtered].sort((a, b) => {
      const sa = SEVERITY_ORDER.indexOf((a.severity || "").toUpperCase());
      const sb = SEVERITY_ORDER.indexOf((b.severity || "").toUpperCase());
      const ra = sa === -1 ? SEVERITY_ORDER.length : sa;
      const rb = sb === -1 ? SEVERITY_ORDER.length : sb;
      if (ra !== rb) return ra - rb;
      return (b.cvss_score ?? -1) - (a.cvss_score ?? -1);
    });
  }, [groups, query, severityFilter]);

  const affectedHostCount = useMemo(() => {
    const hosts = new Set();
    groups.forEach((g) => g.devices.forEach((d) => hosts.add(d.hostname)));
    return hosts.size;
  }, [groups]);
  const highOrCriticalCount = severityCounts.CRITICAL + severityCounts.HIGH;
  const avgExposure = groups.length
    ? (groups.reduce((sum, g) => sum + g.devices.length, 0) / groups.length).toFixed(1)
    : "0";

  const selectedGroup = selectedCveId ? groups.find((g) => g.cve_id === selectedCveId) ?? null : null;

  const loading = agents.state.status === "loading";
  const stillCollecting = (agents.state.data ?? []).some((a) => byAgent[a.id]?.status === "loading");
  const error = agents.state.error;

  if (loading) {
    return (
      <div className="vanitas-hud">
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      </div>
    );
  }

  return (
    <div className="vanitas-hud">
      {error && <p className="vanitas-hud-error">{error}</p>}

      <div className="vanitas-hud-strip">
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-accent)" }}>
          <div className="label">
            {tr("vv.kpi.distinct")}<span className="tag">{tr("vv.kpi.fleet")}</span>
          </div>
          <div className="value">{groups.length}</div>
          <div className="bar">
            <i style={{ width: groups.length ? "100%" : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-high)" }}>
          <div className="label">
            {tr("vv.kpi.highCrit")}<span className="tag">≥ HIGH</span>
          </div>
          <div className="value">{highOrCriticalCount}</div>
          <div className="bar">
            <i style={{ width: groups.length ? `${Math.round((highOrCriticalCount / groups.length) * 100)}%` : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-accent2)" }}>
          <div className="label">
            {tr("vv.kpi.affected")}<span className="tag">{tr("vv.kpi.total")}</span>
          </div>
          <div className="value">{affectedHostCount}</div>
          <div className="bar">
            <i
              style={{
                width: (agents.state.data ?? []).length ? `${Math.round((affectedHostCount / agents.state.data.length) * 100)}%` : "0%",
              }}
            />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-good)" }}>
          <div className="label">
            {tr("vv.kpi.avg")}<span className="tag">{tr("vv.kpi.perCve")}</span>
          </div>
          <div className="value">{avgExposure}</div>
          <div className="bar">
            <i style={{ width: groups.length ? "100%" : "0%" }} />
          </div>
        </div>
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>{rows.length} CVE</h2>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <span className="vanitas-hud-card-note">
              {stillCollecting ? tr("vv.collecting") : tr("vv.clickRow")}
            </span>
            <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting"}>
              <IconDownload />
              {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
            </button>
          </div>
        </div>
        {exportState.error && <p className="error-note" style={{ margin: "0 0 12px" }}>{exportState.error}</p>}

        <div className="vanitas-hud-toolbar">
          <div className="vanitas-hud-search">
            <span className="prompt">&gt;</span>
            <input
              type="text"
              placeholder={tr("vv.searchPlaceholder")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoComplete="off"
            />
          </div>
          <div className="vanitas-hud-chips">
            <button type="button" className={`vanitas-hud-chip${severityFilter === "all" ? " active" : ""}`} onClick={() => setSeverityFilter("all")}>
              <span className="led" />
              {tr("vv.all")} <span className="n">{severityCounts.all}</span>
            </button>
            {SEVERITY_ORDER.map((s) => (
              <button
                key={s}
                type="button"
                className={`vanitas-hud-chip${s === "CRITICAL" || s === "HIGH" ? " tone-high" : ""}${severityFilter === s ? " active" : ""}`}
                onClick={() => setSeverityFilter(s)}
              >
                <span className="led" />
                {severityLabelFr(s).toUpperCase()} <span className="n">{severityCounts[s]}</span>
              </button>
            ))}
          </div>
        </div>

        {(agents.state.data ?? []).length === 0 ? (
          <p className="vanitas-hud-empty-note">{tr("vv.noAgent")}</p>
        ) : rows.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            {groups.length === 0 ? tr("vv.noVuln") : tr("vv.noResult")}
          </p>
        ) : (
          <div className="vanitas-hud-table-wrap">
            <table className="vanitas-hud-table vanitas-vuln-table">
              <colgroup>
                <col style={{ width: "16%" }} />
                <col style={{ width: "26%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "14%" }} />
                <col style={{ width: "14%" }} />
                <col style={{ width: "14%" }} />
                <col style={{ width: "6%" }} />
              </colgroup>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>{tr("vv.col.products")}</th>
                  <th>CVSS</th>
                  <th>{tr("vv.col.severity")}</th>
                  <th>{tr("vv.col.published")}</th>
                  <th>{tr("vv.col.exposed")}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((g) => (
                  <tr key={g.cve_id} onClick={() => setSelectedCveId(g.cve_id)} tabIndex={0} role="button">
                    <td className="vanitas-hud-vuln-cve">{g.cve_id}</td>
                    <td>{g.products.map((p) => p.name).join(", ")}</td>
                    <td className="vanitas-hud-cmd-none">{g.cvss_score ?? "—"}</td>
                    <td>
                      <span className={`vanitas-hud-sev-pill ${severityTone(g.severity)}`}>{severityLabelFr(g.severity)}</span>
                    </td>
                    <td className="vanitas-hud-cmd-none">{fmtDate(g.published)}</td>
                    <td>
                      <span className="vanitas-hud-apps-badge">
                        {tr("vv.endpoints", { count: g.devices.length })}
                      </span>
                    </td>
                    <td>
                      <span className="vanitas-hud-chev">›</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedGroup && <CveDetailModal group={selectedGroup} onClose={() => setSelectedCveId(null)} />}
    </div>
  );
}
