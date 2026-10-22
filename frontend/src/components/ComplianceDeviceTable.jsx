import { useEffect, useMemo, useRef, useState } from "react";
import { OS_COLORS, OS_DEFAULT_COLOR, POLICY_STATUS_COLORS, categoryLabel, policyStatusLabel } from "../theme.js";
import { computeSettingsState, DeviceSettingsPanel } from "./ComplianceOsGrid.jsx";
import { currentLocale, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

/**
 * Table de postes en échec, filtrable par OS puis par politique — remplace la grille de
 * cartes par OS de l'ex-`ComplianceOsGrid` (voir ce fichier) dans le cadre de la refonte
 * "Conformité" du 2026-08-28 (maquette validée par Nicolas, inspirée des consoles
 * antivirus/EDR de référence : recherche, filtres par OS/statut, table de postes triable,
 * détail par réglage au clic). Toute la logique de réconciliation Graph/réglages (cache par
 * device×politique, reclassification "conforme" en direct) reste dans IntuneTab.jsx, qui la
 * partage désormais avec la file de priorité et la liste des politiques par impact — ce
 * composant est volontairement "bête" : il reçoit `entries` déjà déduites et filtre/affiche.
 */

function formatDate(iso) {
  if (!iso) return "?";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "?";
  return d.toLocaleString(currentLocale(), { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

/** Une ligne du tableau : ne déclenche `onVisible` (fetch du détail par réglage) qu'à son
 * entrée réelle dans la zone visible du scroll — même mécanique qu'avant (ex-`LogRow`,
 * IntersectionObserver), pour ne jamais fetcher des centaines de couples device/politique
 * d'un coup sur un parc volumineux. */
function DeviceTableRow({ entry, isOpen, cached, onToggle, onVisible }) {
  const { os, policy, device: d } = entry;
  const rowRef = useRef(null);
  const hasFiredRef = useRef(false);

  useEffect(() => {
    const el = rowRef.current;
    if (!el || !d.deviceId) return undefined;
    const observer = new IntersectionObserver(
      (obsEntries) => {
        if (obsEntries.some((e) => e.isIntersecting) && !hasFiredRef.current) {
          hasFiredRef.current = true;
          onVisible();
          observer.disconnect();
        }
      },
      { rootMargin: "200px 0px" }
    );
    observer.observe(el);
    return () => observer.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [d.deviceId]);

  const clickable = Boolean(d.deviceId);
  const settingsState = clickable ? computeSettingsState(cached) : null;
  const displayState = settingsState || d.status;
  const rawLower = (d.status || "").toLowerCase();
  const recalcLower = (settingsState || "").toLowerCase();
  const diverges = settingsState && rawLower && rawLower !== recalcLower;
  const color = POLICY_STATUS_COLORS[displayState] || POLICY_STATUS_COLORS.unknown;
  const osColor = OS_COLORS[os] || OS_DEFAULT_COLOR;
  const infoTitle = diverges
    ? tr("compliance.aggregateDiverges", { status: d.status })
    : cached?.loading
    ? tr("compliance.recalculating")
    : cached?.error
    ? tr("compliance.settingsUnavailable", { error: cached.error })
    : null;

  return (
    <>
      <tr
        className={`compliance-row${clickable ? " clickable" : ""}${isOpen ? " open" : ""}`}
        ref={rowRef}
        onClick={clickable ? onToggle : undefined}
        onKeyDown={
          clickable
            ? (e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onToggle();
                }
              }
            : undefined
        }
        tabIndex={clickable ? 0 : undefined}
        role={clickable ? "button" : undefined}
        aria-expanded={clickable ? isOpen : undefined}
        title={infoTitle || undefined}
      >
        <td className="device-name-cell">
          <span className="status-dot" style={{ background: color }} role="img" aria-label={policyStatusLabel(displayState)} />
          {d.deviceName || "—"}
        </td>
        <td className="user-cell">{d.userPrincipalName || "—"}</td>
        <td>
          <span className="os-badge" style={{ color: osColor, background: `${osColor}24` }}>
            {os}
          </span>
        </td>
        <td className="policy-cell" title={policy.displayName}>
          {policy.displayName}
        </td>
        <td>
          <span className="status-chip" style={{ color, background: `${color}24` }}>
            <span className="dot" style={{ background: color }} />
            {policyStatusLabel(displayState)}
          </span>
        </td>
        <td className="time-cell">{formatDate(d.lastReportedDateTime)}</td>
      </tr>
      {isOpen && (
        <tr className="compliance-detail-row open">
          <td colSpan={6}>
            <div className="compliance-table-detail">
              <DeviceSettingsPanel state={cached || { loading: true }} policyStatus={d.status} policyName={policy.displayName} />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// `key` is the internal category; the label is read in the current language.
const STATUS_OPTIONS = [
  {
    key: "all",
    get label() {
      return tr("common.all");
    },
  },
  {
    key: "Non conforme",
    get label() {
      return categoryLabel("Non conforme");
    },
    color: "#ea5c5c",
  },
  {
    key: "Erreur",
    get label() {
      return categoryLabel("Erreur");
    },
    color: "#e08052",
  },
];

export default function ComplianceDeviceTable({
  entries,
  osGroups,
  detailCache,
  onRowVisible,
  openRowKey,
  onToggleRow,
  filterOs,
  filterPolicyId,
  onFilterChange,
}) {
  const [status, setStatus] = useState("all");
  const [query, setQuery] = useState("");
  const [panelOpenOs, setPanelOpenOs] = useState(null);

  const osOrder = useMemo(() => Object.keys(OS_COLORS), []);
  const osGroupByName = useMemo(() => {
    const map = new Map();
    (osGroups || []).forEach((g) => map.set(g.os, g));
    return map;
  }, [osGroups]);

  // Le filtre OS/politique peut être posé de L'EXTÉRIEUR (file de priorité, politiques par
  // impact, correctif recommandé — tous appellent `onFilterChange` directement, sans passer
  // par `pickOs`) — sans ce useEffect, le panneau restait fermé et la note "Filtré sur…"
  // perdait le nom de la politique (résolu via `activeOsGroup`, qui ne dépendait que de
  // `panelOpenOs`, jamais mis à jour dans ce cas). On resynchronise `panelOpenOs` sur le
  // filtre contrôlé dès qu'il change vers un OS différent de celui déjà affiché.
  useEffect(() => {
    if (filterOs !== "all" && filterOs !== panelOpenOs) {
      setPanelOpenOs(filterOs);
    } else if (filterOs === "all" && panelOpenOs !== null) {
      setPanelOpenOs(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterOs]);

  const statusCounts = useMemo(() => {
    const scoped = filterOs === "all" ? entries : entries.filter((e) => e.os === filterOs);
    const counts = { all: scoped.length, "Non conforme": 0, Erreur: 0 };
    scoped.forEach((e) => {
      const cat = e.device.complianceCategory;
      if (cat === "Non conforme" || cat === "Erreur") counts[cat] += 1;
    });
    return counts;
  }, [entries, filterOs]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries.filter((e) => {
      if (filterOs !== "all" && e.os !== filterOs) return false;
      if (filterPolicyId && e.policy.id !== filterPolicyId) return false;
      if (status !== "all" && e.device.complianceCategory !== status) return false;
      if (q) {
        const haystack = `${e.device.deviceName || ""} ${e.device.userPrincipalName || ""}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [entries, filterOs, filterPolicyId, status, query]);

  function pickOs(os) {
    if (os === "all") {
      onFilterChange({ os: "all", policyId: null });
      setPanelOpenOs(null);
      return;
    }
    onFilterChange({ os, policyId: null });
    setPanelOpenOs(os);
  }

  function pickPolicy(os, policyId) {
    onFilterChange({ os, policyId });
  }

  const activeOsGroup = panelOpenOs ? osGroupByName.get(panelOpenOs) : null;
  const activePolicies = activeOsGroup ? activeOsGroup.policies.slice().sort((a, b) => b.count - a.count) : [];
  const activeOsTotal = activePolicies.reduce((s, p) => s + p.count, 0);

  const filterLabel =
    filterOs === "all"
      ? null
      : filterPolicyId
      ? `${filterOs} — ${activeOsGroup?.policies.find((p) => p.id === filterPolicyId)?.displayName || ""}`
      : tr("compliance.allPolicies", { os: filterOs });

  return (
    <section className="compliance-table-section" id="compliance-table-section">
      <div className="card-head">
        <h2>{tr("compliance.failingTable")}</h2>
      </div>
      <p className="card-note" style={{ marginTop: 8 }}>
        {tr("compliance.tableNote", { count: filtered.length })}
      </p>

      <div className="compliance-table-toolbar">
        <div className="compliance-search-wrap">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="8.6" cy="8.6" r="5.6" />
            <path d="M12.7 12.7 L17.5 17.5" />
          </svg>
          <input
            className="filter-input compliance-search-input"
            type="text"
            placeholder={tr("compliance.searchPlaceholder")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <div className="chip-group">
          {STATUS_OPTIONS.map((opt) => (
            <button
              key={opt.key}
              type="button"
              className={`filter-chip${status === opt.key ? " active" : ""}`}
              onClick={() => setStatus(opt.key)}
            >
              {opt.color && <span className="dot" style={{ background: opt.color }} />}
              {opt.label} · {statusCounts[opt.key] ?? 0}
            </button>
          ))}
        </div>
        <div className="chip-group">
          <button type="button" className={`filter-chip${filterOs === "all" ? " active" : ""}`} onClick={() => pickOs("all")}>
            {tr("compliance.allOs")}
          </button>
          {osOrder.map((os) => (
            <button
              key={os}
              type="button"
              className={`filter-chip${filterOs === os ? " active" : ""}`}
              onClick={() => pickOs(os)}
            >
              <span className="dot" style={{ background: OS_COLORS[os] }} />
              {os}
            </button>
          ))}
        </div>
      </div>

      {panelOpenOs && (
        <div className="os-policy-panel visible">
          <div className="os-policy-panel-head">
            <span className="lbl">
              <span className="dot" style={{ background: OS_COLORS[panelOpenOs] || OS_DEFAULT_COLOR }} />
              {tr("compliance.policiesFor", { os: panelOpenOs })}
            </span>
            <button type="button" className="os-policy-panel-close" onClick={() => setPanelOpenOs(null)}>
              {tr("common.close")}
            </button>
          </div>
          <div className="os-policy-list">
            <button
              type="button"
              className={`os-policy-item all-item${filterPolicyId === null ? " active" : ""}`}
              onClick={() => pickPolicy(panelOpenOs, null)}
            >
              <span className="os-policy-item-name">{tr("compliance.allPoliciesFor", { os: panelOpenOs })}</span>
              <span className="os-policy-item-count">{activeOsTotal}</span>
            </button>
            {activePolicies.length === 0 && (
              <p className="os-policy-empty">
                {tr("compliance.noFailingOnOs", { os: panelOpenOs })}
              </p>
            )}
            {activePolicies.map((p) => (
              <button
                key={p.id}
                type="button"
                className={`os-policy-item${filterPolicyId === p.id ? " active" : ""}`}
                onClick={() => pickPolicy(panelOpenOs, p.id)}
              >
                <span className="os-policy-item-name">{p.displayName}</span>
                <span className="os-policy-item-count">{p.count}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {filterLabel && (
        <p className="active-filter-note visible">
          {trRich("compliance.filteredOn", { label: <strong>{filterLabel}</strong> })}
          <button
            type="button"
            onClick={() => {
              onFilterChange({ os: "all", policyId: null });
              setPanelOpenOs(null);
            }}
          >
            {tr("common.reset")}
          </button>
        </p>
      )}

      {filtered.length === 0 ? (
        <p className="empty" style={{ marginTop: 14 }}>
          {tr("compliance.noMatch")}
        </p>
      ) : (
        <div className="device-table-wrap">
          <table className="device-table">
            <thead>
              <tr>
                <th>{tr("compliance.col.device")}</th>
                <th>{tr("compliance.col.user")}</th>
                <th>{tr("compliance.col.os")}</th>
                <th>{tr("compliance.col.policy")}</th>
                <th>{tr("compliance.col.state")}</th>
                <th>{tr("compliance.col.lastEvaluation")}</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((entry) => (
                <DeviceTableRow
                  key={entry.key}
                  entry={entry}
                  isOpen={openRowKey === entry.key}
                  cached={detailCache[entry.key]}
                  onToggle={() => onToggleRow(entry)}
                  onVisible={() => onRowVisible(entry)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
