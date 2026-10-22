import { useEffect, useMemo, useState } from "react";
import { useDeviceInventory } from "../hooks/useDashboardData.js";
import { COMPLIANCE_COLORS, COMPLIANCE_LABEL, EXPOSURE_LEVEL_COLORS, EXPOSURE_LEVEL_LABEL } from "../theme.js";
import { currentLocale, tr } from "../i18n/core.js";

/**
 * Onglet "Appareil" > "Inventaire" (2026-09-02, maquette validée par Nicolas — "il me faut ton
 * avis pour la page des appareils que proposent les autres solutions [...] l'inventaire des
 * devices" puis "le visuel me convient" puis "tu as pas mis en place l'inventaire des
 * appareils ?", pointant l'oubli après avoir mis en place les 2 autres maquettes) : table
 * fleet-wide inspirée d'Intune admin center ("Tous les appareils")/Defender "Device
 * inventory"/CrowdStrike Host Management — fusionne DEUX listes déjà bon marché
 * (`intune.devices.list_devices`/`defender.machines.list_machines`, un seul appel Graph paginé
 * chacune) réconciliées par nom côté backend (`device_overview.py::get_device_inventory`),
 * AUCUN appel par appareil.
 *
 * Un appareil peut n'exister que dans UN des deux systèmes (`has_intune`/`has_defender`) —
 * affiché quand même avec un badge de source explicite plutôt que masqué, même philosophie que
 * `DeviceOverviewTab.jsx` pour un appareil "absent" d'un des deux côtés.
 *
 * Cliquer une ligne renvoie vers la fiche "Appareil" (vue 360°) déjà existante via
 * `onNavigate("device-overview", name)` (même mécanisme déjà utilisé par "Top devices à
 * risque"/"Nouveaux devices" de la Vue d'ensemble) plutôt que de dupliquer son détail ici.
 */

const STALE_DAYS = 30;

function osBucket(os) {
  const v = (os || "").toLowerCase();
  if (v.includes("windows")) return "Windows";
  if (v.includes("ios") || v.includes("ipad")) return "iOS/iPadOS";
  if (v.includes("android")) return "Android";
  if (v.includes("mac")) return "macOS";
  if (v.includes("linux")) return "Linux";
  return "Autre";
}

function OsIcon({ os }) {
  const bucket = osBucket(os);
  if (bucket === "Windows")
    return (
      <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
        <path d="M2 4.5l7-1v6.3H2V4.5zm8-1.2l8-1.3v7.5h-8V3.3zM2 10.8h7v6.3l-7-1v-5.3zm8 0h8v7.5l-8-1.3v-6.2z" />
      </svg>
    );
  if (bucket === "iOS/iPadOS")
    return (
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
        <rect x="6" y="2" width="8" height="16" rx="2" />
        <path d="M9 16h2" strokeLinecap="round" />
      </svg>
    );
  if (bucket === "Android")
    return (
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
        <path d="M5 8v6M15 8v6M6 7h8v8a1 1 0 01-1 1H7a1 1 0 01-1-1V7z" />
        <path d="M7 7l-1.5-2.5M13 7l1.5-2.5" />
      </svg>
    );
  if (bucket === "macOS")
    return (
      <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
        <path d="M13.5 5c-.9 0-1.9.5-2.5 1.2-.6-.7-1.5-1.2-2.5-1.2C6.3 5 5 6.6 5 9c0 3.3 2.5 7 4.5 7 .8 0 1.1-.5 2-.5s1.2.5 2 .5c1.7 0 3.8-2.9 3.8-5.1-1.6-.6-2-2-2-3.4 0-1-.6-1.8-1.8-2.5z" />
      </svg>
    );
  return (
    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
      <rect x="3" y="4" width="14" height="9" rx="1.5" />
      <path d="M7 16.5h6M10 13v3.5" strokeLinecap="round" />
    </svg>
  );
}

function fmtRelative(value) {
  if (!value) return null;
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return null;
  const diffMs = Date.now() - then;
  const diffH = diffMs / 3_600_000;
  if (diffH < 1) return tr("rel.minutes");
  if (diffH < 24) return tr("rel.hours", { n: Math.round(diffH) });
  return tr("rel.days", { n: Math.round(diffH / 24) });
}

/** Le plus récent des deux horodatages disponibles ("dernière connexion" tous systèmes
 * confondus) — `null` si aucun des deux n'est renseigné. */
function lastSeenAny(row) {
  const a = row.last_sync_intune ? new Date(row.last_sync_intune).getTime() : null;
  const b = row.last_seen_defender ? new Date(row.last_seen_defender).getTime() : null;
  if (a == null && b == null) return null;
  return Math.max(a ?? -Infinity, b ?? -Infinity);
}

function isStale(row) {
  const ts = lastSeenAny(row);
  if (ts == null) return false;
  return (Date.now() - ts) / 86_400_000 > STALE_DAYS;
}

function CompliancePill({ state, hasIntune }) {
  if (!hasIntune) return <span className="device-inv-pill neutral">{tr("inv.notSet")}</span>;
  const color = COMPLIANCE_COLORS[state] || COMPLIANCE_COLORS.unknown;
  return (
    <span className="device-inv-pill" style={{ color, background: `${color}22` }}>
      {COMPLIANCE_LABEL[state] || state || tr("common.unknown")}
    </span>
  );
}

function ExposurePill({ level, hasDefender }) {
  if (!hasDefender) return <span className="device-inv-pill neutral">{tr("inv.notSet")}</span>;
  const color = EXPOSURE_LEVEL_COLORS[level] || EXPOSURE_LEVEL_COLORS.Unknown;
  return (
    <span className="device-inv-pill" style={{ color, background: `${color}22` }}>
      {EXPOSURE_LEVEL_LABEL[level] || level || tr("inv.unknownF")}
    </span>
  );
}

function HealthPill({ status, hasDefender }) {
  if (!hasDefender) return <span className="device-inv-pill neutral">—</span>;
  const tone = status === "Active" ? "ok" : status ? "bad" : "neutral";
  return <span className={`device-inv-pill ${tone}`}>{status || tr("common.unknown")}</span>;
}

// "Tous"/"Autre" are internal OS bucket values (see osBucket); `osFilterLabel` translates them.
const OS_FILTERS = ["Tous", "Windows", "iOS/iPadOS", "Android", "macOS", "Linux", "Autre"];
function osFilterLabel(os) {
  if (os === "Tous") return tr("common.all");
  if (os === "Autre") return tr("inv.osOther");
  return os;
}
// [key, translation key]
const COMPLIANCE_FILTERS = [
  ["all", "inv.allF"],
  ["compliant", "compliance.state.compliant"],
  ["noncompliant", "compliance.state.noncompliant"],
  ["na", "inv.notSet"],
];
const EXPOSURE_FILTERS = [
  ["all", "inv.allF"],
  ["High", "exposure.High"],
  ["Medium", "exposure.Medium"],
  ["Low", "exposure.Low"],
];

export default function DeviceInventoryTab({ onNavigate }) {
  const inventory = useDeviceInventory();
  const [search, setSearch] = useState("");
  const [osFilter, setOsFilter] = useState("Tous");
  const [complianceFilter, setComplianceFilter] = useState("all");
  const [exposureFilter, setExposureFilter] = useState("all");

  useEffect(() => {
    inventory.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const data = inventory.state.data;

  const stats = useMemo(() => {
    if (data.length === 0) return null;
    const nonCompliant = data.filter((d) => d.compliance_state === "noncompliant").length;
    const highExposure = data.filter((d) => d.exposure_level === "High").length;
    const stale = data.filter((d) => isStale(d)).length;
    return { total: data.length, nonCompliant, highExposure, stale };
  }, [data]);

  const osCounts = useMemo(() => {
    const counts = { Tous: data.length };
    for (const d of data) {
      const b = osBucket(d.operating_system);
      counts[b] = (counts[b] || 0) + 1;
    }
    return counts;
  }, [data]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return data.filter((d) => {
      if (q && !d.name.toLowerCase().includes(q) && !(d.user || "").toLowerCase().includes(q)) return false;
      if (osFilter !== "Tous" && osBucket(d.operating_system) !== osFilter) return false;
      if (complianceFilter !== "all") {
        if (complianceFilter === "na" && d.has_intune) return false;
        if (complianceFilter !== "na" && d.compliance_state !== complianceFilter) return false;
      }
      if (exposureFilter !== "all" && d.exposure_level !== exposureFilter) return false;
      return true;
    });
  }, [data, search, osFilter, complianceFilter, exposureFilter]);

  const sorted = useMemo(() => {
    return filtered.slice().sort((a, b) => (lastSeenAny(b) ?? -Infinity) - (lastSeenAny(a) ?? -Infinity));
  }, [filtered]);

  function handleRowClick(name) {
    if (onNavigate) onNavigate("device-overview", name);
  }

  if (inventory.state.status === "loading") {
    return (
      <div className="card">
        <p className="card-note">{tr("inv.loading")}</p>
      </div>
    );
  }
  if (inventory.state.status === "error") {
    return (
      <div className="card">
        <p className="error-note">{inventory.state.error}</p>
      </div>
    );
  }
  if (!stats) {
    return (
      <div className="card">
        <p className="empty">{tr("inv.empty")}</p>
      </div>
    );
  }

  return (
    <div className="device-inv-layout">
      <div className="device-inv-kpi-strip">
        <div className="device-inv-kpi">
          <span className="lbl">{tr("inv.kpi.total")}</span>
          <span className="val">{stats.total.toLocaleString(currentLocale())}</span>
          <span className="note">Intune ∪ Defender</span>
        </div>
        <div className="device-inv-kpi accent-amber">
          <span className="lbl">{tr("inv.kpi.nonCompliant")}</span>
          <span className="val">{stats.nonCompliant.toLocaleString(currentLocale())}</span>
          <span className="note">{tr("inv.kpi.allPolicies")}</span>
        </div>
        <div className="device-inv-kpi accent-star">
          <span className="lbl">{tr("inv.kpi.highExposure")}</span>
          <span className="val">{stats.highExposure.toLocaleString(currentLocale())}</span>
          <span className="note">Defender</span>
        </div>
        <div className="device-inv-kpi accent-low">
          <span className="lbl">{tr("inv.kpi.silent", { days: STALE_DAYS })}</span>
          <span className="val">{stats.stale.toLocaleString(currentLocale())}</span>
          <span className="note">{tr("inv.kpi.noCheckin")}</span>
        </div>
      </div>

      <div className="device-inv-search-block">
        <div className="device-inv-search-input-wrap">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
            <circle cx="9" cy="9" r="6.5" />
            <path d="M18 18l-4.3-4.3" strokeLinecap="round" />
          </svg>
          <input
            className="filter-input device-inv-search-input"
            type="text"
            placeholder={tr("inv.searchPlaceholder")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="device-inv-filter-rows">
          <div className="device-inv-filter-row">
            <span className="device-inv-filter-label">OS</span>
            <div className="chip-group">
              {OS_FILTERS.map((os) => (
                <button
                  key={os}
                  type="button"
                  className={`filter-chip${osFilter === os ? " active" : ""}`}
                  onClick={() => setOsFilter(os)}
                >
                  {osFilterLabel(os)} <span style={{ opacity: 0.6 }}>{osCounts[os] || 0}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="device-inv-filter-row">
            <span className="device-inv-filter-label">{tr("inv.compliance")}</span>
            <div className="chip-group">
              {COMPLIANCE_FILTERS.map(([key, labelKey]) => (
                <button
                  key={key}
                  type="button"
                  className={`filter-chip${complianceFilter === key ? " active" : ""}`}
                  onClick={() => setComplianceFilter(key)}
                >
                  {tr(labelKey)}
                </button>
              ))}
            </div>
          </div>
          <div className="device-inv-filter-row">
            <span className="device-inv-filter-label">{tr("inv.exposure")}</span>
            <div className="chip-group">
              {EXPOSURE_FILTERS.map(([key, labelKey]) => (
                <button
                  key={key}
                  type="button"
                  className={`filter-chip${exposureFilter === key ? " active" : ""}`}
                  onClick={() => setExposureFilter(key)}
                >
                  {tr(labelKey)}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="device-inv-table-card">
        <div className="card-head">
          <h2>{tr("inv.devices")}</h2>
          <span className="card-note">
            {tr("inv.shown", { shown: sorted.length, total: stats.total })}
          </span>
        </div>
        <div className="device-inv-table-wrap">
          <table className="device-inv-table">
            <thead>
              <tr>
                <th>{tr("inv.col.device")}</th>
                <th>{tr("inv.col.user")}</th>
                <th>{tr("inv.col.compliance")}</th>
                <th>{tr("inv.col.exposure")}</th>
                <th>{tr("inv.col.health")}</th>
                <th>{tr("inv.col.lastSeen")}</th>
                <th>{tr("inv.col.sources")}</th>
                <th aria-hidden="true"></th>
              </tr>
            </thead>
            <tbody>
              {sorted.length === 0 ? (
                <tr>
                  <td colSpan={8} className="empty">
                    {tr("inv.noDeviceForFilter")}
                  </td>
                </tr>
              ) : (
                sorted.map((d) => {
                  const stale = isStale(d);
                  const seenTs = lastSeenAny(d);
                  return (
                    <tr key={d.name} onClick={() => handleRowClick(d.name)}>
                      <td>
                        <div className="device-inv-name-cell">
                          <span className="device-inv-os-icon">
                            <OsIcon os={d.operating_system} />
                          </span>
                          <div>
                            <div className="device-inv-name">{d.name}</div>
                            <div className="device-inv-os-label">{d.operating_system || tr("common.unknownOs")}</div>
                          </div>
                        </div>
                      </td>
                      <td className="device-inv-user-cell">{d.user || <span className="device-inv-none">{tr("inv.unassigned")}</span>}</td>
                      <td>
                        <CompliancePill state={d.compliance_state} hasIntune={d.has_intune} />
                      </td>
                      <td>
                        <ExposurePill level={d.exposure_level} hasDefender={d.has_defender} />
                      </td>
                      <td>
                        <HealthPill status={d.health_status} hasDefender={d.has_defender} />
                      </td>
                      <td className={`device-inv-seen-cell${stale ? " stale" : ""}`}>
                        {seenTs != null ? fmtRelative(new Date(seenTs).toISOString()) : "—"}
                      </td>
                      <td>
                        <div className="device-inv-src-tags">
                          <span className={`device-inv-src-tag${d.has_intune ? "" : " missing"}`}>INTUNE</span>
                          <span className={`device-inv-src-tag${d.has_defender ? "" : " missing"}`}>MDE</span>
                        </div>
                      </td>
                      <td>
                        <span className="device-inv-goto">{tr("inv.open360")}</span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
