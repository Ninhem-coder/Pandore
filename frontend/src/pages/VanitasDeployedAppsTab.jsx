import { useEffect, useMemo, useState } from "react";
import { IconDownload } from "../components/icons.jsx";
import { exportVanitasDeployedAppsToExcel } from "../export.js";
import { useVanitasInstallerDeployments, useVanitasInstallers } from "../hooks/useDashboardData.js";
import { fmtDateTime } from "./vanitasShared.jsx";
import { localizedTable, tr } from "../i18n/core.js";

const STATUS_LABEL = localizedTable("vdep.status", ["ok", "bad", "pending"]);
const STATUS_ORDER = { bad: 0, pending: 1, ok: 2 };

function rowStatus(devices) {
  if (devices.some((d) => d.status === "bad")) return "fail";
  if (devices.some((d) => d.status === "pending")) return "pending";
  return "ok";
}

function splitCounts(devices) {
  const c = { ok: 0, bad: 0, pending: 0 };
  devices.forEach((d) => {
    c[d.status] = (c[d.status] ?? 0) + 1;
  });
  return c;
}

function lastActionAt(devices) {
  let latest = null;
  devices.forEach((d) => {
    const t = d.completed_at || d.created_at;
    if (t && (!latest || new Date(t) > new Date(latest))) latest = t;
  });
  return latest;
}

/** Une carte par poste, MÊME gabarit quel que soit le statut (retour de Nicolas sur la
 * maquette : "pk celui en attente est différent de celui qui est réussi ?") — triées
 * échec → en attente → réussi, ce qui a besoin d'attention en premier. */
function DeployedDeviceCard({ device }) {
  const result =
    device.result ||
    (device.status === "pending" ? tr("vdep.queued") : "—");
  return (
    <div className={`vanitas-deployed-device-row ${device.status}`}>
      <div className="vanitas-deployed-device-main">
        <span className="vanitas-deployed-device-host">{device.hostname}</span>
        <span className={`vanitas-hud-status-pill ${device.status}`}>{STATUS_LABEL[device.status]}</span>
      </div>
      <div className="vanitas-deployed-device-meta">
        <span className="time-cell">{fmtDateTime(device.completed_at || device.created_at)}</span>
        <span className="vanitas-deployed-device-result" title={result}>
          {result}
        </span>
      </div>
    </div>
  );
}

/** Détail par poste d'une ligne dépliée — pastilles de statut cliquables + recherche texte,
 * combinées (retour de Nicolas : "que je puisse filtrer via les blocs En attente, réussi" +
 * "pas trop long quitte à faire un truc scrollable") : une liste UNIQUE qui défile, jamais de
 * section repliée derrière un bouton "voir plus". */
function DeployedAppDetail({ devices }) {
  const [statusFilter, setStatusFilter] = useState("all");
  const [query, setQuery] = useState("");

  const counts = useMemo(() => splitCounts(devices), [devices]);

  const sorted = useMemo(
    () => [...devices].sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]),
    [devices]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return sorted.filter((d) => {
      if (statusFilter !== "all" && d.status !== statusFilter) return false;
      if (q && !d.hostname.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [sorted, statusFilter, query]);

  function pill(status, label, count) {
    return (
      <button
        type="button"
        className={`vanitas-deployed-pill ${status}${statusFilter === status ? " active" : ""}`}
        onClick={() => setStatusFilter(status)}
      >
        <span className="dot" />
        {count} {label}
      </button>
    );
  }

  return (
    <div className="vanitas-deployed-detail" onClick={(e) => e.stopPropagation()}>
      <div className="vanitas-deployed-summary">
        {pill("all", tr("vdep.pill.all"), devices.length)}
        {pill("ok", tr("vdep.pill.ok", { count: counts.ok }), counts.ok)}
        {pill("pending", tr("vdep.pill.pending"), counts.pending)}
        {pill("bad", tr("vdep.pill.bad", { count: counts.bad }), counts.bad)}
      </div>
      {devices.length > 4 && (
        <div className="vanitas-hud-search vanitas-deployed-search">
          <span className="prompt">&gt;</span>
          <input
            type="text"
            placeholder={tr("vdep.searchDevice")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
          />
        </div>
      )}
      <div className="vanitas-deployed-list">
        {filtered.length === 0 ? (
          <p className="vanitas-hud-empty-note" style={{ padding: "8px 0" }}>
            {tr("vdep.noDeviceMatch")}
          </p>
        ) : (
          filtered.map((d) => <DeployedDeviceCard key={d.agent_id} device={d} />)
        )}
      </div>
    </div>
  );
}

function DeployedAppRow({ row, expanded, onToggle }) {
  const counts = splitCounts(row.devices);
  const total = row.devices.length || 1;
  const lastAction = lastActionAt(row.devices);
  const directCount = row.devices.filter((d) => !d.target_label).length;

  return (
    <>
      <tr className={`row${expanded ? " open" : ""}`} onClick={onToggle} tabIndex={0} role="button">
        <td className="vanitas-hud-host">
          <span className="name">{row.name}</span>
          {row.version && <span className="id">v{row.version}</span>}
        </td>
        <td>
          <div className="vanitas-deployed-targets">
            {row.targets.map((t) => (
              <span key={t} className="vanitas-hud-apps-badge">
                {t}
              </span>
            ))}
            {directCount > 0 && (
              <span className="vanitas-hud-apps-badge vanitas-deployed-direct-badge">
                {tr("vdep.direct", { count: directCount })}
              </span>
            )}
            {row.targets.length === 0 && directCount === 0 && <span className="cve-small">—</span>}
          </div>
        </td>
        <td className="devices-count">{row.devices.length}</td>
        <td>
          <div className="vanitas-deployed-split-bar">
            <span style={{ width: `${(counts.ok / total) * 100}%`, background: "var(--hud-good)" }} />
            <span style={{ width: `${(counts.bad / total) * 100}%`, background: "var(--hud-high)" }} />
            <span style={{ width: `${(counts.pending / total) * 100}%`, background: "var(--hud-accent)" }} />
          </div>
          <div className="vanitas-deployed-split-legend">
            {counts.ok} ok · {tr("vdep.legendFails", { count: counts.bad })} · {tr("vdep.legendPending", { count: counts.pending })}
          </div>
        </td>
        <td className="time-cell">{fmtDateTime(lastAction)}</td>
        <td>
          <span className="vanitas-hud-chev">›</span>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6} style={{ padding: 0 }}>
            <DeployedAppDetail devices={row.devices} />
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * "Vanitas" > Inventaire > Applications déployées (2026-09-10, demande de Nicolas — "déployer
 * depuis le catalogue, assigner les groupes... et avoir une page pour voir les applications
 * qu'on a déployées" ; maquette validée puis retouchée trois fois avant mise en place).
 *
 * Reconstruit une vue "une ligne par application" à partir des commandes `install_application`
 * déjà envoyées (`GET /installers/deployments` côté serveur Vanitas) — AUCUNE nouvelle donnée
 * stockée côté dashboard, cette page est un pur agrégat en lecture. Une application n'apparaît
 * ici qu'après avoir été poussée AU MOINS UNE FOIS (depuis « Applications » ou la fiche d'un
 * groupe) — jamais tout le catalogue par défaut, ce serait confondre "disponible" et "déployé".
 *
 * `targets` (badges de groupe) vient de `target_label`, écrit par le serveur au moment du push
 * (voir `build_install_parameters`) — un push direct vers un seul poste n'a pas de groupe,
 * compté à part dans le badge "poste(s) direct(s)" plutôt que fabriqué comme un faux groupe.
 * Si un poste a été ciblé plusieurs fois pour le MÊME installeur, seule la tentative la PLUS
 * RÉCENTE compte pour son statut (calculé côté serveur) — jamais un doublon dans la liste.
 */
export default function VanitasDeployedAppsTab() {
  const installers = useVanitasInstallers();
  const deployments = useVanitasInstallerDeployments();
  const [query, setQuery] = useState("");
  const [rowFilter, setRowFilter] = useState("all");
  const [expandedId, setExpandedId] = useState(null);

  useEffect(() => {
    installers.ensureLoaded();
    deployments.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const installersById = useMemo(() => {
    const m = new Map();
    installers.state.data.forEach((i) => m.set(i.id, i));
    return m;
  }, [installers.state.data]);

  const rows = useMemo(
    () =>
      deployments.state.data.map((d) => {
        const installer = installersById.get(d.installer_id);
        return {
          installerId: d.installer_id,
          name: installer?.name ?? tr("vdep.deletedInstaller"),
          version: installer?.version ?? null,
          targets: d.targets,
          devices: d.devices,
        };
      }),
    [deployments.state.data, installersById]
  );

  const [exportState, setExportState] = useState({ status: "idle", error: null });
  async function handleExport() {
    setExportState({ status: "exporting", error: null });
    try {
      await exportVanitasDeployedAppsToExcel(rows);
      setExportState({ status: "idle", error: null });
    } catch (err) {
      setExportState({ status: "idle", error: err.message || tr("v.exportFailed") });
    }
  }

  const filteredRows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows.filter((r) => {
      const status = rowStatus(r.devices);
      if (rowFilter === "fail" && status !== "fail") return false;
      if (rowFilter === "ok" && status !== "ok") return false;
      if (!q) return true;
      return `${r.name} ${r.targets.join(" ")}`.toLowerCase().includes(q);
    });
  }, [rows, query, rowFilter]);

  const kpis = useMemo(() => {
    const allDevices = rows.flatMap((r) => r.devices);
    const uniqueHosts = new Set(allDevices.map((d) => d.hostname));
    const ok = allDevices.filter((d) => d.status === "ok").length;
    const bad = allDevices.filter((d) => d.status === "bad").length;
    const rate = allDevices.length ? Math.round((ok / allDevices.length) * 100) : 0;
    return { deployments: rows.length, devices: uniqueHosts.size, rate, fails: bad };
  }, [rows]);

  const failCount = useMemo(() => rows.filter((r) => rowStatus(r.devices) === "fail").length, [rows]);
  const okCount = useMemo(() => rows.filter((r) => rowStatus(r.devices) === "ok").length, [rows]);

  const loading = installers.state.status === "loading" || deployments.state.status === "loading";

  if (loading) {
    return (
      <div className="vanitas-hud">
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      </div>
    );
  }

  return (
    <div className="vanitas-hud">
      {deployments.state.error && <p className="vanitas-hud-error">{deployments.state.error}</p>}
      {installers.state.error && <p className="vanitas-hud-error">{installers.state.error}</p>}

      <div className="vanitas-hud-strip" style={{ marginBottom: "16px" }}>
        <div className="vanitas-hud-kpi" style={{ "--tone": "var(--hud-accent)" }}>
          <div className="label">{tr("vdep.kpi.deployments")}</div>
          <div className="value">{kpis.deployments}</div>
        </div>
        <div className="vanitas-hud-kpi" style={{ "--tone": "var(--hud-accent2)" }}>
          <div className="label">{tr("vdep.kpi.targeted")}</div>
          <div className="value">{kpis.devices}</div>
        </div>
        <div className="vanitas-hud-kpi" style={{ "--tone": "var(--hud-good)" }}>
          <div className="label">{tr("vdep.kpi.rate")}</div>
          <div className="value">{kpis.rate}%</div>
        </div>
        <div className="vanitas-hud-kpi" style={{ "--tone": "var(--hud-high)" }}>
          <div className="label">{tr("vdep.kpi.fails")}</div>
          <div className="value">{kpis.fails}</div>
        </div>
      </div>

      <div className="vanitas-hud-toolbar" style={{ marginBottom: "16px" }}>
        <div className="vanitas-hud-search">
          <span className="prompt">&gt;</span>
          <input
            type="text"
            placeholder={tr("vdep.searchPlaceholder")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
          />
        </div>
        <div className="vanitas-hud-chips">
          <button type="button" className={`vanitas-hud-chip${rowFilter === "all" ? " active" : ""}`} onClick={() => setRowFilter("all")}>
            <span className="led" />
            {tr("vdep.chip.all")}<span className="n">{rows.length}</span>
          </button>
          <button
            type="button"
            className={`vanitas-hud-chip tone-high${rowFilter === "fail" ? " active" : ""}`}
            onClick={() => setRowFilter("fail")}
          >
            <span className="led" />
            {tr("vdep.chip.fail")}<span className="n">{failCount}</span>
          </button>
          <button
            type="button"
            className={`vanitas-hud-chip tone-good${rowFilter === "ok" ? " active" : ""}`}
            onClick={() => setRowFilter("ok")}
          >
            <span className="led" />
            {tr("vdep.chip.ok")}<span className="n">{okCount}</span>
          </button>
        </div>
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>
            {tr("vdep.count", { filtered: filteredRows.length, count: rows.length })}
          </h2>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <span className="vanitas-hud-card-note">{tr("vdep.clickRow")}</span>
            <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting"}>
              <IconDownload />
              {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
            </button>
          </div>
        </div>
        {exportState.error && <p className="error-note" style={{ margin: "0 0 12px" }}>{exportState.error}</p>}
        {rows.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            {tr("vdep.empty")}
          </p>
        ) : filteredRows.length === 0 ? (
          <p className="vanitas-hud-empty-note">{tr("vdep.noResult")}</p>
        ) : (
          <div className="vanitas-hud-table-wrap">
            <table className="vanitas-hud-table">
              <thead>
                <tr>
                  <th>{tr("vdep.col.app")}</th>
                  <th>{tr("vdep.col.targets")}</th>
                  <th>{tr("vdep.col.endpoints")}</th>
                  <th>{tr("vdep.col.state")}</th>
                  <th>{tr("vdep.col.last")}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((r) => (
                  <DeployedAppRow
                    key={r.installerId}
                    row={r}
                    expanded={expandedId === r.installerId}
                    onToggle={() => setExpandedId(expandedId === r.installerId ? null : r.installerId)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
