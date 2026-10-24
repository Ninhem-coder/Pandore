import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { useAuth } from "../AuthContext.jsx";
import { IconDownload } from "../components/icons.jsx";
import { exportVanitasDeployedAppsToExcel } from "../export.js";
import { isErrorPayload, useVanitasAgents, useVanitasInstallerDeployments, useVanitasInstallers } from "../hooks/useDashboardData.js";
import { CVE_SEVERITY_COLORS } from "../theme.js";
import { ConfirmButton, fmtDateTime, fmtRelative, hasVanitasAccess } from "./vanitasShared.jsx";
import { localizedTable, tr } from "../i18n/core.js";

const STATUS_LABEL = localizedTable("vdep.status", ["ok", "bad", "pending"]);
const STATUS_ORDER = { bad: 0, pending: 1, ok: 2 };
// Réussi = vert, en attente = accent, échec = rouge (CVE_SEVERITY_COLORS, jamais une palette maison).
const STATUS_COLOR = { ok: CVE_SEVERITY_COLORS.Low, pending: "var(--hud-accent)", bad: CVE_SEVERITY_COLORS.Critical };
// État d'une application : le pire de ses postes (échec > en cours > réussi).
const APP_STATE = { fail: "bad", pending: "pending", ok: "ok" };

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

// Taux de réussite hors installations en attente — `null` tant que rien n'est terminé.
function successRate(c) {
  const done = c.ok + c.bad;
  return done ? Math.round((c.ok / done) * 100) : null;
}

function SplitBar({ counts, className }) {
  return (
    <span className={className}>
      {["ok", "pending", "bad"].map((k) => (
        <i key={k} style={{ flex: counts[k], background: STATUS_COLOR[k] }} />
      ))}
    </span>
  );
}

function TargetTags({ row }) {
  const directCount = row.devices.filter((d) => !d.target_label).length;
  return (
    <>
      {row.targets.map((t) => (
        <span key={t} className="vda-tag">
          {t}
        </span>
      ))}
      {directCount > 0 && <span className="vda-tag direct">{tr("vdep.direct", { count: directCount })}</span>}
    </>
  );
}

/** Détail d'une application déployée (panneau latéral, clé = installerId) — pastilles de statut
 * + recherche combinées sur la liste des postes (retour de Nicolas sur l'ancienne version :
 * "que je puisse filtrer via les blocs En attente, réussi"), message d'erreur sous chaque échec,
 * et "Relancer sur les échecs" (refonte 2026-10-23) : une commande `install_application` par
 * poste en échec, même appel que l'installation sur un seul poste depuis "Applications". */
function DeployedAppDetail({ row, canRetry, onRetried }) {
  const [statusFilter, setStatusFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [retry, setRetry] = useState({ busy: false, queued: null, error: null });

  const counts = useMemo(() => splitCounts(row.devices), [row.devices]);
  const rate = successRate(counts);
  const state = rowStatus(row.devices);
  const failed = useMemo(() => row.devices.filter((d) => d.status === "bad"), [row.devices]);
  const topError = useMemo(() => {
    const freq = new Map();
    for (const d of failed) if (d.result) freq.set(d.result, (freq.get(d.result) ?? 0) + 1);
    return [...freq.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? null;
  }, [failed]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return [...row.devices]
      .sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status])
      .filter((d) => (statusFilter === "all" || d.status === statusFilter) && (!q || d.hostname.toLowerCase().includes(q)));
  }, [row.devices, statusFilter, query]);

  async function handleRetry() {
    setRetry({ busy: true, queued: null, error: null });
    let queued = 0;
    let error = null;
    for (const d of failed) {
      try {
        const payload = await api.vanitas.queueCommand(d.agent_id, "install_application", row.installerId);
        if (isErrorPayload(payload)) error = payload.message;
        else queued++;
      } catch (err) {
        error = err.message;
      }
    }
    setRetry({ busy: false, queued, error });
    if (queued) onRetried();
  }

  const rateColor = rate === null ? undefined : rate === 100 ? CVE_SEVERITY_COLORS.Low : rate >= 80 ? CVE_SEVERITY_COLORS.Medium : CVE_SEVERITY_COLORS.Critical;

  return (
    <aside className="vda-card vda-detail" aria-label={tr("vda.detailAria")}>
      <div className="vda-detail-head">
        <div className="vda-detail-title">
          <h2>
            {row.name} {row.version && <span className="vda-ver">v{row.version}</span>}
          </h2>
          <span className="vda-sub vda-targets">
            {tr("vda.lastAction", { when: fmtRelative(lastActionAt(row.devices)) })} · <TargetTags row={row} />
          </span>
        </div>
        <span className="vda-pill" style={{ "--c": STATUS_COLOR[APP_STATE[state]] }}>
          {tr(`vda.state.${state}`)}
        </span>
      </div>

      <div className="vda-rate">
        <div className="vda-col">
          <span className="vda-lbl">{tr("vda.success")}</span>
          <span className="vda-val" style={rateColor ? { color: rateColor } : undefined}>
            {rate === null ? "—" : `${rate} %`}
          </span>
        </div>
        <div className="vda-rate-bar">
          <SplitBar counts={counts} className="vda-bar" />
          <span className="vda-sub">{tr("vda.splitLine", { ok: counts.ok, pending: counts.pending, bad: counts.bad, count: row.devices.length })}</span>
        </div>
      </div>

      {failed.length > 0 && (
        <div className="vda-fail">
          <span className="vda-fail-text">
            <b>{tr("vda.failedCount", { count: failed.length })}</b>
            {topError && <> — {tr("vda.topError", { error: topError })}</>}
          </span>
          {canRetry && (
            <ConfirmButton
              label={retry.busy ? tr("vda.retrying") : tr("vda.retry", { count: failed.length })}
              confirmLabel={tr("v.confirm")}
              className="vanitas-danger-btn"
              disabled={retry.busy}
              onConfirm={handleRetry}
              title={tr("vda.retryTitle")}
            />
          )}
        </div>
      )}
      {retry.error && <p className="error-note" style={{ margin: 0 }}>{retry.error}</p>}
      {retry.queued !== null && retry.queued > 0 && (
        <p className="vda-sub" style={{ margin: 0 }}>
          <b className="vda-ok">{tr("vgd.queued", { count: retry.queued })}</b> — {tr("vgd.resultsCommands")}
        </p>
      )}

      <div className="vda-devices">
        <div className="vda-devices-head">
          <span className="vda-lbl">{tr("vda.devices", { count: row.devices.length })}</span>
          <span className="vda-chips" role="group" aria-label={tr("vda.devFilterAria")}>
            {[
              ["all", tr("vda.f.all"), row.devices.length],
              ["bad", STATUS_LABEL.bad, counts.bad],
              ["pending", STATUS_LABEL.pending, counts.pending],
              ["ok", STATUS_LABEL.ok, counts.ok],
            ].map(([k, label, n]) => (
              <button key={k} type="button" className={`vda-chip sm${statusFilter === k ? " on" : ""}`} aria-pressed={statusFilter === k} onClick={() => setStatusFilter(k)}>
                {label} <b>{n}</b>
              </button>
            ))}
          </span>
        </div>
        {row.devices.length > 4 && (
          <input type="search" className="vda-input" placeholder={tr("vda.searchDevice")} aria-label={tr("vda.searchDevice")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
        )}
        {filtered.length === 0 ? (
          <p className="vda-sub" style={{ margin: 0 }}>{tr("vdep.noDeviceMatch")}</p>
        ) : (
          <div className="vda-dev-list">
            {filtered.map((d) => (
              <div key={d.agent_id} className="vda-dev">
                <span className="vda-dot" style={{ background: STATUS_COLOR[d.status] }} />
                <span className="vda-dev-host">{d.hostname}</span>
                <span className="vda-sub vda-small vda-nowrap">
                  {STATUS_LABEL[d.status]} · {d.status === "pending" ? tr("vda.inQueue") : fmtDateTime(d.completed_at || d.created_at)}
                </span>
                {d.status === "bad" && d.result && (
                  <span className="vda-dev-res" title={d.result}>
                    {d.result}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}

/**
 * "Vanitas" > Inventaire > Applications déployées (2026-09-10, demande de Nicolas — "déployer
 * depuis le catalogue, assigner les groupes... et avoir une page pour voir les applications
 * qu'on a déployées").
 *
 * Reconstruit une vue "une entrée par application" à partir des commandes `install_application`
 * déjà envoyées (`GET /installers/deployments` côté serveur Vanitas) — AUCUNE nouvelle donnée
 * stockée côté dashboard. Une application n'apparaît ici qu'après avoir été poussée AU MOINS UNE
 * FOIS — jamais tout le catalogue, ce serait confondre "disponible" et "déployé". `targets` vient
 * de `target_label` (écrit par le serveur au push) ; un push direct vers un poste est compté à
 * part ("N en direct"). Si un poste a été ciblé plusieurs fois pour le même installeur, seule la
 * tentative la PLUS RÉCENTE compte (calculé côté serveur).
 *
 * Refonte liste + détail (2026-10-23, maquette canvas validée par Nicolas) : bandeau de synthèse
 * (installations par état en barre avec légende cliquable, taux de réussite hors attente, postes
 * ciblés), liste avec mini-barre par application (échecs en tête) et détail dans un panneau
 * latéral au lieu de l'accordéon. Classes `.vda-*`.
 */
export default function VanitasDeployedAppsTab({ onNavigateVanitas }) {
  const { user } = useAuth();
  const installers = useVanitasInstallers();
  const deployments = useVanitasInstallerDeployments();
  const agents = useVanitasAgents();
  const [query, setQuery] = useState("");
  const [rowFilter, setRowFilter] = useState("all");
  const [selectedId, setSelectedId] = useState(null);
  const detailRef = useRef(null);

  useEffect(() => {
    installers.ensureLoaded();
    deployments.ensureLoaded();
    agents.ensureLoaded();
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

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return rows
      .filter((r) => {
        if (rowFilter !== "all" && rowStatus(r.devices) !== rowFilter) return false;
        if (!q) return true;
        return `${r.name} ${r.targets.join(" ")} ${r.devices.map((d) => d.hostname).join(" ")}`.toLowerCase().includes(q);
      })
      .sort((a, b) => {
        const o = { fail: 0, pending: 1, ok: 2 };
        const d = o[rowStatus(a.devices)] - o[rowStatus(b.devices)];
        return d || new Date(lastActionAt(b.devices) ?? 0) - new Date(lastActionAt(a.devices) ?? 0);
      });
  }, [rows, query, rowFilter]);

  const totals = useMemo(() => {
    const all = rows.flatMap((r) => r.devices);
    const c = splitCounts(all);
    return { ...c, installs: all.length, hosts: new Set(all.map((d) => d.agent_id)).size, rate: successRate(c) };
  }, [rows]);
  const stateCounts = useMemo(() => {
    const c = { all: rows.length, fail: 0, pending: 0, ok: 0 };
    for (const r of rows) c[rowStatus(r.devices)]++;
    return c;
  }, [rows]);

  const selected = visible.find((r) => r.installerId === selectedId) ?? visible[0] ?? null;

  function selectRow(id) {
    setSelectedId(id);
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  const loading = installers.state.status === "loading" || deployments.state.status === "loading";
  if (loading) {
    return (
      <div className="vanitas-hud vda">
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      </div>
    );
  }

  const canDeploy = hasVanitasAccess(user, "applications", "read");
  const canRetry = hasVanitasAccess(user, "applications", "write");
  const agentTotal = (agents.state.data ?? []).length;

  return (
    <div className="vanitas-hud vda">
      {deployments.state.error && <p className="vanitas-hud-error">{deployments.state.error}</p>}
      {installers.state.error && <p className="vanitas-hud-error">{installers.state.error}</p>}

      <section className="vda-card vda-sum" aria-label={tr("vda.sumAria")}>
        <div className="vda-col">
          <span className="vda-lbl">{tr("vda.apps")}</span>
          <span className="vda-val accent">{rows.length}</span>
          <span className="vda-sub vda-small">{tr("vda.installs", { count: totals.installs })}</span>
        </div>
        <div className="vda-sum-state">
          <span className="vda-lbl">{tr("vda.byState")}</span>
          <span role="img" aria-label={`${tr("vda.leg.ok", { count: totals.ok })}, ${tr("vda.leg.pending", { count: totals.pending })}, ${tr("vda.leg.bad", { count: totals.bad })}`}>
            <SplitBar counts={totals} className="vda-bar" />
          </span>
          <div className="vda-legend">
            {[
              ["ok", "ok"],
              ["pending", "pending"],
              ["bad", "fail"],
            ].map(([k, f]) => (
              <button key={k} type="button" className="vda-leg" onClick={() => setRowFilter(f)}>
                <i style={{ background: STATUS_COLOR[k] }} />
                {tr(`vda.leg.${k}`, { count: totals[k] })}
              </button>
            ))}
          </div>
        </div>
        <div className="vda-col vda-sum-third">
          <span className="vda-lbl">{tr("vdep.kpi.rate")}</span>
          <span className="vda-val" style={totals.rate !== null ? { color: totals.rate >= 80 ? CVE_SEVERITY_COLORS.Low : CVE_SEVERITY_COLORS.Critical } : undefined}>
            {totals.rate === null ? "—" : `${totals.rate} %`}
          </span>
          <span className="vda-sub vda-small">{tr("vda.rateSub")}</span>
        </div>
        <div className="vda-col vda-sum-fourth">
          <span className="vda-lbl">{tr("vdep.kpi.targeted")}</span>
          <span className="vda-val">
            {totals.hosts} {agentTotal > 0 && <small>/ {agentTotal}</small>}
          </span>
          <span className="vda-sub vda-small">{tr("vda.targetedSub")}</span>
        </div>
      </section>

      <div className="vda-split">
        <section className="vda-card vda-list" aria-label={tr("vda.listTitle")}>
          <div className="vda-list-head">
            <h2 className="vda-h2">{tr("vda.listTitle")}</h2>
            <div className="vda-row">
              <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting" || rows.length === 0}>
                <IconDownload />
                {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
              </button>
              {canDeploy && (
                <button type="button" className="vanitas-queue-btn" onClick={() => onNavigateVanitas?.("vanitas-installers")}>
                  {tr("vda.deploy")}
                </button>
              )}
            </div>
          </div>
          {exportState.error && <p className="error-note" style={{ margin: 0 }}>{exportState.error}</p>}
          <div className="vda-row">
            <label className="vda-search-wrap">
              <span className="vda-sr">{tr("vda.search")}</span>
              <input type="search" className="vda-input" placeholder={tr("vda.search")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
            </label>
            <span className="vda-chips" role="group" aria-label={tr("vda.filterAria")}>
              {[
                ["all", tr("vda.f.allApps"), "var(--vda-muted)"],
                ["fail", tr("vda.f.fail"), STATUS_COLOR.bad],
                ["pending", tr("vda.f.pending"), STATUS_COLOR.pending],
                ["ok", tr("vda.f.ok"), STATUS_COLOR.ok],
              ].map(([k, label, color]) => (
                <button key={k} type="button" className={`vda-chip${rowFilter === k ? " on" : ""}`} aria-pressed={rowFilter === k} onClick={() => setRowFilter(k)}>
                  <i className="dot" style={{ background: color }} />
                  {label} <b>{stateCounts[k]}</b>
                </button>
              ))}
            </span>
          </div>

          {rows.length === 0 ? (
            <p className="vda-empty">{tr("vdep.empty")}</p>
          ) : visible.length === 0 ? (
            <p className="vda-empty">{tr("vda.noMatch")}</p>
          ) : (
            <div className="vda-rows">
              {visible.map((r) => {
                const c = splitCounts(r.devices);
                const st = rowStatus(r.devices);
                const isSel = selected?.installerId === r.installerId;
                return (
                  <button key={r.installerId} type="button" className={`vda-app${isSel ? " sel" : ""}`} aria-pressed={isSel} onClick={() => selectRow(r.installerId)}>
                    <span className="vda-ico" aria-hidden="true">
                      {r.name.charAt(0).toUpperCase()}
                    </span>
                    <span className="vda-app-name">
                      {r.name} {r.version && <span className="vda-ver">v{r.version}</span>}
                    </span>
                    <span className="vda-pill" style={{ "--c": STATUS_COLOR[APP_STATE[st]] }}>
                      {tr(`vda.state.${st}`)}
                    </span>
                    <SplitBar counts={c} className="vda-bar vda-bar-sm" />
                    <span className="vda-app-meta">
                      <span className="vda-ink">{tr("vda.okOf", { ok: c.ok, count: r.devices.length })}</span>
                      {c.bad > 0 && <span className="vda-bad">· {tr("vdep.legendFails", { count: c.bad })}</span>}
                      <span>·</span>
                      <TargetTags row={r} />
                      <span>· {fmtRelative(lastActionAt(r.devices))}</span>
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        <div ref={detailRef} className="vda-detail-slot">
          {selected ? (
            <DeployedAppDetail key={selected.installerId} row={selected} canRetry={canRetry} onRetried={() => deployments.refresh()} />
          ) : (
            <div className="vda-card vda-empty-panel">
              <p className="vda-sub">{tr("vda.pick")}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
