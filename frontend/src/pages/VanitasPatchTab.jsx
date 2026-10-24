import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { IconDownload } from "../components/icons.jsx";
import { exportPatchStatusToExcel } from "../export.js";
import { isErrorPayload, useVanitasGroups, useVanitasPatchStatus } from "../hooks/useDashboardData.js";
import { CVE_SEVERITY_COLORS } from "../theme.js";
import { ConfirmButton, fmtRelative } from "./vanitasShared.jsx";
import { tr } from "../i18n/core.js";

/**
 * "Vanitas" > Sécurité > Mises à jour Vanitas (2026-09-17, maquette validée par Nicolas —
 * "Déploiement réel des mises à jour Windows [...] pas un simple bouton"). Trois décisions de
 * cadrage tranchées avant la maquette (`AskUserQuestion`), directement visibles ici :
 * - Périmètre SÉCURITÉ/CRITIQUE uniquement (`MsrcSeverity`, voir `PatchRunner.cs` côté agent).
 * - Installation immédiate, REDÉMARRAGE différé jusqu'à la fenêtre de maintenance du groupe.
 * - Politique PERSISTANTE par groupe (pas un push ponctuel) — délai de grâce avant redémarrage
 *   forcé si le poste n'atteint jamais sa fenêtre.
 *
 * Statut affiché calculé CÔTÉ SERVEUR (`endpoint-agent/server/app/routes/patch.py::
 * _display_status`) — jamais recalculé ici. 4 buckets de mises à jour par poste
 * (`available`/`todo`/`in_progress`/`installed`).
 *
 * Refonte liste + détail (2026-10-24, maquette canvas validée par Nicolas) : bandeau de synthèse
 * (6 états en une barre, légende cliquable), bascule "Postes / Politiques par groupe" en tête de
 * liste, détail dans un panneau latéral — fenêtre de redémarrage sur une frise 24 h (lisible même
 * quand elle passe minuit) — au lieu de la popup et de la colonne de politiques. Classes `.vpt-*`.
 */

const STATUS_ORDER = ["ok", "pending-install", "installing", "pending-window", "forced", "off"];
// Mêmes tons qu'avant la refonte (vert / ambre / accent / rouge / neutre) via CVE_SEVERITY_COLORS ;
// "attend fenêtre" = accent atténué, pour le distinguer d'"installation en cours" sans teinte de plus.
const STATUS_COLOR = {
  ok: CVE_SEVERITY_COLORS.Low,
  "pending-install": CVE_SEVERITY_COLORS.Medium,
  installing: "var(--hud-accent)",
  "pending-window": "color-mix(in srgb, var(--hud-accent) 55%, transparent)",
  forced: CVE_SEVERITY_COLORS.Critical,
  off: CVE_SEVERITY_COLORS.Unknown,
};
const PILL_COLOR = { ...STATUS_COLOR, "pending-window": "var(--hud-accent)" };

const UPDATE_BUCKETS = [
  { key: "in_progress", color: "var(--hud-accent)" },
  { key: "todo", hasHint: true, color: CVE_SEVERITY_COLORS.Medium },
  { key: "installed", hasHint: true, color: CVE_SEVERITY_COLORS.Low },
  { key: "available", hasHint: true, color: "var(--vpt-muted)" },
];

// Statuts où "Forcer le redémarrage maintenant" a un sens — jamais sur un poste déjà à jour,
// déjà forcé, ou hors politique (rien n'a été installé automatiquement pour lui).
const FORCE_REBOOT_ELIGIBLE = new Set(["pending-install", "installing", "pending-window"]);

function StatusPill({ status }) {
  return (
    <span className="vpt-pill" style={{ "--c": PILL_COLOR[status] ?? STATUS_COLOR.off }}>
      {status === "installing" && <span className="vpt-live" />}
      {tr(`vp.status.${status}`)}
    </span>
  );
}

function hourOf(hhmm) {
  const [h, m] = String(hhmm || "0:0").split(":").map(Number);
  return (h || 0) + (m || 0) / 60;
}

/** Frise 24 h de la fenêtre de redémarrage — une case par heure, allumée si la fenêtre la
 * recouvre (gère le passage de minuit, ex. 22:00 → 02:00). */
function WindowTimeline({ start, end, legend = false }) {
  const s = hourOf(start);
  const e = hourOf(end);
  const cells = Array.from({ length: 24 }, (_, h) => {
    if (start == null || end == null || s === e) return false;
    const mid = h + 0.5;
    return s < e ? mid >= s && mid < e : mid >= s || mid < e;
  });
  return (
    <>
      <span className="vpt-timeline" aria-hidden="true">
        {cells.map((on, h) => (
          <i key={h} className={on ? "w" : ""} />
        ))}
      </span>
      {legend && (
        <span className="vpt-timeline-legend" aria-hidden="true">
          <span>00h</span>
          <span>06h</span>
          <span>12h</span>
          <span>18h</span>
          <span>24h</span>
        </span>
      )}
    </>
  );
}

function StatusBar({ counts, className = "vpt-bar" }) {
  return (
    <span className={className}>
      {STATUS_ORDER.map((k) => (counts[k] ? <i key={k} style={{ flex: counts[k], background: STATUS_COLOR[k] }} /> : null))}
    </span>
  );
}

function countByStatus(entries) {
  const c = Object.fromEntries(STATUS_ORDER.map((k) => [k, 0]));
  for (const e of entries) if (c[e.status] !== undefined) c[e.status]++;
  return c;
}

function DevicePanel({ entry, onForced }) {
  const [error, setError] = useState(null);
  const [queued, setQueued] = useState(false);

  async function handleForce() {
    setError(null);
    try {
      const payload = await api.vanitas.queueCommand(entry.agent_id, "force_reboot");
      if (isErrorPayload(payload)) {
        setError(payload.message);
        return;
      }
      setQueued(true);
      onForced();
    } catch (err) {
      setError(err.message);
    }
  }

  const sections = UPDATE_BUCKETS.map((b) => ({
    ...b,
    label: tr(`vp.bucket.${b.key}`),
    // "Installées" sur un poste à jour ou déjà redémarré de force : le redémarrage a eu lieu,
    // l'indice générique ("en attente du redémarrage") serait faux.
    hint:
      b.key === "installed" && (entry.status === "ok" || entry.status === "forced")
        ? tr("vpt.installedDone")
        : b.hasHint
          ? tr(`vp.bucket.${b.key}.hint`)
          : null,
    items: entry[b.key] ?? [],
  })).filter((b) => b.items.length > 0);
  const hasWindow = entry.window_start && entry.window_end;
  const windowHint =
    entry.status === "off"
      ? tr("vpt.hint.off")
      : entry.status === "pending-window"
        ? tr("vpt.hint.pendingWindow", { start: entry.window_start })
        : entry.status === "forced"
          ? tr("vpt.hint.forced", { when: fmtRelative(entry.forced_at) })
          : tr("vpt.hint.default");

  return (
    <aside className="vpt-card vpt-detail" aria-label={tr("vpt.deviceAria")}>
      <div className="vpt-detail-head">
        <div className="vpt-detail-title">
          <h2 className="vpt-mono">{entry.hostname}</h2>
          <span className="vpt-sub">
            {entry.group_name ?? tr("vpt.noPolicyGroup")} · {tr("vpt.checked", { when: fmtRelative(entry.updated_at) })}
          </span>
        </div>
        <StatusPill status={entry.status} />
      </div>

      <div className="vpt-box">
        <div className="vpt-box-head">
          <span className="vpt-lbl">{tr("vp.rebootWindow")}</span>
          <span className="vpt-mono vpt-small-ink">
            {hasWindow ? tr("vpt.windowLine", { start: entry.window_start, end: entry.window_end, days: entry.grace_days ?? "—" }) : "—"}
          </span>
        </div>
        <WindowTimeline start={entry.window_start} end={entry.window_end} />
        <span className="vpt-sub vpt-small">{windowHint}</span>
      </div>

      {sections.length === 0 ? (
        <p className="vpt-sub" style={{ margin: 0 }}>
          {tr("vp.noUpdate")}
        </p>
      ) : (
        sections.map((b) => (
          <div key={b.key} className="vpt-bucket">
            <span className="vpt-lbl" style={{ color: b.color }}>
              {b.label} ({b.items.length})
              {b.hint && <span className="vpt-bucket-hint"> — {b.hint}</span>}
            </span>
            <div className="vpt-kbs">
              {b.items.map((u) => (
                <div key={u.kb} className="vpt-kb">
                  <span className="vpt-mono vpt-kb-id" style={{ color: b.color }}>
                    {u.kb}
                  </span>
                  <span>{u.title}</span>
                </div>
              ))}
            </div>
          </div>
        ))
      )}

      {error && <p className="error-note" style={{ margin: 0 }}>{error}</p>}
      {FORCE_REBOOT_ELIGIBLE.has(entry.status) && (
        <div className="vpt-foot">
          <span className="vpt-sub">{queued ? tr("vpt.forceQueued") : tr("vpt.forceHint")}</span>
          <ConfirmButton label={tr("vp.forceReboot")} confirmLabel={tr("vp.forceConfirm")} className="vanitas-danger-btn" onConfirm={handleForce} disabled={queued} />
        </div>
      )}
    </aside>
  );
}

function PolicyPanel({ group, entries, onSaved }) {
  const [enabled, setEnabled] = useState(group.patch_enabled);
  const [windowStart, setWindowStart] = useState(group.patch_window_start ?? "20:00");
  const [windowEnd, setWindowEnd] = useState(group.patch_window_end ?? "06:00");
  const [graceDays, setGraceDays] = useState(group.patch_grace_days ?? 5);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [saved, setSaved] = useState(false);

  async function save(nextEnabled = enabled) {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const payload = await api.vanitas.updatePatchPolicy(group.id, {
        enabled: nextEnabled,
        windowStart,
        windowEnd,
        graceDays: Number(graceDays) || 5,
      });
      if (isErrorPayload(payload)) {
        setError(payload.message);
        return false;
      }
      setSaved(true);
      onSaved();
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function handleToggle() {
    const next = !enabled;
    setEnabled(next);
    // Désactiver ne nécessite pas de fenêtre valide (le serveur ne l'exige que pour ACTIVER,
    // voir `routes/groups.py::update_patch_policy`) — enregistré immédiatement.
    // Échec (ex. droits insuffisants) : l'interrupteur revient à l'état réel.
    if (!next && !(await save(false))) setEnabled(true);
  }

  const dirty =
    enabled !== group.patch_enabled ||
    windowStart !== (group.patch_window_start ?? "20:00") ||
    windowEnd !== (group.patch_window_end ?? "06:00") ||
    Number(graceDays) !== (group.patch_grace_days ?? 5);
  const counts = countByStatus(entries);

  return (
    <aside className="vpt-card vpt-detail" aria-label={tr("vpt.policyAria")}>
      <div className="vpt-detail-head vpt-center">
        <div className="vpt-detail-title">
          <h2>{group.name}</h2>
          <span className="vpt-sub">
            {tr("vp.endpoints", { count: group.device_count })} · {tr(enabled ? "vpt.policyOn" : "vpt.policyOff")}
          </span>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={enabled}
          aria-label={tr("vpt.toggleAria")}
          className={`vpt-switch${enabled ? " on" : ""}`}
          onClick={handleToggle}
          disabled={busy}
        >
          <i />
        </button>
      </div>

      <div className={`vpt-box${enabled ? "" : " off"}`}>
        <span className="vpt-lbl">{tr("vp.rebootWindow")}</span>
        <div className="vpt-field">
          <input type="time" className="vpt-input" value={windowStart} onChange={(e) => setWindowStart(e.target.value)} disabled={busy || !enabled} aria-label={tr("vpt.start")} />
          <span>→</span>
          <input type="time" className="vpt-input" value={windowEnd} onChange={(e) => setWindowEnd(e.target.value)} disabled={busy || !enabled} aria-label={tr("vpt.end")} />
          <span className="vpt-sub">{tr("vpt.localTime")}</span>
        </div>
        <WindowTimeline start={windowStart} end={windowEnd} legend />
        <span className="vpt-lbl vpt-gap">{tr("vp.grace")}</span>
        <div className="vpt-field">
          <input
            type="number"
            min={1}
            max={30}
            className="vpt-input vpt-input-sm"
            value={graceDays}
            onChange={(e) => setGraceDays(e.target.value)}
            disabled={busy || !enabled}
            aria-label={tr("vp.grace")}
          />
          <span className="vpt-sub">{tr("vpt.graceHint")}</span>
        </div>
      </div>

      <div className="vpt-bucket">
        <span className="vpt-lbl">{tr("vpt.groupState")}</span>
        {entries.length === 0 ? (
          <span className="vpt-sub">{tr(enabled ? "vpt.noTracked" : "vpt.notTracked")}</span>
        ) : (
          <>
            <StatusBar counts={counts} />
            <span className="vpt-sub">
              {tr("vpt.groupLine", { ok: counts.ok, window: counts["pending-window"], install: counts["pending-install"] + counts.installing })}
            </span>
          </>
        )}
      </div>

      {error && <p className="error-note" style={{ margin: 0 }}>{error}</p>}
      <div className="vpt-actions">
        {saved && !dirty && <span className="vpt-sub vpt-ok">{tr("vpt.saved")}</span>}
        <button type="button" className="vanitas-queue-btn" onClick={() => save()} disabled={busy || !enabled || !dirty}>
          {busy ? tr("vp.saving") : tr("vp.save")}
        </button>
      </div>
      <p className="vpt-sub vpt-small" style={{ margin: 0 }}>
        {tr("vp.disabledNote")}
      </p>
    </aside>
  );
}

export default function VanitasPatchTab() {
  const fleet = useVanitasPatchStatus();
  const groups = useVanitasGroups();
  const [mode, setMode] = useState("devices");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedAgentId, setSelectedAgentId] = useState(null);
  const [selectedGroupId, setSelectedGroupId] = useState(null);
  const detailRef = useRef(null);

  useEffect(() => {
    fleet.ensureLoaded();
    groups.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const entries = fleet.state.data ?? [];
  const groupList = groups.state.data ?? [];
  const counts = useMemo(() => countByStatus(entries), [entries]);
  const pendingFixes = useMemo(() => entries.reduce((n, e) => n + (e.todo?.length ?? 0) + (e.in_progress?.length ?? 0), 0), [entries]);
  const activePolicies = groupList.filter((g) => g.patch_enabled).length;

  const [exportState, setExportState] = useState({ status: "idle", error: null });
  async function handleExport() {
    setExportState({ status: "exporting", error: null });
    try {
      await exportPatchStatusToExcel(entries);
      setExportState({ status: "idle", error: null });
    } catch (err) {
      setExportState({ status: "idle", error: err.message || tr("v.exportFailed") });
    }
  }

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries
      .filter((e) => {
        if (statusFilter !== "all" && e.status !== statusFilter) return false;
        if (!q) return true;
        return e.hostname.toLowerCase().includes(q) || (e.group_name ?? "").toLowerCase().includes(q);
      })
      .sort((a, b) => {
        // Ce qui demande une action d'abord (forcé, en attente, en cours...), "à jour" et "hors
        // politique" en dernier ; puis par nom.
        const rank = { forced: 0, "pending-install": 1, installing: 2, "pending-window": 3, ok: 4, off: 5 };
        return (rank[a.status] ?? 9) - (rank[b.status] ?? 9) || a.hostname.localeCompare(b.hostname);
      });
  }, [entries, query, statusFilter]);

  const entriesByGroup = useMemo(() => {
    const map = new Map();
    for (const e of entries) if (e.group_id) (map.get(e.group_id) ?? map.set(e.group_id, []).get(e.group_id)).push(e);
    return map;
  }, [entries]);
  const sortedGroups = useMemo(
    () => [...groupList].sort((a, b) => Number(b.patch_enabled) - Number(a.patch_enabled) || a.name.localeCompare(b.name)),
    [groupList]
  );

  const selectedEntry = rows.find((e) => e.agent_id === selectedAgentId) ?? rows[0] ?? null;
  const selectedGroup = sortedGroups.find((g) => g.id === selectedGroupId) ?? sortedGroups[0] ?? null;

  function scrollToDetail() {
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  const error = fleet.state.error || groups.state.error;
  const loading = fleet.state.status === "loading" || groups.state.status === "loading";
  if (loading) {
    return (
      <div className="vanitas-hud vpt">
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      </div>
    );
  }

  return (
    <div className="vanitas-hud vpt">
      {error && <p className="vanitas-hud-error">{error}</p>}

      <section className="vpt-card vpt-sum" aria-label={tr("vpt.sumAria")}>
        <div className="vpt-col">
          <span className="vpt-lbl">{tr("vp.kpi.tracked")}</span>
          <span className="vpt-val accent">{entries.length}</span>
          <span className="vpt-sub vpt-small">{tr("vpt.scope")}</span>
        </div>
        <div className="vpt-sum-state">
          <span className="vpt-lbl">{tr("vpt.byState")}</span>
          <span role="img" aria-label={STATUS_ORDER.map((k) => `${counts[k]} ${tr(`vp.status.${k}`)}`).join(", ")}>
            <StatusBar counts={counts} />
          </span>
          <div className="vpt-legend">
            {STATUS_ORDER.filter((k) => counts[k] > 0).map((k) => (
              <button
                key={k}
                type="button"
                className="vpt-leg"
                onClick={() => {
                  setMode("devices");
                  setStatusFilter(k);
                }}
              >
                <i style={{ background: STATUS_COLOR[k] }} />
                <b>{counts[k]}</b> {tr(`vp.status.${k}`)}
              </button>
            ))}
          </div>
        </div>
        <div className="vpt-col vpt-sum-third">
          <span className="vpt-lbl">{tr("vpt.pendingFixes")}</span>
          <span className="vpt-val" style={pendingFixes ? { color: CVE_SEVERITY_COLORS.Medium } : undefined}>
            {pendingFixes}
          </span>
          <span className="vpt-sub vpt-small">{tr("vpt.pendingFixesSub")}</span>
        </div>
        <div className="vpt-col vpt-sum-fourth">
          <span className="vpt-lbl">{tr("vpt.activePolicies")}</span>
          <span className="vpt-val">
            {activePolicies} <small>/ {groupList.length}</small>
          </span>
          <span className="vpt-sub vpt-small">{tr("vpt.activePoliciesSub")}</span>
        </div>
      </section>

      <div className="vpt-split">
        <section className="vpt-card vpt-list" aria-label={tr("vpt.listAria")}>
          <div className="vpt-list-head">
            <span className="vpt-seg" role="tablist" aria-label={tr("vpt.listAria")}>
              <button type="button" role="tab" aria-selected={mode === "devices"} className={mode === "devices" ? "on" : ""} onClick={() => setMode("devices")}>
                {tr("vpt.mode.devices")}
              </button>
              <button type="button" role="tab" aria-selected={mode === "policies"} className={mode === "policies" ? "on" : ""} onClick={() => setMode("policies")}>
                {tr("vpt.mode.policies")}
              </button>
            </span>
            <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting" || entries.length === 0}>
              <IconDownload />
              {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
            </button>
          </div>
          {exportState.error && <p className="error-note" style={{ margin: 0 }}>{exportState.error}</p>}

          {mode === "devices" ? (
            <>
              <label className="vpt-search-wrap">
                <span className="vpt-sr">{tr("vpt.search")}</span>
                <input type="search" className="vpt-input" placeholder={tr("vpt.search")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
              </label>
              <span className="vpt-chips" role="group" aria-label={tr("vpt.filterAria")}>
                {["all", ...STATUS_ORDER].map((k) => {
                  const n = k === "all" ? entries.length : counts[k];
                  if (k !== "all" && !n && statusFilter !== k) return null;
                  return (
                    <button key={k} type="button" className={`vpt-chip${statusFilter === k ? " on" : ""}`} aria-pressed={statusFilter === k} onClick={() => setStatusFilter(k)}>
                      <i className="dot" style={{ background: k === "all" ? "var(--vpt-muted)" : STATUS_COLOR[k] }} />
                      {k === "all" ? tr("vpt.f.all") : tr(`vp.status.${k}`)} <b>{n}</b>
                    </button>
                  );
                })}
              </span>
              {entries.length === 0 ? (
                <p className="vpt-empty">{tr("vv.noAgent")}</p>
              ) : rows.length === 0 ? (
                <p className="vpt-empty">{tr("vv.noResult")}</p>
              ) : (
                <div className="vpt-rows">
                  {rows.map((e) => {
                    const pending = (e.todo?.length ?? 0) + (e.in_progress?.length ?? 0);
                    const isSel = selectedEntry?.agent_id === e.agent_id;
                    return (
                      <button
                        key={e.agent_id}
                        type="button"
                        className={`vpt-row${isSel ? " sel" : ""}`}
                        aria-pressed={isSel}
                        onClick={() => {
                          setSelectedAgentId(e.agent_id);
                          scrollToDetail();
                        }}
                      >
                        <span className="vpt-dot" style={{ background: STATUS_COLOR[e.status] }} />
                        <span className="vpt-host">{e.hostname}</span>
                        <StatusPill status={e.status} />
                        <span className="vpt-meta">
                          {e.group_name && <span className="vpt-tag">{e.group_name}</span>}
                          {pending > 0 && <span className="vpt-warn">{tr("vpt.pendingCount", { count: pending })}</span>}
                          <span>{tr("vpt.checked", { when: fmtRelative(e.updated_at) })}</span>
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </>
          ) : (
            <>
              <span className="vpt-sub">{tr("vpt.policyIntro")}</span>
              {sortedGroups.length === 0 ? (
                <p className="vpt-empty">{tr("vp.noGroup")}</p>
              ) : (
                <div className="vpt-rows">
                  {sortedGroups.map((g) => {
                    const ge = entriesByGroup.get(g.id) ?? [];
                    const c = countByStatus(ge);
                    const isSel = selectedGroup?.id === g.id;
                    return (
                      <button
                        key={g.id}
                        type="button"
                        className={`vpt-grp${isSel ? " sel" : ""}`}
                        aria-pressed={isSel}
                        onClick={() => {
                          setSelectedGroupId(g.id);
                          scrollToDetail();
                        }}
                      >
                        <span className="vpt-grp-name">{g.name}</span>
                        <span className="vpt-pill" style={{ "--c": g.patch_enabled ? CVE_SEVERITY_COLORS.Low : CVE_SEVERITY_COLORS.Unknown }}>
                          {tr(g.patch_enabled ? "vpt.active" : "vpt.inactive")}
                        </span>
                        {ge.length > 0 && <StatusBar counts={c} className="vpt-bar vpt-bar-sm" />}
                        <span className="vpt-grp-meta">
                          {g.patch_enabled
                            ? tr("vpt.groupMeta", { start: g.patch_window_start, end: g.patch_window_end, days: g.patch_grace_days ?? "—" })
                            : tr("vpt.groupMetaOff")}
                          {" · "}
                          {ge.length > 0 ? tr("vpt.upToDate", { ok: c.ok, count: ge.length }) : tr("vp.endpoints", { count: g.device_count })}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </section>

        <div ref={detailRef} className="vpt-detail-slot">
          {mode === "devices" ? (
            selectedEntry ? (
              <DevicePanel key={selectedEntry.agent_id} entry={selectedEntry} onForced={() => fleet.refresh()} />
            ) : (
              <div className="vpt-card vpt-empty-panel">
                <p className="vpt-sub">{tr("vpt.pickDevice")}</p>
              </div>
            )
          ) : selectedGroup ? (
            <PolicyPanel
              key={selectedGroup.id}
              group={selectedGroup}
              entries={entriesByGroup.get(selectedGroup.id) ?? []}
              onSaved={() => {
                groups.refresh();
                fleet.refresh();
              }}
            />
          ) : (
            <div className="vpt-card vpt-empty-panel">
              <p className="vpt-sub">{tr("vp.noGroup")}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
