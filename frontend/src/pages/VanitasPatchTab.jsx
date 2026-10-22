import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { IconDownload } from "../components/icons.jsx";
import { exportPatchStatusToExcel } from "../export.js";
import { isErrorPayload, useVanitasGroups, useVanitasPatchStatus } from "../hooks/useDashboardData.js";
import { ConfirmButton, VanitasWizardShell, fmtRelative } from "./vanitasShared.jsx";
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
 * _display_status`) — jamais recalculé ici, pour ne jamais diverger de ce que l'agent applique
 * réellement. 4 buckets de mises à jour par poste (`available`/`todo`/`in_progress`/`installed`)
 * — mêmes 3 catégories demandées par Nicolas ("en cours, à faire, disponible") + une 4ᵉ
 * ("installées, attend redémarrage") nécessaire pour les statuts déjà patchés.
 */

// Labels: vp.status.<key>; bucket labels/hints: vp.bucket.<key>[.hint].
const STATUS_META = {
  ok: { tone: "ok" },
  "pending-install": { tone: "pending-install" },
  installing: { tone: "installing", live: true },
  "pending-window": { tone: "pending-window" },
  forced: { tone: "forced" },
  off: { tone: "off" },
};
for (const [key, meta] of Object.entries(STATUS_META)) {
  Object.defineProperty(meta, "label", { get: () => tr(`vp.status.${key}`), enumerable: true });
}

const UPDATE_BUCKETS = [
  { key: "in_progress", cls: "inprogress" },
  { key: "todo", hasHint: true, cls: "todo" },
  { key: "available", hasHint: true, cls: "" },
  { key: "installed", hasHint: true, cls: "installed" },
];

// Statuts où "Forcer le redémarrage maintenant" a un sens — jamais sur un poste déjà à jour,
// déjà forcé, ou hors politique (rien n'a été installé automatiquement pour lui).
const FORCE_REBOOT_ELIGIBLE = new Set(["pending-install", "installing", "pending-window"]);

function StatusPill({ status }) {
  const meta = STATUS_META[status] ?? { label: status, tone: "off" };
  return (
    <span className={`vanitas-patch-status-pill ${meta.tone}`}>
      {meta.live && <span className="vanitas-patch-live-dot" />}
      {meta.label}
    </span>
  );
}

function DeviceDetailModal({ entry, onClose, onForced }) {
  const [error, setError] = useState(null);

  async function handleForce() {
    setError(null);
    try {
      const payload = await api.vanitas.queueCommand(entry.agent_id, "force_reboot");
      if (isErrorPayload(payload)) {
        setError(payload.message);
        return;
      }
      onForced();
    } catch (err) {
      setError(err.message);
    }
  }

  const sections = UPDATE_BUCKETS.map((b) => ({
    ...b,
    label: tr(`vp.bucket.${b.key}`),
    hint: b.hasHint ? tr(`vp.bucket.${b.key}.hint`) : null,
    items: entry[b.key] ?? [],
  })).filter((b) => b.items.length > 0);

  return (
    <VanitasWizardShell onClose={onClose}>
      <div className="vanitas-wiz-header">
        <span className="vanitas-wiz-header-icon">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
            <rect x="3" y="4" width="14" height="9" rx="1" />
            <path d="M2 16h16" strokeLinecap="round" />
            <path d="M7.5 16v-3M12.5 16v-3" strokeLinecap="round" />
          </svg>
        </span>
        <div className="vanitas-wiz-header-text">
          <h2>{entry.hostname}</h2>
          <p>Vanitas · {tr("vp.module")}{entry.group_name ? ` · ${entry.group_name}` : ""}</p>
        </div>
      </div>
      <div className="vanitas-wiz-body">
        <div className="vanitas-patch-meta-row">
          <StatusPill status={entry.status} />
          <span className="vanitas-patch-meta-badge">{tr("vp.lastCheck", { when: fmtRelative(entry.updated_at) })}</span>
          {entry.window_start && entry.window_end && (
            <span className="vanitas-patch-meta-badge">
              {tr("vp.window", { start: entry.window_start, end: entry.window_end, days: entry.grace_days })}
            </span>
          )}
        </div>

        {sections.length === 0 ? (
          <p className="vanitas-hud-empty-note" style={{ padding: "8px 0" }}>
            {tr("vp.noUpdate")}
          </p>
        ) : (
          sections.map((b) => (
            <div key={b.key} className="vanitas-patch-update-section">
              <p className="filter-chip-group-label">
                {b.label} ({b.items.length})
                {b.hint && <span className="vanitas-patch-section-hint"> — {b.hint}</span>}
              </p>
              <div className="vanitas-patch-update-list">
                {b.items.map((u) => (
                  <div key={u.kb} className={`vanitas-patch-update-row ${b.cls}`}>
                    <div className="vanitas-patch-update-kb">{u.kb}</div>
                    <div className="vanitas-patch-update-title">{u.title}</div>
                  </div>
                ))}
              </div>
            </div>
          ))
        )}

        {error && <p className="error-note">{error}</p>}

        <div className="wizard-actions">
          <button type="button" className="vanitas-ghost-btn" onClick={onClose}>
            {tr("vp.close")}
          </button>
          {FORCE_REBOOT_ELIGIBLE.has(entry.status) && (
            <ConfirmButton
              label={tr("vp.forceReboot")}
              confirmLabel={tr("vp.forceConfirm")}
              className="vanitas-danger-btn"
              onConfirm={handleForce}
            />
          )}
        </div>
      </div>
    </VanitasWizardShell>
  );
}

function PolicyCard({ group, onSaved }) {
  const [enabled, setEnabled] = useState(group.patch_enabled);
  const [windowStart, setWindowStart] = useState(group.patch_window_start ?? "20:00");
  const [windowEnd, setWindowEnd] = useState(group.patch_window_end ?? "06:00");
  const [graceDays, setGraceDays] = useState(group.patch_grace_days ?? 5);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleToggle(nextEnabled) {
    setEnabled(nextEnabled);
    if (!nextEnabled) {
      // Désactiver ne nécessite pas de fenêtre valide (le serveur ne l'exige que pour ACTIVER,
      // voir `routes/groups.py::update_patch_policy`) — enregistré immédiatement, pas de bouton
      // "Enregistrer" à cliquer en plus pour un simple arrêt.
      await save(false);
    }
  }

  async function save(nextEnabled = enabled) {
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.updatePatchPolicy(group.id, {
        enabled: nextEnabled,
        windowStart,
        windowEnd,
        graceDays: Number(graceDays) || 5,
      });
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        onSaved();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="vanitas-patch-policy-card">
      <div className="vanitas-patch-policy-head">
        <div>
          <span className="vanitas-patch-policy-name">{group.name}</span>
          <span className="vanitas-patch-policy-kind">{tr("vp.endpoints", { count: group.device_count })}</span>
        </div>
        <label className="vanitas-patch-switch">
          <input type="checkbox" checked={enabled} onChange={(e) => handleToggle(e.target.checked)} disabled={busy} />
          <span className="vanitas-patch-switch-track" />
          <span className="vanitas-patch-switch-knob" />
        </label>
      </div>
      <div className={`vanitas-patch-policy-config${enabled ? "" : " disabled"}`}>
        <div>
          <span className="filter-chip-group-label">{tr("vp.rebootWindow")}</span>
          <div className="vanitas-patch-window-row">
            <input type="time" value={windowStart} onChange={(e) => setWindowStart(e.target.value)} disabled={busy} />
            <span>→</span>
            <input type="time" value={windowEnd} onChange={(e) => setWindowEnd(e.target.value)} disabled={busy} />
          </div>
        </div>
        <div className="vanitas-patch-grace-row">
          <span className="filter-chip-group-label" style={{ margin: 0 }}>
            {tr("vp.grace")}
          </span>
          <input
            type="number"
            min={1}
            max={30}
            value={graceDays}
            onChange={(e) => setGraceDays(e.target.value)}
            disabled={busy}
          />
          <span>{tr("vp.graceSuffix")}</span>
        </div>
        <button type="button" className="vanitas-queue-btn" onClick={() => save()} disabled={busy}>
          {busy ? tr("vp.saving") : tr("vp.save")}
        </button>
      </div>
      {error && <p className="error-note">{error}</p>}
    </div>
  );
}

export default function VanitasPatchTab() {
  const fleet = useVanitasPatchStatus();
  const groups = useVanitasGroups();
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedAgentId, setSelectedAgentId] = useState(null);

  useEffect(() => {
    fleet.ensureLoaded();
    groups.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const entries = fleet.state.data ?? [];

  const counts = useMemo(() => {
    const c = { all: entries.length, ok: 0, "pending-window": 0, forced: 0, off: 0 };
    for (const e of entries) if (c[e.status] !== undefined) c[e.status]++;
    return c;
  }, [entries]);

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
    return entries.filter((e) => {
      if (statusFilter !== "all" && e.status !== statusFilter) return false;
      if (!q) return true;
      return e.hostname.toLowerCase().includes(q) || (e.group_name ?? "").toLowerCase().includes(q);
    });
  }, [entries, query, statusFilter]);

  const selected = selectedAgentId ? entries.find((e) => e.agent_id === selectedAgentId) ?? null : null;

  const error = fleet.state.error || groups.state.error;
  const loading = fleet.state.status === "loading" || groups.state.status === "loading";

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
          <div className="label">{tr("vp.kpi.tracked")}<span className="tag">{tr("vv.kpi.fleet")}</span></div>
          <div className="value">{counts.all}</div>
          <div className="bar"><i style={{ width: counts.all ? "100%" : "0%" }} /></div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-good)" }}>
          <div className="label">{tr("vp.kpi.upToDate")}<span className="tag">OK</span></div>
          <div className="value">{counts.ok}</div>
          <div className="bar"><i style={{ width: counts.all ? `${Math.round((counts.ok / counts.all) * 100)}%` : "0%" }} /></div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-accent)" }}>
          <div className="label">{tr("vp.kpi.awaiting")}<span className="tag">{tr("vp.kpi.patched")}</span></div>
          <div className="value">{counts["pending-window"]}</div>
          <div className="bar"><i style={{ width: counts.all ? `${Math.round((counts["pending-window"] / counts.all) * 100)}%` : "0%" }} /></div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-high)" }}>
          <div className="label">{tr("vp.kpi.forced")}<span className="tag">{tr("vp.kpi.grace")}</span></div>
          <div className="value">{counts.forced}</div>
          <div className="bar"><i style={{ width: counts.all ? `${Math.round((counts.forced / counts.all) * 100)}%` : "0%" }} /></div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-ink-faint)" }}>
          <div className="label">{tr("vp.kpi.off")}<span className="tag">{tr("vp.kpi.groupOff")}</span></div>
          <div className="value">{counts.off}</div>
          <div className="bar"><i style={{ width: counts.all ? `${Math.round((counts.off / counts.all) * 100)}%` : "0%" }} /></div>
        </div>
      </div>

      <div className="vanitas-hud-layout">
        <div className="vanitas-hud-main">
          <div className="vanitas-hud-card vanitas-hud-frame">
            <div className="vanitas-hud-card-head">
              <h2>{tr("vp.tracked", { shown: rows.length, total: entries.length })}</h2>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <span className="vanitas-hud-card-note">{tr("vp.clickRow")}</span>
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
                  placeholder={tr("vp.searchPlaceholder")}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  autoComplete="off"
                />
              </div>
              <div className="vanitas-hud-chips">
                <button type="button" className={`vanitas-hud-chip${statusFilter === "all" ? " active" : ""}`} onClick={() => setStatusFilter("all")}>
                  <span className="led" />
                  {tr("vv.all")} <span className="n">{counts.all}</span>
                </button>
                {Object.entries(STATUS_META).map(([key, meta]) => (
                  <button
                    key={key}
                    type="button"
                    className={`vanitas-hud-chip${statusFilter === key ? " active" : ""}`}
                    onClick={() => setStatusFilter(key)}
                  >
                    <span className="led" />
                    {meta.label.toUpperCase()} <span className="n">{entries.filter((e) => e.status === key).length}</span>
                  </button>
                ))}
              </div>
            </div>

            {entries.length === 0 ? (
              <p className="vanitas-hud-empty-note">{tr("vv.noAgent")}</p>
            ) : rows.length === 0 ? (
              <p className="vanitas-hud-empty-note">{tr("vv.noResult")}</p>
            ) : (
              <div className="vanitas-hud-table-wrap">
                <table className="vanitas-hud-table">
                  <thead>
                    <tr>
                      <th>{tr("vp.col.endpoint")}</th>
                      <th>{tr("vp.col.group")}</th>
                      <th>{tr("vp.col.status")}</th>
                      <th>{tr("vp.col.security")}</th>
                      <th>{tr("vp.col.lastCheck")}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((e) => {
                      const pendingCount = (e.todo?.length ?? 0) + (e.in_progress?.length ?? 0);
                      return (
                        <tr key={e.agent_id} onClick={() => setSelectedAgentId(e.agent_id)} tabIndex={0} role="button">
                          <td className="host">{e.hostname}</td>
                          <td>{e.group_name ? <span className="group-badge">{e.group_name}</span> : "—"}</td>
                          <td><StatusPill status={e.status} /></td>
                          <td className="vanitas-hud-cmd-none">{pendingCount}</td>
                          <td className="vanitas-hud-cmd-none">{fmtRelative(e.updated_at)}</td>
                          <td><span className="vanitas-hud-chev">›</span></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <aside className="vanitas-hud-rail">
          <div className="vanitas-hud-card vanitas-hud-frame">
            <div className="vanitas-hud-card-head">
              <h2>{tr("vp.policies")}</h2>
            </div>
            {(groups.state.data ?? []).length === 0 ? (
              <p className="vanitas-hud-empty-note">{tr("vp.noGroup")}</p>
            ) : (
              <div className="vanitas-patch-policy-list">
                {groups.state.data.map((g) => (
                  <PolicyCard key={g.id} group={g} onSaved={() => { groups.refresh(); fleet.refresh(); }} />
                ))}
              </div>
            )}
            <p className="vanitas-hud-empty-note" style={{ padding: "12px 0 0" }}>
              {tr("vp.disabledNote")}
            </p>
          </div>
        </aside>
      </div>

      {selected && (
        <DeviceDetailModal
          entry={selected}
          onClose={() => setSelectedAgentId(null)}
          onForced={() => {
            fleet.refresh();
            setSelectedAgentId(null);
          }}
        />
      )}
    </div>
  );
}
