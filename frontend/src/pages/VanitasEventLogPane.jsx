import { useMemo, useState } from "react";
import { api } from "../api.js";
import { fmtDateTime, latestCommandOf, parseCommandResult } from "./vanitasShared.jsx";
import { IconDownload, IconPackage, IconSettings, IconShield, IconWrench } from "../components/icons.jsx";
import { localizedTable, tr } from "../i18n/core.js";

/**
 * "Journal d'événements Windows" (2026-09-16) — recherche PONCTUELLE à la demande sur ce
 * poste, à distinguer nettement du pane "Activités suspectes" (flux filtré en CONTINU par
 * l'agent). Maquette validée par Nicolas — structure inspirée de l'Observateur d'événements
 * (arbre des journaux / liste Niveau·Date·Source·ID·Catégorie / volet Général-Détails / volet
 * Actions), tokens de couleur Vanitas (`--hud-*`) conservés, jamais le gris Win32 d'origine.
 *
 * Chaque recherche met en file une commande `fetch_event_log` (voir `Commands/
 * EventLogFetcher.cs` côté agent, `commands.py::build_event_log_parameters` côté serveur) —
 * même mécanisme que "Diagnostic système"/"Inventaire matériel" (synchrone, ~5 min de délai via
 * le cycle de sondage de l'agent), pas un canal séparé. `latestCommandOf` ne retient que la
 * dernière commande TERMINÉE AVEC SUCCÈS ; `queuedAt` distingue "on attend le résultat de CETTE
 * recherche" d'un ancien résultat déjà affiché avant de recliquer "Filtrer".
 */

const CHANNELS = ["Security", "System", "Application", "Setup", "ForwardedEvents"];
const CHANNEL_LABELS = { ForwardedEvents: "Forwarded Events" };
// Même famille d'icônes traits fins que le reste de l'app (icons.jsx) — pas de pictogramme
// inventé pour ce pane : IconShield/IconPackage déjà "propriétaires" du sens sécurité/application
// ailleurs (Conformité, onglet Application Intune), réutilisés ici pour rester cohérent plutôt
// que de multiplier les symboles pour un même concept.
const CHANNEL_ICONS = {
  Security: IconShield,
  System: IconSettings,
  Application: IconPackage,
  Setup: IconWrench,
  ForwardedEvents: IconDownload,
};

// Level labels: ev.level.<key>; common-ID group and row labels: ev.grp.<grp> / ev.id.<id>.
const LEVEL_OPTIONS = [
  { key: "error" },
  { key: "warning" },
  { key: "information" },
  { key: "audit_success", tone: "good" },
  { key: "audit_failure", tone: "high" },
];

const LEVEL_LABEL = localizedTable("ev.level", ["audit_success", "audit_failure", "critical", "error", "warning", "information", "verbose"]);

const COMMON_IDS = [
  { grp: "logons", ids: [4624, 4625] },
  { grp: "accounts", ids: [4720, 4732] },
  { grp: "process", ids: [4688, 1102] },
];

/** "4624,4625,-4634" → { include: [4624,4625], exclude: [4634] } — même syntaxe que le champ
 * "ID d'événement" du vrai Observateur d'événements ("tape un tiret pour exclure"). */
function parseIdsText(text) {
  const include = [];
  const exclude = [];
  for (const raw of (text || "").split(",")) {
    const t = raw.trim();
    if (!t) continue;
    if (t.startsWith("-")) {
      const n = parseInt(t.slice(1), 10);
      if (!Number.isNaN(n)) exclude.push(n);
    } else {
      const n = parseInt(t, 10);
      if (!Number.isNaN(n)) include.push(n);
    }
  }
  return { include, exclude };
}

function isoStartOfDay(dateStr) {
  return `${dateStr}T00:00:00Z`;
}
function isoEndOfDay(dateStr) {
  return `${dateStr}T23:59:59Z`;
}

function todayStr(offsetDays = 0) {
  const d = new Date(Date.now() + offsetDays * 86_400_000);
  return d.toISOString().slice(0, 10);
}

export default function VanitasEventLogPane({ agent, commandList, onQueued, canWrite }) {
  const [channels, setChannels] = useState(() => new Set(["Security"]));
  const [since, setSince] = useState(todayStr(-14));
  const [until, setUntil] = useState(todayStr(0));
  const [levels, setLevels] = useState(() => new Set(["audit_success", "audit_failure"]));
  const [idsText, setIdsText] = useState("");
  const [queuedAt, setQueuedAt] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [detailTab, setDetailTab] = useState("general");

  const latestSuccess = latestCommandOf(commandList, "fetch_event_log");
  const latestAny = (commandList ?? []).find((c) => c.command_type === "fetch_event_log") ?? null;
  const waiting = queuedAt && (!latestAny || new Date(latestAny.created_at) < queuedAt);
  const failed = !waiting && latestAny && latestAny.status === "completed" && latestAny.success === false;
  const result = !waiting && latestSuccess ? parseCommandResult(latestSuccess.result) : null;
  const events = result?.events ?? [];
  const selected = events[selectedIdx] ?? null;

  function toggleChannel(ch) {
    setChannels((prev) => {
      const next = new Set(prev);
      if (next.has(ch)) next.delete(ch);
      else next.add(ch);
      return next.size ? next : prev; // toujours au moins un canal sélectionné
    });
  }
  function selectAllChannels() {
    setChannels(new Set(CHANNELS));
  }
  function toggleLevel(key) {
    setLevels((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  async function runSearch(afterRecordId = null) {
    setBusy(true);
    setError(null);
    try {
      const { include, exclude } = parseIdsText(idsText);
      const eventLogQuery = {
        channels: [...channels],
        since: isoStartOfDay(since),
        until: isoEndOfDay(until),
        event_ids_include: include,
        event_ids_exclude: exclude,
        levels: [...levels],
        after_record_id: afterRecordId,
        max_events: 2000,
      };
      const payload = await api.vanitas.queueCommand(agent.id, "fetch_event_log", null, null, eventLogQuery);
      if (payload?.error) {
        setError(payload.message);
      } else {
        setQueuedAt(new Date());
        setSelectedIdx(0);
        onQueued?.();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const canPaginate = result?.has_more && channels.size === 1 && result?.next_after_record_id != null;

  return (
    <div className="vanitas-evlog-shell">
      <div className="vanitas-evlog-tree">
        <div className="vanitas-evlog-tree-root">{tr("ev.windowsLogs")}</div>
        {CHANNELS.map((ch) => {
          const ChannelIcon = CHANNEL_ICONS[ch];
          return (
            <div
              key={ch}
              className={`vanitas-evlog-tree-leaf${channels.has(ch) ? " active" : ""}`}
              role="button"
              tabIndex={0}
              onClick={() => toggleChannel(ch)}
            >
              <ChannelIcon />
              {CHANNEL_LABELS[ch] ?? ch}
            </div>
          );
        })}
        <button type="button" className="vanitas-evlog-select-all" onClick={selectAllChannels}>
          {tr("ev.selectAll")}
        </button>
      </div>

      <div className="vanitas-evlog-main">
        <div className="vanitas-evlog-filter">
          <div className="vanitas-evlog-filter-title">{tr("ev.filterTitle", { channels: [...channels].join(", ") })}</div>
          <div className="vanitas-evlog-filter-grid">
            <div className="vanitas-evlog-field vanitas-evlog-field-since">
              <label>{tr("ev.since")}</label>
              <input type="date" value={since} max={until} onChange={(e) => setSince(e.target.value)} />
            </div>
            <div className="vanitas-evlog-field vanitas-evlog-field-until">
              <label>{tr("ev.until")}</label>
              <input type="date" value={until} min={since} max={todayStr(0)} onChange={(e) => setUntil(e.target.value)} />
            </div>
            <div className="vanitas-evlog-field vanitas-evlog-field-level">
              <label>{tr("ev.level")}</label>
              <div className="vanitas-evlog-lvl-checks">
                {LEVEL_OPTIONS.map((l) => (
                  <label key={l.key} className="vanitas-evlog-lvl-check" style={l.tone ? { color: `var(--hud-${l.tone})` } : undefined}>
                    <input type="checkbox" checked={levels.has(l.key)} onChange={() => toggleLevel(l.key)} />
                    {LEVEL_LABEL[l.key]}
                  </label>
                ))}
              </div>
            </div>
            <div className="vanitas-evlog-field vanitas-evlog-id-field">
              <label>
                {tr("ev.eventId")}
                <span className="vanitas-evlog-id-help">
                  <span className="link">{tr("ev.commonIds")}</span>
                  <div className="vanitas-evlog-id-help-panel">
                    {COMMON_IDS.map((g) => (
                      <div key={g.grp}>
                        <div className="grp">{tr(`ev.grp.${g.grp}`)}</div>
                        {g.ids.map((id) => (
                          <div className="row" key={id}>
                            <span>{tr(`ev.id.${id}`)}</span>
                            <b>{id}</b>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                </span>
              </label>
              <div className="vanitas-evlog-id-row">
                <input
                  type="text"
                  placeholder={tr("ev.idsPlaceholder")}
                  value={idsText}
                  onChange={(e) => setIdsText(e.target.value)}
                />
                <button type="button" className="vanitas-evlog-go-btn" disabled={busy || !canWrite} onClick={() => runSearch(null)}>
                  {busy ? tr("ev.sending") : tr("ev.filter")}
                </button>
              </div>
              <div className="vanitas-evlog-hint">{tr("ev.hint")}</div>
            </div>
          </div>
          {!canWrite && <p className="vanitas-hud-empty-note">{tr("ev.readOnly")}</p>}
          {error && <p className="vanitas-hud-error">{error}</p>}
        </div>

        {waiting ? (
          <p className="vanitas-hud-empty-note">
            {tr("ev.queued")}
          </p>
        ) : failed ? (
          <p className="vanitas-hud-error">{latestAny.result || tr("ev.failed")}</p>
        ) : !result ? (
          <p className="vanitas-hud-empty-note">{tr("ev.noSearch")}</p>
        ) : events.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            {tr("ev.noEvent")}
          </p>
        ) : (
          <>
            <div className="vanitas-evlog-list-head">
              <span>{tr("ev.col.level")}</span>
              <span>{tr("ev.col.datetime")}</span>
              <span>{tr("ev.col.source")}</span>
              <span>{tr("ev.col.id")}</span>
              <span>{tr("ev.col.task")}</span>
            </div>
            <div className="vanitas-evlog-list-wrap">
              {events.map((e, i) => (
                <div
                  key={e.record_id ?? i}
                  className={`vanitas-evlog-row${i === selectedIdx ? " sel" : ""}`}
                  role="button"
                  tabIndex={0}
                  onClick={() => {
                    setSelectedIdx(i);
                    setDetailTab("general");
                  }}
                >
                  <span className={`vanitas-evlog-lvl ${e.level}`}>{LEVEL_LABEL[e.level] ?? e.level}</span>
                  <span className="vanitas-evlog-time">{fmtDateTime(e.time)}</span>
                  <span className="vanitas-evlog-src">{e.provider}</span>
                  <span className="vanitas-evlog-eid">{e.event_id}</span>
                  <span className="vanitas-evlog-task">{e.task_category || "—"}</span>
                </div>
              ))}
            </div>

            {selected && (
              <div className="vanitas-evlog-detail">
                <div className="vanitas-evlog-detail-tabs">
                  <span
                    className={`vanitas-evlog-detail-tab${detailTab === "general" ? " active" : ""}`}
                    onClick={() => setDetailTab("general")}
                  >
                    {tr("ev.general")}
                  </span>
                  <span
                    className={`vanitas-evlog-detail-tab${detailTab === "xml" ? " active" : ""}`}
                    onClick={() => setDetailTab("xml")}
                  >
                    {tr("ev.xml")}
                  </span>
                </div>
                <div className="vanitas-evlog-detail-text">
                  {detailTab === "general" ? selected.description : selected.xml || tr("ev.xmlUnavailable")}
                </div>
                <div className="vanitas-evlog-detail-meta">
                  <span>
                    <b>{tr("ev.meta.log")}</b> {selected.channel}
                  </span>
                  <span>
                    <b>{tr("ev.meta.source")}</b> {selected.provider}
                  </span>
                  <span>
                    <b>{tr("ev.meta.id")}</b> {selected.event_id}
                  </span>
                  <span>
                    <b>{tr("ev.meta.record")}</b> {selected.record_id}
                  </span>
                </div>
              </div>
            )}

            <div className="vanitas-evlog-status-bar">
              <span>{tr("ev.shown", { count: events.length })}</span>
              {result?.has_more && channels.size > 1 && (
                <span className="more">{tr("ev.cap")}</span>
              )}
              {canPaginate && (
                <button
                  type="button"
                  className="vanitas-evlog-more-btn"
                  disabled={busy}
                  onClick={() => runSearch(result.next_after_record_id)}
                >
                  {tr("ev.next")}
                </button>
              )}
            </div>
          </>
        )}
      </div>

      <div className="vanitas-evlog-actions">
        <div className="vanitas-evlog-actions-title">{tr("ev.currentLog")}</div>
        <button type="button" className="vanitas-evlog-act-btn primary" disabled={busy || !canWrite} onClick={() => runSearch(null)}>
          {tr("ev.search")}
        </button>
        {selected && (
          <>
            <div className="vanitas-evlog-actions-title">{tr("ev.selectedEvent")}</div>
            <button
              type="button"
              className="vanitas-evlog-act-btn"
              onClick={() => navigator.clipboard?.writeText(selected.description)}
            >
              {tr("ev.copyDescription")}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
