import { useMemo, useState } from "react";
import { api } from "../api.js";
import { fmtDateTime, latestCommandOf, parseCommandResult } from "./vanitasShared.jsx";
import { IconDownload, IconPackage, IconSettings, IconShield, IconWrench } from "../components/icons.jsx";

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

const LEVEL_OPTIONS = [
  { key: "error", label: "Erreur" },
  { key: "warning", label: "Avertissement" },
  { key: "information", label: "Information" },
  { key: "audit_success", label: "Succès d'audit", tone: "good" },
  { key: "audit_failure", label: "Échec d'audit", tone: "high" },
];

const LEVEL_LABEL_FR = {
  audit_success: "Succès d'audit",
  audit_failure: "Échec d'audit",
  critical: "Critique",
  error: "Erreur",
  warning: "Avertissement",
  information: "Information",
  verbose: "Détaillé",
};

const COMMON_IDS = [
  { grp: "Connexions", rows: [["Connexion réussie", 4624], ["Échec de connexion", 4625]] },
  { grp: "Comptes", rows: [["Compte créé", 4720], ["Ajout à un groupe", 4732]] },
  { grp: "Processus & journal", rows: [["Processus créé", 4688], ["Journal purgé", 1102]] },
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
        <div className="vanitas-evlog-tree-root">Journaux Windows</div>
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
          Tout sélectionner
        </button>
      </div>

      <div className="vanitas-evlog-main">
        <div className="vanitas-evlog-filter">
          <div className="vanitas-evlog-filter-title">Filtrer le journal — {[...channels].join(", ")}</div>
          <div className="vanitas-evlog-filter-grid">
            <div className="vanitas-evlog-field vanitas-evlog-field-since">
              <label>Depuis</label>
              <input type="date" value={since} max={until} onChange={(e) => setSince(e.target.value)} />
            </div>
            <div className="vanitas-evlog-field vanitas-evlog-field-until">
              <label>Jusqu'à</label>
              <input type="date" value={until} min={since} max={todayStr(0)} onChange={(e) => setUntil(e.target.value)} />
            </div>
            <div className="vanitas-evlog-field vanitas-evlog-field-level">
              <label>Niveau</label>
              <div className="vanitas-evlog-lvl-checks">
                {LEVEL_OPTIONS.map((l) => (
                  <label key={l.key} className="vanitas-evlog-lvl-check" style={l.tone ? { color: `var(--hud-${l.tone})` } : undefined}>
                    <input type="checkbox" checked={levels.has(l.key)} onChange={() => toggleLevel(l.key)} />
                    {l.label}
                  </label>
                ))}
              </div>
            </div>
            <div className="vanitas-evlog-field vanitas-evlog-id-field">
              <label>
                ID d'événement (inclure/exclure)
                <span className="vanitas-evlog-id-help">
                  <span className="link">· IDs courants</span>
                  <div className="vanitas-evlog-id-help-panel">
                    {COMMON_IDS.map((g) => (
                      <div key={g.grp}>
                        <div className="grp">{g.grp}</div>
                        {g.rows.map(([label, id]) => (
                          <div className="row" key={id}>
                            <span>{label}</span>
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
                  placeholder="ex. 4624,4625,-4634"
                  value={idsText}
                  onChange={(e) => setIdsText(e.target.value)}
                />
                <button type="button" className="vanitas-evlog-go-btn" disabled={busy || !canWrite} onClick={() => runSearch(null)}>
                  {busy ? "Envoi…" : "Filtrer"}
                </button>
              </div>
              <div className="vanitas-evlog-hint">Tape un tiret pour exclure : « 4624,4625,-4634 »</div>
            </div>
          </div>
          {!canWrite && <p className="vanitas-hud-empty-note">Lecture seule sur ce poste — recherche indisponible.</p>}
          {error && <p className="vanitas-hud-error">{error}</p>}
        </div>

        {waiting ? (
          <p className="vanitas-hud-empty-note">
            Recherche en file d'attente — l'agent la récupère au prochain cycle (jusqu'à ~5 min).
          </p>
        ) : failed ? (
          <p className="vanitas-hud-error">{latestAny.result || "La recherche a échoué."}</p>
        ) : !result ? (
          <p className="vanitas-hud-empty-note">Aucune recherche encore lancée sur ce poste.</p>
        ) : events.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            Aucun événement trouvé pour cette recherche. Le journal de ce poste ne conserve peut-être plus cette
            période (rotation locale, indépendante de Vanitas) — essaie une période plus récente.
          </p>
        ) : (
          <>
            <div className="vanitas-evlog-list-head">
              <span>Niveau</span>
              <span>Date et heure</span>
              <span>Source</span>
              <span>ID</span>
              <span>Catégorie de tâche</span>
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
                  <span className={`vanitas-evlog-lvl ${e.level}`}>{LEVEL_LABEL_FR[e.level] ?? e.level}</span>
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
                    Général
                  </span>
                  <span
                    className={`vanitas-evlog-detail-tab${detailTab === "xml" ? " active" : ""}`}
                    onClick={() => setDetailTab("xml")}
                  >
                    Détails (XML)
                  </span>
                </div>
                <div className="vanitas-evlog-detail-text">
                  {detailTab === "general" ? selected.description : selected.xml || "(XML indisponible)"}
                </div>
                <div className="vanitas-evlog-detail-meta">
                  <span>
                    <b>Journal :</b> {selected.channel}
                  </span>
                  <span>
                    <b>Source :</b> {selected.provider}
                  </span>
                  <span>
                    <b>ID :</b> {selected.event_id}
                  </span>
                  <span>
                    <b>RecordId :</b> {selected.record_id}
                  </span>
                </div>
              </div>
            )}

            <div className="vanitas-evlog-status-bar">
              <span>{events.length} événement{events.length > 1 ? "s" : ""} affiché{events.length > 1 ? "s" : ""}</span>
              {result?.has_more && channels.size > 1 && (
                <span className="more">⚠ Plafond atteint — sélectionne un seul canal pour paginer au-delà</span>
              )}
              {canPaginate && (
                <button
                  type="button"
                  className="vanitas-evlog-more-btn"
                  disabled={busy}
                  onClick={() => runSearch(result.next_after_record_id)}
                >
                  Voir les 2000 suivants →
                </button>
              )}
            </div>
          </>
        )}
      </div>

      <div className="vanitas-evlog-actions">
        <div className="vanitas-evlog-actions-title">Journal actuel</div>
        <button type="button" className="vanitas-evlog-act-btn primary" disabled={busy || !canWrite} onClick={() => runSearch(null)}>
          🔍 Rechercher
        </button>
        {selected && (
          <>
            <div className="vanitas-evlog-actions-title">Événement sélectionné</div>
            <button
              type="button"
              className="vanitas-evlog-act-btn"
              onClick={() => navigator.clipboard?.writeText(selected.description)}
            >
              Copier la description
            </button>
          </>
        )}
      </div>
    </div>
  );
}
