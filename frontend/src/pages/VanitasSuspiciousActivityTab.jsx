import { useEffect, useMemo, useState } from "react";
import { useAuth } from "../AuthContext.jsx";
import SummaryCard from "../components/SummaryCard.jsx";
import { IconDownload } from "../components/icons.jsx";
import { exportSuspiciousEventsToExcel } from "../export.js";
import {
  isErrorPayload,
  useVanitasAgents,
  useVanitasSuspiciousEventCorrelation,
  useVanitasSuspiciousEvents,
  useVanitasSuspiciousEventsSummary,
} from "../hooks/useDashboardData.js";
import { ALERT_SEVERITY_COLORS, ALERT_SEVERITY_LABEL } from "../theme.js";
import { api } from "../api.js";
import { ConfirmButton, fmtDateTime, fmtRelative, hasVanitasAccess, VanitasWizardShell } from "./vanitasShared.jsx";

/**
 * Onglet transverse "Activités suspectes" (jalon "détection d'activités suspectes sur les
 * postes", 2026-09-14) — croise les nouvelles détections comportementales Vanitas (processus
 * suspects, journal d'événements Windows, connexions réseau sortantes, support amovible USB,
 * filtrées LOCALEMENT côté agent avant remontée, voir le plan de ce jalon) avec les alertes
 * Defender du même poste (bloc de corrélation, chargé en lazy à l'ouverture du détail).
 *
 * Nichée dans le groupe "Sécurité" de la nav Vanitas, au-dessus de "Conformité" (voir
 * VanitasSidebar.jsx — placement demandé par Nicolas le 2026-09-14, remplace le top-level du
 * plan validé) — c'est un nouveau jalon dédié, pas une extension d'un onglet existant. Gardé en
 * lecture par le nouveau module de permission "activites_suspectes" (`hasVanitasAccess`) ; les 3
 * actions de triage (Accuser réception/Faux positif/Escalader) exigent en plus l'écriture.
 *
 * Sévérité : les chaînes `low`/`med`/`high` reçues du backend mappent DIRECTEMENT vers les
 * tokens sémantiques "sacrés" déjà utilisés partout ailleurs (`.vanitas-hud-sev-pill`,
 * `--hud-good`/`--hud-warn`/`--hud-high`, identiques aux `--low`/`--med`/`--high` de Pandore,
 * voir docs/internal/ARCHITECTURE.md §6) — jamais une palette inventée pour cette page. Le bandeau KPI
 * réutilise `.strip`/`SummaryCard` (Pandore) plutôt que les tuiles `.vanitas-hud-kpi` : les deux
 * cohabitent déjà dans ce dashboard, `.strip-item.c-low/c-med/c-high` correspond littéralement
 * au vocabulaire de sévérité de ce jalon (low/med/high), pas besoin d'un mapping supplémentaire.
 */

export const SEVERITY_LABEL_FR = { low: "Faible", med: "Moyenne", high: "Élevée" };
// `.vanitas-hud-sev-pill` (styles.css) attend low/medium/high — "med" est la seule chaîne du
// vocabulaire backend qui ne coïncide pas lettre à lettre avec sa classe CSS existante.
const SEVERITY_PILL_TONE = { low: "low", med: "medium", high: "high" };

export const SIGNAL_TYPE_LABEL_FR = {
  process: "Processus",
  event_log: "Journal d'événements",
  network: "Réseau",
  usb: "Support amovible (USB)",
};
// Couleurs = jetons --hud-* déjà existants (jamais inventées), un signal = une teinte, même
// esprit que CATEGORY_META de VanitasActivityLogTab.jsx.
const SIGNAL_TYPE_COLOR = {
  process: "var(--hud-accent)",
  event_log: "var(--hud-warn)",
  network: "var(--hud-accent2)",
  usb: "var(--hud-good)",
};

export const STATUS_LABEL_FR = {
  new: "Nouveau",
  acknowledged: "Accusé réception",
  false_positive: "Faux positif",
  escalated: "Escaladé",
};
// `.vanitas-hud-status-pill` (styles.css) — classes déjà utilisées ailleurs pour un statut de
// commande (ok/bad/pending), réemployées ici pour un statut de triage plutôt que d'inventer une
// 2e famille de pastilles de statut.
const STATUS_PILL_TONE = { new: "warn", acknowledged: "pending", false_positive: "ok", escalated: "bad" };

const SIGNAL_TYPE_OPTIONS = ["process", "event_log", "network", "usb"];
const SEVERITY_OPTIONS = ["high", "med", "low"];
const STATUS_OPTIONS = ["new", "acknowledged", "false_positive", "escalated"];
const RANGE_OPTIONS = [
  { key: "7", label: "7 jours", days: 7 },
  { key: "30", label: "30 jours", days: 30 },
  { key: "90", label: "90 jours", days: 90 },
  { key: "all", label: "Tout", days: null },
];

export function sinceIsoFor(rangeKey) {
  const range = RANGE_OPTIONS.find((r) => r.key === rangeKey);
  if (!range || range.days === null) return undefined;
  return new Date(Date.now() - range.days * 86_400_000).toISOString();
}

/** Format lisible du champ `detail` (déjà un objet côté serveur pour le détail unitaire ;
 * potentiellement une chaîne JSON selon la route pour la liste — jamais supposer un seul
 * format, même prudence que `parseCommandResult` (vanitasShared.jsx)). */
export function prettyDetail(detail) {
  if (detail == null) return null;
  if (typeof detail === "string") {
    try {
      return JSON.stringify(JSON.parse(detail), null, 2);
    } catch {
      return detail;
    }
  }
  try {
    return JSON.stringify(detail, null, 2);
  } catch {
    return String(detail);
  }
}

export function SeverityPill({ severity }) {
  return (
    <span className={`vanitas-hud-sev-pill ${SEVERITY_PILL_TONE[severity] ?? "neutral"}`}>
      {SEVERITY_LABEL_FR[severity] ?? severity}
    </span>
  );
}

export function StatusPill({ status }) {
  return (
    <span className={`vanitas-hud-status-pill ${STATUS_PILL_TONE[status] ?? "warn"}`}>
      {STATUS_LABEL_FR[status] ?? status}
    </span>
  );
}

export function SignalTypeBadge({ signalType }) {
  const color = SIGNAL_TYPE_COLOR[signalType] ?? "var(--hud-ink-faint)";
  return (
    <span className="badge" style={{ background: "rgba(255,255,255,.06)", color }}>
      {SIGNAL_TYPE_LABEL_FR[signalType] ?? signalType}
    </span>
  );
}

/**
 * Table triable, réutilisée telle quelle par la vue transverse (ci-dessous) ET par le pane
 * "Activités suspectes" de la fiche poste (`VanitasDeviceDetail.jsx`, filtré sur `agent_id`) —
 * `showHost` masqué dans ce 2e cas (le poste est déjà connu du contexte, colonne redondante).
 */
export function SuspiciousEventsTable({ events, loading, error, onSelect, showHost = true }) {
  const [sortKey, setSortKey] = useState("occurred_at");
  const [sortDir, setSortDir] = useState(-1);

  function handleSort(key) {
    if (sortKey === key) {
      setSortDir((d) => -d);
    } else {
      setSortKey(key);
      setSortDir(key === "occurred_at" ? -1 : 1);
    }
  }

  const sorted = useMemo(() => {
    const SEVERITY_RANK = { high: 3, med: 2, low: 1 };
    function value(e) {
      if (sortKey === "severity") return SEVERITY_RANK[e.severity] ?? 0;
      if (sortKey === "occurred_at") return new Date(e.occurred_at).getTime();
      return (e[sortKey] ?? "").toString().toLowerCase();
    }
    return [...events].sort((a, b) => {
      const va = value(a);
      const vb = value(b);
      if (typeof va === "string") return va.localeCompare(vb) * sortDir;
      return (va - vb) * sortDir;
    });
  }, [events, sortKey, sortDir]);

  function arrow(key) {
    return sortKey === key ? (sortDir === -1 ? "▾" : "▴") : "";
  }

  if (error) return <p className="vanitas-hud-error">{error}</p>;
  if (loading) return <p className="vanitas-hud-empty-note">CHARGEMENT…</p>;
  if (sorted.length === 0) {
    return <p className="vanitas-hud-empty-note">Aucun événement suspect ne correspond à ce filtre.</p>;
  }

  return (
    <div className="vanitas-hud-table-wrap">
      <table className="vanitas-hud-table">
        <thead>
          <tr>
            <th className={`sortable${sortKey === "severity" ? " sorted" : ""}`} onClick={() => handleSort("severity")}>
              Sévérité <span className="arrow">{arrow("severity")}</span>
            </th>
            {showHost && (
              <th className={`sortable${sortKey === "hostname" ? " sorted" : ""}`} onClick={() => handleSort("hostname")}>
                Poste <span className="arrow">{arrow("hostname")}</span>
              </th>
            )}
            <th className={`sortable${sortKey === "signal_type" ? " sorted" : ""}`} onClick={() => handleSort("signal_type")}>
              Signal <span className="arrow">{arrow("signal_type")}</span>
            </th>
            <th>Règle / résumé</th>
            <th className={`sortable${sortKey === "status" ? " sorted" : ""}`} onClick={() => handleSort("status")}>
              Statut <span className="arrow">{arrow("status")}</span>
            </th>
            <th className={`sortable${sortKey === "occurred_at" ? " sorted" : ""}`} onClick={() => handleSort("occurred_at")}>
              Survenu le <span className="arrow">{arrow("occurred_at")}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((e) => (
            <tr key={e.id} onClick={() => onSelect(e)} tabIndex={0} role="button">
              <td>
                <SeverityPill severity={e.severity} />
              </td>
              {showHost && <td className="vanitas-hud-host">{e.hostname}</td>}
              <td>
                <SignalTypeBadge signalType={e.signal_type} />
              </td>
              <td>
                <div>{e.summary || e.matched_rule}</div>
                {e.summary && e.matched_rule && (
                  <div className="vanitas-hud-card-note" style={{ fontFamily: "var(--mono)" }}>
                    {e.matched_rule}
                  </div>
                )}
              </td>
              <td>
                <StatusPill status={e.status} />
              </td>
              <td>{fmtDateTime(e.occurred_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Bloc de corrélation Defender — chargé en LAZY à l'ouverture du panneau de détail (jamais au
 * chargement de la liste), route Pandore native `GET .../correlation` (`device_overview.py`,
 * pas un proxy Vanitas). Réutilise `ALERT_SEVERITY_COLORS`/`ALERT_SEVERITY_LABEL`
 * (theme.js) : vocabulaire de sévérité Defender (High/Medium/Low/Informational/UnSpecified),
 * volontairement DISTINCT du vocabulaire low/med/high de ce jalon — jamais mélangé. */
function DefenderCorrelationBlock({ eventId }) {
  const correlation = useVanitasSuspiciousEventCorrelation();

  useEffect(() => {
    correlation.ensureLoaded(eventId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eventId]);

  const entry = correlation.state[eventId];
  if (!entry || entry.loading) {
    return <p className="vanitas-hud-empty-note">Corrélation Defender — chargement…</p>;
  }
  if (entry.error) {
    return <p className="vanitas-hud-error">{entry.error}</p>;
  }
  const overview = entry.data;
  if (!overview) return null;

  const defender = overview.defender;
  if (!defender?.found) {
    return (
      <p className="vanitas-hud-empty-note">
        Ce poste n'a pas été retrouvé sur Microsoft Defender for Endpoint
        {defender?.error ? ` (${defender.error})` : ""}.
      </p>
    );
  }

  const alerts = defender.alerts ?? [];
  if (alerts.length === 0) {
    return <p className="vanitas-hud-empty-note">Aucune alerte Defender active sur ce poste actuellement.</p>;
  }

  return (
    <div>
      {alerts.slice(0, 8).map((a) => (
        <div className="vanitas-hud-feed-row" key={a.id}>
          <span
            className="badge"
            style={{
              background: "rgba(255,255,255,.06)",
              color: ALERT_SEVERITY_COLORS[a.severity] ?? ALERT_SEVERITY_COLORS.UnSpecified,
            }}
          >
            {ALERT_SEVERITY_LABEL[a.severity] ?? a.severity}
          </span>
          <span className="vanitas-hud-feed-cmd" style={{ flex: 1 }}>
            {a.title}
          </span>
          <span className="vanitas-hud-feed-time">{fmtDateTime(a.alertCreationTime ?? a.firstActivity)}</span>
        </div>
      ))}
    </div>
  );
}

// Jalon "confinement" (mini-EDR, 2026-09-17) — fenêtre de contexte demandée par Nicolas pour
// reconstituer la chaîne d'événements menant à l'alerte principale (ex. clé USB → connexion
// suspecte → process), pas une valeur configurable : 3h est un choix de cadrage, pas un réglage.
const PRIOR_ALERTS_WINDOW_HOURS = 3;

/** Alertes du MÊME poste dans les 3h précédant celle-ci (bornes strictes, jamais l'alerte
 * elle-même) — `agent_id`/`since`/`until` déjà supportés par `GET /suspicious-events`, aucune
 * nouvelle route (voir routes/suspicious_activity.py). Non bloquant pour le reste du panneau :
 * une erreur ici n'empêche jamais de voir/traiter l'alerte principale. */
function PriorAlertsBlock({ event }) {
  const [state, setState] = useState({ status: "loading", data: [] });

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading", data: [] });
    const until = event.occurred_at;
    const since = new Date(new Date(event.occurred_at).getTime() - PRIOR_ALERTS_WINDOW_HOURS * 3_600_000).toISOString();
    api.vanitas.suspiciousEvents({ agentId: event.agent_id, since, until }).then(
      (payload) => {
        if (cancelled) return;
        setState(isErrorPayload(payload) ? { status: "error", data: [] } : { status: "done", data: payload });
      },
      () => {
        if (!cancelled) setState({ status: "error", data: [] });
      }
    );
    return () => {
      cancelled = true;
    };
  }, [event.id, event.agent_id, event.occurred_at]);

  if (state.status === "loading") {
    return <p className="vanitas-hud-empty-note">Chargement…</p>;
  }
  if (state.status === "error") {
    return null; // Contexte optionnel — jamais bloquant pour le reste du panneau.
  }
  if (state.data.length === 0) {
    return (
      <p className="vanitas-hud-empty-note">
        Aucune autre alerte sur ce poste dans les {PRIOR_ALERTS_WINDOW_HOURS}h précédentes.
      </p>
    );
  }

  // Le serveur trie `occurred_at desc` (le plus récent d'abord) — inversé ici pour lire la
  // chaîne d'événements dans l'ordre chronologique, le sens naturel d'un "avant l'alerte".
  const chronological = [...state.data].reverse();
  return (
    <div>
      {chronological.map((e) => (
        <div className="vanitas-hud-feed-row" key={e.id}>
          <SeverityPill severity={e.severity} />
          <SignalTypeBadge signalType={e.signal_type} />
          <span className="vanitas-hud-feed-cmd" style={{ flex: 1 }}>
            {e.summary || e.matched_rule}
          </span>
          <span className="vanitas-hud-feed-time">{fmtDateTime(e.occurred_at)}</span>
        </div>
      ))}
    </div>
  );
}

// Seuls les signaux avec un process associé peuvent proposer "Tuer le process" — un signal
// "event_log" (compte créé, RDP, échec d'authentification, purge de journal) ou "usb" n'a pas
// de PID à cibler (voir SuspiciousActivityRuleEngine.cs).
const KILLABLE_SIGNAL_TYPES = new Set(["process", "network"]);

/**
 * Boutons de confinement (jalon "mini-EDR", 2026-09-17) — TOUJOURS manuels, 2 clics
 * (`ConfirmButton`), jamais déclenchés par la détection elle-même (voir la maquette validée
 * avec Nicolas). "Tuer le process" seulement si le signal en porte un (voir
 * `KILLABLE_SIGNAL_TYPES` et le `detail` déjà chargé) ; "Isoler le réseau"/"Lever l'isolement"
 * togglent selon `Agent.network_isolated` — jamais les deux boutons à la fois.
 *
 * Réutilise `useVanitasAgents()` (déjà chargé/caché ailleurs dans le dashboard, voir
 * VanitasDevicesTab.jsx) plutôt qu'une nouvelle route dédiée : l'état d'isolement voyage déjà
 * sur `AgentSummary` (jalon "confinement", `routes/agents.py`).
 */
function ContainmentControls({ event, onIsolationChanged }) {
  const { user } = useAuth();
  const canContain = hasVanitasAccess(user, "activites_suspectes", "write");
  const agents = useVanitasAgents();

  useEffect(() => {
    agents.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [state, setState] = useState({ busy: null, error: null });

  if (!canContain) return null;

  // 🔧 Revue de sécurité du 2026-09-17 — tant que `useVanitasAgents()` n'a pas résolu au moins
  // une fois, `agents.state.data` vaut `[]` (état initial du hook) : sans cette garde, un poste
  // DÉJÀ isolé afficherait brièvement le bouton "Isoler le réseau" (destructif) au lieu de
  // "Lever l'isolement", le temps d'un aller-retour réseau — jamais montrer l'un ou l'autre tant
  // que l'état réel n'est pas connu.
  const agentsReady = agents.state.status === "done";
  const agent = agentsReady ? (agents.state.data ?? []).find((a) => a.id === event.agent_id) : undefined;
  const canKill = KILLABLE_SIGNAL_TYPES.has(event.signal_type) && (event.detail?.pid != null || event.detail?.process_name);
  const isIsolated = !!agent?.network_isolated;

  async function runCommand(commandType) {
    setState({ busy: commandType, error: null });
    try {
      const payload = await api.vanitas.queueCommand(event.agent_id, commandType, null, null, null, event.id);
      if (isErrorPayload(payload)) {
        setState({ busy: null, error: payload.message });
      } else {
        setState({ busy: null, error: null });
        agents.refresh();
        // Une AUTRE instance de `useVanitasAgents()` (compteur d'onglet "Postes isolés", panneau
        // dédié) ne partage pas cet état local — `cachedCall` ne fait que partager la PROMESSE,
        // pas de pub/sub entre montages (voir cache.js) — donc chacune doit être notifiée pour se
        // rafraîchir elle-même plutôt que de rester périmée après une action de confinement.
        if (commandType === "isolate_network" || commandType === "lift_isolation") onIsolationChanged?.();
      }
    } catch (err) {
      setState({ busy: null, error: err.message });
    }
  }

  return (
    <>
      <p className="vanitas-cmd-detail-section-title">Actions de confinement</p>
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center", marginBottom: "8px" }}>
        {canKill && (
          <ConfirmButton
            className="vanitas-danger-btn"
            label={state.busy === "kill_process" ? "Envoi…" : "Tuer le process"}
            confirmLabel={`Confirmer ? (PID ${event.detail?.pid ?? "inconnu"})`}
            disabled={state.busy !== null}
            onConfirm={() => runCommand("kill_process")}
          />
        )}
        {!agentsReady ? (
          <span className="vanitas-hud-card-note">État réseau : chargement…</span>
        ) : isIsolated ? (
          <ConfirmButton
            className="vanitas-queue-btn"
            label={state.busy === "lift_isolation" ? "Envoi…" : "Lever l'isolement"}
            confirmLabel="Confirmer la levée ?"
            disabled={state.busy !== null}
            onConfirm={() => runCommand("lift_isolation")}
          />
        ) : (
          <ConfirmButton
            className="vanitas-danger-btn"
            label={state.busy === "isolate_network" ? "Envoi…" : "Isoler le réseau"}
            confirmLabel="Confirmer l'isolement ?"
            disabled={state.busy !== null}
            onConfirm={() => runCommand("isolate_network")}
          />
        )}
      </div>
      {isIsolated && (
        <p className="vanitas-hud-card-note" style={{ marginBottom: "8px" }}>
          Poste isolé du réseau{agent.network_isolated_by ? ` par ${agent.network_isolated_by}` : ""}, {fmtRelative(agent.network_isolated_at)}.
        </p>
      )}
      {state.error && <p className="error-note">{state.error}</p>}
    </>
  );
}

/**
 * Panneau de détail — JSON `detail` formaté lisiblement, `matched_rule`, historique de triage
 * (`handled_by`/`handled_at`/`handled_note`), corrélation Defender lazy, 3 actions gatées en
 * écriture. Réutilisé tel quel par la fiche poste (`VanitasDeviceDetail.jsx`).
 */
export function SuspiciousEventDetailModal({ event, onClose, onUpdated, onIsolationChanged }) {
  const { user } = useAuth();
  const canWrite = hasVanitasAccess(user, "activites_suspectes", "write");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(null); // null | status en cours d'envoi
  const [error, setError] = useState(null);
  const [current, setCurrent] = useState(event);

  useEffect(() => {
    // Si le parent nous repasse le MÊME événement (ex. sa ligne de liste vient d'être
    // rafraîchie après un triage), on garde le `detail` déjà chargé plutôt que de le perdre le
    // temps d'un aller-retour réseau — sinon chaque accusé de réception/faux positif/escalade
    // ferait clignoter "Aucun détail" pendant le re-fetch.
    setCurrent((prev) => (prev && prev.id === event.id ? { ...event, detail: prev.detail } : event));
    setNote("");
    setError(null);
    // La liste (`GET /suspicious-events`) n'inclut jamais `detail` (payload potentiellement
    // volumineux, même logique que `RuleSummaryOut` côté conformité) — seul le détail unitaire
    // (`GET /suspicious-events/{id}`) le fournit. On le récupère à l'ouverture du panneau.
    let cancelled = false;
    api.vanitas.suspiciousEvent(event.id).then((full) => {
      if (!cancelled && !isErrorPayload(full)) {
        setCurrent((prev) => (prev.id === full.id ? { ...prev, detail: full.detail } : prev));
      }
    });
    return () => {
      cancelled = true;
    };
  }, [event]);

  async function applyStatus(status) {
    setBusy(status);
    setError(null);
    try {
      const payload = await api.vanitas.updateSuspiciousEvent(current.id, { status, note: note.trim() || null });
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        // Le PUT (comme la liste) ne renvoie pas `detail` — le fusionner plutôt que remplacer
        // `current`, sinon le détail déjà chargé disparaîtrait après le premier triage.
        setCurrent((prev) => ({ ...prev, ...payload, detail: prev.detail }));
        setNote("");
        onUpdated?.(payload);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  const detailText = prettyDetail(current.detail);
  // Miroir de `_ALLOWED_TRANSITIONS` côté serveur (routes/suspicious_activity.py) : "new" et
  // "acknowledged" ont encore des transitions sortantes, "false_positive"/"escalated" sont
  // terminaux. Un mapping local plutôt qu'un appel réseau juste pour savoir quels boutons
  // activer — le serveur reste la seule source de vérité (400 si jamais désynchronisé).
  const canTransitionFurther = current.status === "new" || current.status === "acknowledged";

  return (
    <VanitasWizardShell onClose={onClose} wide>
      <div className="vanitas-wiz-header">
        <div className="vanitas-wiz-header-icon">
          <SeverityPill severity={current.severity} />
        </div>
        <div className="vanitas-wiz-header-text">
          <h2>{current.summary || current.matched_rule}</h2>
          <p>
            {current.hostname} · {SIGNAL_TYPE_LABEL_FR[current.signal_type] ?? current.signal_type}
          </p>
        </div>
      </div>

      <div className="vanitas-wiz-body">
        <div className="vanitas-cmd-detail-meta">
          <StatusPill status={current.status} />
          <span className="vanitas-cmd-detail-meta-item">
            Règle : <b>{current.matched_rule}</b>
          </span>
          <span className="vanitas-cmd-detail-meta-item">
            Survenu le <b>{fmtDateTime(current.occurred_at)}</b>
          </span>
          <span className="vanitas-cmd-detail-meta-item">
            Reçu le <b>{fmtDateTime(current.received_at)}</b>
          </span>
        </div>

        {current.handled_by && (
          <>
            <p className="vanitas-cmd-detail-section-title">Historique de triage</p>
            <p className="vanitas-hud-card-note">
              Traité par <b>{current.handled_by}</b> le {fmtDateTime(current.handled_at)}
              {current.handled_note ? ` — « ${current.handled_note} »` : ""}
            </p>
          </>
        )}

        <p className="vanitas-cmd-detail-section-title">Détail</p>
        {detailText ? (
          <pre className="vanitas-cmd-detail-pre">{detailText}</pre>
        ) : (
          <p className="vanitas-hud-empty-note" style={{ padding: "8px 0" }}>
            Aucun détail structuré supplémentaire pour cet événement.
          </p>
        )}

        <p className="vanitas-cmd-detail-section-title">
          Alertes précédentes sur ce poste ({PRIOR_ALERTS_WINDOW_HOURS}h avant)
        </p>
        <PriorAlertsBlock event={current} />

        <p className="vanitas-cmd-detail-section-title">Corrélation Defender</p>
        <DefenderCorrelationBlock eventId={current.id} />

        <ContainmentControls event={current} onIsolationChanged={onIsolationChanged} />

        {canWrite && (
          <>
            <p className="vanitas-cmd-detail-section-title">Traiter cet événement</p>
            <textarea
              className="filter-input"
              style={{ width: "100%", minHeight: "60px", marginBottom: "10px" }}
              placeholder="Note de triage (optionnelle)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              disabled={busy !== null}
            />
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
              {/* Transitions valides côté serveur (routes/suspicious_activity.py::
                  _ALLOWED_TRANSITIONS) : new -> {acknowledged, false_positive, escalated},
                  acknowledged -> {false_positive, escalated} — "Accuser réception" n'a de sens
                  QUE depuis "new" (rien à accuser une 2e fois) ; "Faux positif"/"Escalader"
                  restent possibles depuis "new" ET "acknowledged". `false_positive`/`escalated`
                  sont TERMINAUX — les 3 boutons se désactivent depuis ces deux statuts. */}
              <button
                type="button"
                className="vanitas-queue-btn"
                onClick={() => applyStatus("acknowledged")}
                disabled={busy !== null || current.status !== "new"}
              >
                {busy === "acknowledged" ? "Envoi…" : "Accuser réception"}
              </button>
              <button
                type="button"
                className="vanitas-ghost-btn"
                onClick={() => applyStatus("false_positive")}
                disabled={busy !== null || !canTransitionFurther}
              >
                {busy === "false_positive" ? "Envoi…" : "Faux positif"}
              </button>
              <button
                type="button"
                className="vanitas-danger-btn"
                onClick={() => applyStatus("escalated")}
                disabled={busy !== null || !canTransitionFurther}
              >
                {busy === "escalated" ? "Envoi…" : "Escalader"}
              </button>
            </div>
            {!canTransitionFurther && (
              <p className="vanitas-hud-card-note" style={{ marginTop: "8px" }}>
                Déjà traité — plus aucune transition possible depuis « {STATUS_LABEL_FR[current.status]} ».
              </p>
            )}
            {error && <p className="error-note">{error}</p>}
          </>
        )}
      </div>
    </VanitasWizardShell>
  );
}

/**
 * Onglet "Postes isolés" (jalon "confinement", 2026-09-17, demande de Nicolas — "possible de
 * mettre en place un onglet dans la page pour voir les postes qui sont sous isolement avec la
 * raison ?") — simple FILTRE sur `useVanitasAgents()` déjà chargé/caché ailleurs dans le
 * dashboard (`network_isolated === true`), jamais une nouvelle route dédiée. La raison
 * (`network_isolated_reason`, un INSTANTANÉ, voir models.py) est cliquable quand l'alerte
 * d'origine existe encore (`network_isolated_event_id`) — rouvre son détail, y compris le
 * bouton "Lever l'isolement" déjà présent dans `ContainmentControls`, donc le bouton de CETTE
 * ligne n'est qu'un raccourci, pas le seul chemin possible.
 */
function IsolatedDevicesPanel({ onOpenEvent, onIsolationChanged }) {
  const { user } = useAuth();
  const canContain = hasVanitasAccess(user, "activites_suspectes", "write");
  const agents = useVanitasAgents();

  useEffect(() => {
    agents.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [busyId, setBusyId] = useState(null);
  const [error, setError] = useState(null);

  if (agents.state.status === "loading") {
    return <p className="vanitas-hud-empty-note">CHARGEMENT…</p>;
  }

  const isolated = (agents.state.data ?? []).filter((a) => a.network_isolated);

  async function liftFor(agent) {
    setBusyId(agent.id);
    setError(null);
    try {
      const payload = await api.vanitas.queueCommand(agent.id, "lift_isolation");
      if (isErrorPayload(payload)) setError(payload.message);
      else {
        agents.refresh();
        onIsolationChanged?.();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
    }
  }

  function openReason(agent) {
    if (!agent.network_isolated_event_id) return;
    api.vanitas.suspiciousEvent(agent.network_isolated_event_id).then((full) => {
      if (!isErrorPayload(full)) onOpenEvent(full);
    });
  }

  return (
    <div className="vanitas-hud-card vanitas-hud-frame">
      <div className="vanitas-hud-card-head">
        <h2>
          {isolated.length} poste{isolated.length > 1 ? "s" : ""} sous isolement réseau
        </h2>
      </div>
      {error && <p className="error-note">{error}</p>}
      {isolated.length === 0 ? (
        <p className="vanitas-hud-empty-note">Aucun poste isolé actuellement.</p>
      ) : (
        <div className="vanitas-hud-table-wrap">
          <table className="vanitas-hud-table">
            <thead>
              <tr>
                <th>Poste</th>
                <th>Raison</th>
                <th>Isolé par</th>
                <th>Depuis</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {isolated.map((a) => (
                <tr key={a.id}>
                  <td className="vanitas-hud-host">{a.hostname}</td>
                  <td>
                    {a.network_isolated_event_id ? (
                      <span
                        role="button"
                        tabIndex={0}
                        className="vanitas-hud-card-note"
                        style={{ cursor: "pointer", textDecoration: "underline" }}
                        onClick={() => openReason(a)}
                        onKeyDown={(e) => e.key === "Enter" && openReason(a)}
                      >
                        {a.network_isolated_reason ?? "Isolement manuel"}
                      </span>
                    ) : (
                      a.network_isolated_reason ?? "Isolement manuel"
                    )}
                  </td>
                  <td>{a.network_isolated_by ?? "—"}</td>
                  <td>{fmtRelative(a.network_isolated_at)}</td>
                  <td>
                    {canContain && (
                      <ConfirmButton
                        className="vanitas-queue-btn"
                        label={busyId === a.id ? "Envoi…" : "Lever l'isolement"}
                        confirmLabel="Confirmer ?"
                        disabled={busyId !== null}
                        onConfirm={() => liftFor(a)}
                      />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default function VanitasSuspiciousActivityTab() {
  const [pageTab, setPageTab] = useState("alerts");
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [signalFilter, setSignalFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [rangeKey, setRangeKey] = useState("30");
  const [selectedEvent, setSelectedEvent] = useState(null);

  const summary = useVanitasSuspiciousEventsSummary();
  const agentsForCount = useVanitasAgents();
  useEffect(() => {
    summary.ensureLoaded();
    agentsForCount.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const isolatedCount = (agentsForCount.state.data ?? []).filter((a) => a.network_isolated).length;

  const filters = useMemo(
    () => ({
      severity: severityFilter === "all" ? undefined : severityFilter,
      signalType: signalFilter === "all" ? undefined : signalFilter,
      status: statusFilter === "all" ? undefined : statusFilter,
      since: sinceIsoFor(rangeKey),
    }),
    [severityFilter, signalFilter, statusFilter, rangeKey]
  );
  const events = useVanitasSuspiciousEvents(filters);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return events.state.data;
    return events.state.data.filter((e) =>
      [e.hostname, e.summary, e.matched_rule].filter(Boolean).join(" ").toLowerCase().includes(q)
    );
  }, [events.state.data, query]);

  function handleUpdated() {
    events.refresh();
    summary.refresh();
  }

  const [exportState, setExportState] = useState({ status: "idle", error: null });
  async function handleExport() {
    setExportState({ status: "exporting", error: null });
    try {
      await exportSuspiciousEventsToExcel(filtered, {
        severity: SEVERITY_LABEL_FR,
        signalType: SIGNAL_TYPE_LABEL_FR,
        status: STATUS_LABEL_FR,
      });
      setExportState({ status: "idle", error: null });
    } catch (err) {
      setExportState({ status: "idle", error: err.message || "Échec de l'export Excel." });
    }
  }

  const bySeverity = summary.state.data?.by_severity ?? { low: 0, med: 0, high: 0 };
  const byStatus = summary.state.data?.by_status ?? { new: 0, acknowledged: 0, false_positive: 0, escalated: 0 };

  return (
    <div className="vanitas-hud">
      <div style={{ display: "flex", borderBottom: "1px solid var(--hud-line)", marginBottom: "18px" }}>
        <button
          type="button"
          className={`vanitas-tab-btn${pageTab === "alerts" ? " active" : ""}`}
          onClick={() => setPageTab("alerts")}
        >
          Alertes
        </button>
        <button
          type="button"
          className={`vanitas-tab-btn${pageTab === "isolated" ? " active" : ""}`}
          onClick={() => setPageTab("isolated")}
        >
          Postes isolés
          {isolatedCount > 0 && <span className="vanitas-tab-btn-badge">{isolatedCount}</span>}
        </button>
      </div>

      {pageTab === "isolated" ? (
        <IsolatedDevicesPanel onOpenEvent={setSelectedEvent} onIsolationChanged={() => agentsForCount.refresh()} />
      ) : (
        <>
          <div className="strip" style={{ marginBottom: "20px" }}>
            <SummaryCard title="Sévérité élevée" value={bySeverity.high ?? 0} tone="danger" hint="événements" />
            <SummaryCard title="Sévérité moyenne" value={bySeverity.med ?? 0} tone="warning" hint="événements" />
            <SummaryCard title="Sévérité faible" value={bySeverity.low ?? 0} tone="good" hint="événements" />
            <SummaryCard
              title="Non traités"
              value={byStatus.new ?? 0}
              tone={(byStatus.new ?? 0) > 0 ? "danger" : "good"}
              hint="statut « nouveau »"
            />
          </div>

          <div className="vanitas-hud-toolbar" style={{ marginBottom: "12px", flexWrap: "wrap" }}>
        <div className="vanitas-hud-search">
          <span className="prompt">&gt;</span>
          <input
            type="text"
            placeholder="Rechercher (poste, résumé, règle)…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
          />
        </div>
        <select className="filter-input" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="all">Toute sévérité</option>
          {SEVERITY_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL_FR[s]}
            </option>
          ))}
        </select>
        <select className="filter-input" value={signalFilter} onChange={(e) => setSignalFilter(e.target.value)}>
          <option value="all">Tout signal</option>
          {SIGNAL_TYPE_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {SIGNAL_TYPE_LABEL_FR[s]}
            </option>
          ))}
        </select>
        <select className="filter-input" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="all">Tout statut</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {STATUS_LABEL_FR[s]}
            </option>
          ))}
        </select>
        <select className="filter-input" value={rangeKey} onChange={(e) => setRangeKey(e.target.value)}>
          {RANGE_OPTIONS.map((r) => (
            <option key={r.key} value={r.key}>
              {r.label}
            </option>
          ))}
        </select>
        <button
          type="button"
          className="vanitas-export-btn"
          style={{ marginLeft: "auto" }}
          onClick={handleExport}
          disabled={exportState.status === "exporting"}
        >
          <IconDownload />
          {exportState.status === "exporting" ? "Export…" : "Exporter Excel"}
        </button>
      </div>
      {exportState.error && <p className="error-note" style={{ margin: "0 0 12px" }}>{exportState.error}</p>}

          <div className="vanitas-susp-scroll">
            <SuspiciousEventsTable
              events={filtered}
              loading={events.state.status === "loading"}
              error={events.state.error}
              onSelect={setSelectedEvent}
            />
          </div>
        </>
      )}

      {selectedEvent && (
        <SuspiciousEventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onUpdated={(updated) => {
            setSelectedEvent(updated);
            handleUpdated();
          }}
          onIsolationChanged={() => agentsForCount.refresh()}
        />
      )}
    </div>
  );
}
