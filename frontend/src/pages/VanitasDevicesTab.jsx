import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { IconDownload } from "../components/icons.jsx";
import { exportPostesToExcel } from "../export.js";
import {
  isErrorPayload,
  listPayloadError,
  useVanitasAgentCompliance,
  useVanitasAgentInventory,
  useVanitasAgentVulnerabilities,
  useVanitasAgents,
  useVanitasCommands,
  useVanitasGroups,
} from "../hooks/useDashboardData.js";
import VanitasDeviceDetail from "./VanitasDeviceDetail.jsx";
import {
  CERT_WARNING_DAYS,
  COMMAND_LABELS,
  CertSegBar,
  ConfirmButton,
  STALE_HOURS,
  certTone,
  daysUntil,
  fmtRelative,
  isOnline,
  summarizeGroupRules,
  toneVar,
} from "./vanitasShared.jsx";
import { tr } from "../i18n/core.js";

function sortVal(a, key) {
  if (key === "hostname") return a.hostname ?? "";
  if (key === "certDays") {
    const d = daysUntil(a.cert_not_after);
    return d === null ? -Infinity : d;
  }
  if (key === "apps") return a.apps_count ?? 0;
  // "lastSeen" — plus petit = vu plus récemment (millisecondes écoulées depuis last_seen).
  return a.last_seen ? Date.now() - new Date(a.last_seen).getTime() : Infinity;
}

/**
 * "Vanitas" > Postes (jalon 8, refonte HUD) — remplace la table plate d'origine (jalon 5,
 * étape 7) par un bandeau KPI + recherche/filtres + table enrichie (certificat en barre
 * segmentée, statut en pastille pulsante, dernière commande visible sans ouvrir la fiche).
 * Identité visuelle propre à Vanitas ("façon cyberpunk mais pro", demande explicite de
 * Nicolas après trois maquettes comparées) — voir `.vanitas-hud` dans styles.css, scopée pour
 * ne jamais déteindre sur le reste du dashboard ("dossier sombre").
 *
 * "Dernière commande" par agent dérivée de `useVanitasCommands()` (fleet-wide, déjà utilisée
 * par VanitasOverviewTab.jsx/VanitasCommandsTab.jsx) — pas de nouvel appel réseau, juste un
 * regroupement côté client par `agent_id` en gardant la plus récente par `created_at`.
 *
 * "Retirer de l'inventaire" (déjà possible depuis la fiche poste, jalon 7) est maintenant
 * AUSSI accessible directement depuis une ligne de la liste — même `ConfirmButton` (deux
 * clics), le clic sur le bouton stoppe sa propagation pour ne jamais déclencher la navigation
 * de la ligne vers la fiche poste.
 */
export default function VanitasDevicesTab({ vanitasNav }) {
  const agents = useVanitasAgents();
  const inventory = useVanitasAgentInventory();
  const vulnerabilities = useVanitasAgentVulnerabilities();
  const compliance = useVanitasAgentCompliance();
  const commands = useVanitasCommands();
  // Groupes (2026-09-08) — chargés ici (pas dans VanitasDeviceDetail.jsx) pour bénéficier du
  // même cache partagé que VanitasGroupsTab.jsx, jamais deux appels réseau indépendants pour
  // la même liste selon l'onglet ouvert en premier.
  const groups = useVanitasGroups();

  const [selectedId, setSelectedId] = useState(null);
  const [detailCommands, setDetailCommands] = useState({ status: "idle", data: [], error: null });

  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [sortKey, setSortKey] = useState("lastSeen");
  const [sortDir, setSortDir] = useState(1);
  const [removeError, setRemoveError] = useState(null);

  useEffect(() => {
    agents.ensureLoaded();
    commands.ensureLoaded();
    groups.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Groupes (2026-09-08) — `groupById` pour résoudre `agent.group_ids` en badges nommés,
  // `staticGroups` pour le sélecteur d'ajout (jamais un groupe DYNAMIQUE, sans objet — ses
  // membres sont calculés par motif, pas affectés à la main).
  const groupById = useMemo(() => {
    const map = new Map();
    for (const g of groups.state.data ?? []) map.set(g.id, g);
    return map;
  }, [groups.state.data]);
  const staticGroups = useMemo(
    () => (groups.state.data ?? []).filter((g) => !g.rules),
    [groups.state.data]
  );

  const latestCommandByAgent = useMemo(() => {
    const map = new Map();
    for (const c of commands.state.data ?? []) {
      const prev = map.get(c.agent_id);
      if (!prev || new Date(c.created_at) > new Date(prev.created_at)) map.set(c.agent_id, c);
    }
    return map;
  }, [commands.state.data]);

  const [exportState, setExportState] = useState({ status: "idle", error: null });
  async function handleExport() {
    setExportState({ status: "exporting", error: null });
    try {
      await exportPostesToExcel(agents.state.data ?? [], groupById, latestCommandByAgent, isOnline);
      setExportState({ status: "idle", error: null });
    } catch (err) {
      setExportState({ status: "idle", error: err.message || tr("v.exportFailed") });
    }
  }

  const counts = useMemo(() => {
    const list = agents.state.data ?? [];
    const total = list.length;
    const online = list.filter(isOnline).length;
    const cert = list.filter((a) => {
      const d = daysUntil(a.cert_not_after);
      return d !== null && d < CERT_WARNING_DAYS;
    }).length;
    const stale = list.filter((a) => {
      if (!a.last_seen) return true;
      return (Date.now() - new Date(a.last_seen).getTime()) / 3_600_000 > STALE_HOURS;
    }).length;
    return { total, online, offline: total - online, cert, stale };
  }, [agents.state.data]);

  const rows = useMemo(() => {
    const list = agents.state.data ?? [];
    const q = query.trim().toLowerCase();
    const filtered = list.filter((a) => {
      if (q && !a.hostname.toLowerCase().includes(q)) return false;
      const online = isOnline(a);
      if (filter === "online" && !online) return false;
      if (filter === "offline" && online) return false;
      if (filter === "cert") {
        const d = daysUntil(a.cert_not_after);
        if (!(d !== null && d < CERT_WARNING_DAYS)) return false;
      }
      return true;
    });
    return [...filtered].sort((a, b) => {
      const va = sortVal(a, sortKey);
      const vb = sortVal(b, sortKey);
      if (typeof va === "string") return va.localeCompare(vb) * sortDir;
      return (va - vb) * sortDir;
    });
  }, [agents.state.data, query, filter, sortKey, sortDir]);

  function handleSort(key) {
    if (sortKey === key) {
      setSortDir((d) => -d);
    } else {
      setSortKey(key);
      setSortDir(1);
    }
  }

  function loadDetailCommands(agentId) {
    setDetailCommands({ status: "loading", data: [], error: null });
    api.vanitas.agentCommands(agentId).then(
      (payload) => {
        const err = listPayloadError(payload);
        setDetailCommands({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => setDetailCommands({ status: "error", data: [], error: err.message })
    );
  }

  function selectAgent(agentId) {
    setSelectedId(agentId);
    inventory.ensureLoaded(agentId);
    vulnerabilities.ensureLoaded(agentId);
    compliance.ensureLoaded(agentId);
    loadDetailCommands(agentId);
  }

  // Navigation depuis la Vue d'ensemble (2026-09-11, "les blocs sont juste là mais ne renvoie
  // sur aucune page") — `vanitasNav.payload` porte soit `selectAgentId` (ouvre directement la
  // fiche d'un poste précis, ex. depuis "Postes à surveiller"), soit `filter` (applique une
  // pastille de filtre déjà existante, ex. depuis la tuile "En ligne"). Gardé sur
  // `vanitasNav?.token` (pas `.payload`) — voir bumpVanitasNav (../navigation.js) : incrémente
  // à chaque clic, y compris vers la même cible, pour redéclencher même un reclic identique.
  useEffect(() => {
    if (!vanitasNav?.payload) return;
    const { selectAgentId, filter: navFilter } = vanitasNav.payload;
    if (selectAgentId) selectAgent(selectAgentId);
    if (navFilter) setFilter(navFilter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vanitasNav?.token]);

  // Groupes (2026-09-08, many-to-many) — assignation directement depuis la liste ("via la
  // page avec tous les postes", demande explicite de Nicolas), en plus des cases à cocher déjà
  // en place sur la fiche poste (VanitasDeviceDetail.jsx) — mêmes appels, même contrat d'erreur.
  // Un poste peut désormais appartenir à PLUSIEURS groupes statiques à la fois.
  async function handleAddToGroup(agentId, groupId) {
    if (!groupId) return;
    setRemoveError(null);
    try {
      const payload = await api.vanitas.addAgentToGroup(agentId, groupId);
      if (isErrorPayload(payload)) {
        setRemoveError(payload.message);
      } else {
        agents.refresh();
      }
    } catch (err) {
      setRemoveError(err.message);
    }
  }

  async function handleRemoveFromGroup(agentId, groupId) {
    setRemoveError(null);
    try {
      const payload = await api.vanitas.removeAgentFromGroup(agentId, groupId);
      if (isErrorPayload(payload)) {
        setRemoveError(payload.message);
      } else {
        agents.refresh();
      }
    } catch (err) {
      setRemoveError(err.message);
    }
  }

  async function handleRemove(agentId) {
    setRemoveError(null);
    try {
      const payload = await api.vanitas.removeAgent(agentId);
      if (isErrorPayload(payload)) {
        setRemoveError(payload.message);
      } else {
        agents.refresh();
      }
    } catch (err) {
      setRemoveError(err.message);
    }
  }

  const selectedAgent = selectedId ? agents.state.data.find((a) => a.id === selectedId) ?? null : null;

  if (selectedAgent) {
    return (
      <VanitasDeviceDetail
        key={selectedAgent.id}
        agent={selectedAgent}
        inv={inventory.state[selectedAgent.id]}
        vulns={vulnerabilities.state[selectedAgent.id]}
        compliance={compliance.state[selectedAgent.id]}
        commands={detailCommands}
        groups={groups.state.data}
        onGroupChanged={() => agents.refresh()}
        onQueued={() => loadDetailCommands(selectedAgent.id)}
        onBack={() => setSelectedId(null)}
        onRemoved={() => {
          setSelectedId(null);
          agents.refresh();
        }}
      />
    );
  }

  return (
    <div className="vanitas-hud">
      {agents.state.error && <p className="vanitas-hud-error">{agents.state.error}</p>}
      {removeError && <p className="vanitas-hud-error">{removeError}</p>}

      <div className="vanitas-hud-strip">
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-accent)" }}>
          <div className="label">
            {tr("vd.endpoints")}
            <span className="tag">{tr("vd.total")}</span>
          </div>
          <div className="value">{counts.total}</div>
          <div className="bar">
            <i style={{ width: "100%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-good)" }}>
          <div className="label">
            {tr("vd.online")}
            <span className="tag">LIVE</span>
          </div>
          <div className="value">{counts.online}</div>
          <div className="bar">
            <i style={{ width: counts.total ? `${Math.round((counts.online / counts.total) * 100)}%` : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-warn)" }}>
          <div className="label">
            {tr("vd.certificate")}
            <span className="tag">{tr("vd.certTag")}</span>
          </div>
          <div className="value">{counts.cert}</div>
          <div className="bar">
            <i style={{ width: counts.total ? `${Math.round((counts.cert / counts.total) * 100)}%` : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-high)" }}>
          <div className="label">
            {tr("vd.silent")}
            <span className="tag">{tr("vd.silentTag")}</span>
          </div>
          <div className="value">{counts.stale}</div>
          <div className="bar">
            <i style={{ width: counts.total ? `${Math.round((counts.stale / counts.total) * 100)}%` : "0%" }} />
          </div>
        </div>
      </div>

      <div className="vanitas-hud-toolbar">
        <div className="vanitas-hud-search">
          <span className="prompt">&gt;</span>
          <input
            type="text"
            placeholder="grep --hostname ..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
          />
        </div>
        <div className="vanitas-hud-chips">
          <button type="button" className={`vanitas-hud-chip${filter === "all" ? " active" : ""}`} onClick={() => setFilter("all")}>
            <span className="led" />
            {tr("vd.chip.all")} <span className="n">{counts.total}</span>
          </button>
          <button type="button" className={`vanitas-hud-chip${filter === "online" ? " active" : ""}`} onClick={() => setFilter("online")}>
            <span className="led" />
            {tr("vd.chip.online")} <span className="n">{counts.online}</span>
          </button>
          <button
            type="button"
            className={`vanitas-hud-chip tone-high${filter === "offline" ? " active" : ""}`}
            onClick={() => setFilter("offline")}
          >
            <span className="led" />
            {tr("vd.chip.silent")} <span className="n">{counts.offline}</span>
          </button>
          <button type="button" className={`vanitas-hud-chip tone-high${filter === "cert" ? " active" : ""}`} onClick={() => setFilter("cert")}>
            <span className="led" />
            {tr("vd.chip.cert")} <span className="n">{counts.cert}</span>
          </button>
        </div>
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>{rows.length === counts.total ? tr("vd.countAll", { count: counts.total }) : tr("vd.countOf", { shown: rows.length, count: counts.total })}</h2>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <span className="vanitas-hud-card-note">{tr("vd.clickRow")}</span>
            <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting"}>
              <IconDownload />
              {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
            </button>
          </div>
        </div>
        {exportState.error && <p className="error-note" style={{ margin: "0 0 12px" }}>{exportState.error}</p>}
        <div className="vanitas-hud-table-wrap">
          <table className="vanitas-hud-table">
            <thead>
              <tr>
                <th className={`sortable${sortKey === "hostname" ? " sorted" : ""}`} onClick={() => handleSort("hostname")}>
                  {tr("vd.col.endpoint")} <span className="arrow">{sortKey === "hostname" && sortDir === -1 ? "▴" : "▾"}</span>
                </th>
                <th className={`sortable${sortKey === "lastSeen" ? " sorted" : ""}`} onClick={() => handleSort("lastSeen")}>
                  {tr("vd.col.status")} <span className="arrow">{sortKey === "lastSeen" && sortDir === -1 ? "▴" : "▾"}</span>
                </th>
                <th className={`sortable${sortKey === "certDays" ? " sorted" : ""}`} onClick={() => handleSort("certDays")}>
                  {tr("vd.col.certificate")} <span className="arrow">{sortKey === "certDays" && sortDir === -1 ? "▴" : "▾"}</span>
                </th>
                <th className={`sortable${sortKey === "apps" ? " sorted" : ""}`} onClick={() => handleSort("apps")}>
                  {tr("vd.col.apps")} <span className="arrow">{sortKey === "apps" && sortDir === -1 ? "▴" : "▾"}</span>
                </th>
                <th>{tr("vd.col.group")}</th>
                <th>{tr("vd.col.lastCommand")}</th>
                <th></th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {agents.state.status === "loading" ? (
                <tr className="vanitas-hud-empty">
                  <td colSpan={8}>{tr("v.loading")}</td>
                </tr>
              ) : rows.length === 0 ? (
                <tr className="vanitas-hud-empty">
                  <td colSpan={8}>
                    {counts.total === 0 ? tr("vd.noAgent") : tr("vd.noMatch")}
                  </td>
                </tr>
              ) : (
                rows.map((a) => {
                  const online = isOnline(a);
                  const days = daysUntil(a.cert_not_after);
                  const tone = toneVar(certTone(days));
                  const cmd = latestCommandByAgent.get(a.id);
                  return (
                    <tr key={a.id} tabIndex={0} role="button" aria-label={tr("vd.openAria", { host: a.hostname })} onClick={() => selectAgent(a.id)}>
                      <td className="vanitas-hud-host">
                        <span className="name">{a.hostname}</span>
                        <span className="id">
                          {a.id.slice(0, 12)}… · {tr("vd.agentVersion", { version: a.agent_version ? `v${a.agent_version}` : tr("vd.unknownVersion") })}
                        </span>
                      </td>
                      <td>
                        <div className="vanitas-hud-status">
                          <span className={`vanitas-hud-pulse ${online ? "on" : "off"}`} />
                          <span className={`lbl${online ? "" : " off"}`}>{tr(online ? "vd.chip.online" : "vd.chip.silent")}</span>
                          <span className="meta">{fmtRelative(a.last_seen)}</span>
                        </div>
                      </td>
                      <td className="vanitas-hud-cert">
                        <CertSegBar days={days} />
                        <span className="vanitas-hud-cert-days" style={{ color: tone }}>
                          {days === null ? "—" : tr("vd.daysLeft", { n: Math.max(0, Math.round(days)) })}
                        </span>
                      </td>
                      <td>
                        <span className="vanitas-hud-apps-badge">{a.apps_count}</span>
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <div className="vanitas-hud-group-cell">
                          {(a.group_ids ?? []).map((gid) => {
                            const g = groupById.get(gid);
                            if (!g) return null;
                            const isDynamic = !!g.rules;
                            return (
                              <span
                                key={gid}
                                className={`vanitas-hud-group-chip${isDynamic ? " dynamic" : ""}`}
                                title={isDynamic ? tr("vd.dynamicMember", { rule: summarizeGroupRules(g.rules) }) : g.name}
                              >
                                {g.name}
                                {!isDynamic && (
                                  <span className="rm" onClick={() => handleRemoveFromGroup(a.id, gid)}>
                                    ×
                                  </span>
                                )}
                              </span>
                            );
                          })}
                          {staticGroups.filter((g) => !(a.group_ids ?? []).includes(g.id)).length > 0 && (
                            <select
                              className="vanitas-hud-group-add"
                              value=""
                              onChange={(e) => handleAddToGroup(a.id, e.target.value)}
                            >
                              <option value="">{tr("vd.addGroup")}</option>
                              {staticGroups
                                .filter((g) => !(a.group_ids ?? []).includes(g.id))
                                .map((g) => (
                                  <option key={g.id} value={g.id}>
                                    {g.name}
                                  </option>
                                ))}
                            </select>
                          )}
                        </div>
                      </td>
                      <td className="vanitas-hud-cmd">
                        {cmd ? (
                          <>
                            <div className="cmd-name">{COMMAND_LABELS[cmd.command_type] ?? cmd.command_type}</div>
                            <div className="cmd-meta">
                              <span
                                className={`vanitas-hud-status-pill ${
                                  cmd.status === "pending" || cmd.status === "running" ? "pending" : cmd.success ? "ok" : "bad"
                                }`}
                              >
                                {tr(cmd.status === "pending" || cmd.status === "running" ? "vd.cmd.inProgress" : cmd.success ? "vd.cmd.ok" : "vd.cmd.failed")}
                              </span>
                              <span>{fmtRelative(cmd.created_at)}</span>
                            </div>
                          </>
                        ) : (
                          <span className="vanitas-hud-cmd-none">{tr("vd.noCommand")}</span>
                        )}
                      </td>
                      <td className="vanitas-hud-actions" onClick={(e) => e.stopPropagation()}>
                        <ConfirmButton
                          label={tr("vd.remove")}
                          confirmLabel={tr("vd.confirm")}
                          className="vanitas-hud-purge-btn"
                          onConfirm={() => handleRemove(a.id)}
                          title={tr("vd.removeTitle")}
                        />
                      </td>
                      <td>
                        <span className="vanitas-hud-chev">›</span>
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
