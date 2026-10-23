import { useEffect, useMemo, useRef, useState } from "react";
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
import { CVE_SEVERITY_COLORS } from "../theme.js";
import VanitasDeviceDetail from "./VanitasDeviceDetail.jsx";
import {
  CERT_VALIDITY_DAYS,
  CERT_WARNING_DAYS,
  COMMAND_LABELS,
  ConfirmButton,
  STALE_HOURS,
  certTone,
  daysUntil,
  fmtDateTime,
  fmtRelative,
  isOnline,
  latestCommandResult,
  summarizeGroupRules,
  toneVar,
} from "./vanitasShared.jsx";
import { tr } from "../i18n/core.js";

// Connectivité en 3 états (refonte 2026-10-23) : la page mélangeait "silencieux" > 24 h (pastille)
// et > 7 j (tuile). En ligne < 24 h (`isOnline`), hors ligne 24 h – 7 j, silencieux > 7 j / jamais vu.
function connState(agent) {
  if (isOnline(agent)) return "online";
  if (!agent.last_seen) return "silent";
  return (Date.now() - new Date(agent.last_seen).getTime()) / 3_600_000 > STALE_HOURS ? "silent" : "offline";
}
const CONN_COLOR = { online: CVE_SEVERITY_COLORS.Low, offline: CVE_SEVERITY_COLORS.Medium, silent: CVE_SEVERITY_COLORS.Unknown };

function cmpVersion(a, b) {
  return (a || "").localeCompare(b || "", undefined, { numeric: true });
}

function sortVal(a, key, risk) {
  if (key === "hostname") return a.hostname ?? "";
  if (key === "certDays") {
    const d = daysUntil(a.cert_not_after);
    return d === null ? Infinity : d;
  }
  if (key === "risk") return -(risk ?? 0);
  // "lastSeen" — plus petit = vu plus récemment (millisecondes écoulées depuis last_seen).
  return a.last_seen ? Date.now() - new Date(a.last_seen).getTime() : Infinity;
}

function vulnCounts(entry) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  for (const v of entry?.data ?? []) {
    const s = (v.severity || "").toLowerCase();
    if (c[s] !== undefined) c[s]++;
    c.total++;
  }
  return c;
}

/**
 * "Vanitas" > Postes — jalon 8 (refonte HUD), puis refonte liste + aperçu (2026-10-23, maquette
 * canvas validée par Nicolas) : bandeau de synthèse (postes, connectivité en 3 états avec légende
 * cliquable, certificats < 30 j, version d'agent), liste compacte (recherche, tri, pastilles) et
 * APERÇU latéral du poste sélectionné. La fiche complète (VanitasDeviceDetail.jsx, inchangée)
 * s'ouvre depuis l'aperçu, ou directement via `vanitasNav.payload.selectAgentId`.
 *
 * "Dernière commande" par agent dérivée de `useVanitasCommands()` (fleet-wide, déjà partagée avec
 * la Vue d'ensemble / Commandes) — pas de nouvel appel réseau. Vulnérabilités chargées pour tout le
 * parc (même cache que la page Vulnérabilités) pour la pastille / le badge « CVE critiques » ;
 * inventaire et conformité chargés seulement pour le poste prévisualisé.
 *
 * Groupes et "Retirer de l'inventaire" passent de la ligne à l'aperçu (même `ConfirmButton` en
 * deux clics, mêmes appels, même contrat d'erreur). Classes `.vdp-*`.
 */
export default function VanitasDevicesTab({ vanitasNav }) {
  const agents = useVanitasAgents();
  const inventory = useVanitasAgentInventory();
  const vulnerabilities = useVanitasAgentVulnerabilities();
  const compliance = useVanitasAgentCompliance();
  const commands = useVanitasCommands();
  // Groupes (2026-09-08) — chargés ici (pas dans VanitasDeviceDetail.jsx) pour bénéficier du
  // même cache partagé que VanitasGroupsTab.jsx.
  const groups = useVanitasGroups();

  const [selectedId, setSelectedId] = useState(null);
  const [previewId, setPreviewId] = useState(null);
  const [detailCommands, setDetailCommands] = useState({ status: "idle", data: [], error: null });
  const detailRef = useRef(null);

  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [sortKey, setSortKey] = useState("lastSeen");
  const [removeError, setRemoveError] = useState(null);

  useEffect(() => {
    agents.ensureLoaded();
    commands.ensureLoaded();
    groups.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    for (const a of agents.state.data ?? []) vulnerabilities.ensureLoaded(a.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents.state.data]);

  const groupById = useMemo(() => {
    const map = new Map();
    for (const g of groups.state.data ?? []) map.set(g.id, g);
    return map;
  }, [groups.state.data]);
  const staticGroups = useMemo(() => (groups.state.data ?? []).filter((g) => !g.rules), [groups.state.data]);

  const commandsByAgent = useMemo(() => {
    const map = new Map();
    for (const c of commands.state.data ?? []) {
      if (!map.has(c.agent_id)) map.set(c.agent_id, []);
      map.get(c.agent_id).push(c);
    }
    for (const list of map.values()) list.sort((x, y) => new Date(y.created_at) - new Date(x.created_at));
    return map;
  }, [commands.state.data]);
  const latestCommandByAgent = useMemo(() => {
    const map = new Map();
    for (const [id, list] of commandsByAgent) map.set(id, list[0]);
    return map;
  }, [commandsByAgent]);

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

  const list = agents.state.data ?? [];
  const vulnByAgent = useMemo(() => {
    const map = new Map();
    for (const a of list) map.set(a.id, vulnCounts(vulnerabilities.state[a.id]));
    return map;
  }, [list, vulnerabilities.state]);

  const latestAgentVersion = useMemo(
    () => list.map((a) => a.agent_version).filter(Boolean).sort(cmpVersion).pop() ?? null,
    [list]
  );

  const counts = useMemo(() => {
    const c = { total: list.length, online: 0, offline: 0, silent: 0, cert: 0, risk: 0, latest: 0 };
    for (const a of list) {
      c[connState(a)]++;
      const d = daysUntil(a.cert_not_after);
      if (d !== null && d < CERT_WARNING_DAYS) c.cert++;
      if (vulnByAgent.get(a.id)?.critical) c.risk++;
      if (latestAgentVersion && a.agent_version === latestAgentVersion) c.latest++;
    }
    c.down = c.offline + c.silent;
    return c;
  }, [list, vulnByAgent, latestAgentVersion]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = list.filter((a) => {
      if (q && !a.hostname.toLowerCase().includes(q)) return false;
      const st = connState(a);
      if ((filter === "online" || filter === "offline" || filter === "silent") && st !== filter) return false;
      if (filter === "down" && st === "online") return false;
      if (filter === "cert") {
        const d = daysUntil(a.cert_not_after);
        if (!(d !== null && d < CERT_WARNING_DAYS)) return false;
      }
      if (filter === "risk" && !vulnByAgent.get(a.id)?.critical) return false;
      return true;
    });
    const risk = (a) => {
      const v = vulnByAgent.get(a.id);
      return v ? v.critical * 1e6 + v.high * 1e3 + v.medium : 0;
    };
    return [...filtered].sort((a, b) => {
      const va = sortVal(a, sortKey, risk(a));
      const vb = sortVal(b, sortKey, risk(b));
      if (typeof va === "string") return va.localeCompare(vb);
      return va - vb;
    });
  }, [list, query, filter, sortKey, vulnByAgent]);

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

  function openAgent(agentId) {
    setSelectedId(agentId);
    setPreviewId(agentId);
    inventory.ensureLoaded(agentId);
    vulnerabilities.ensureLoaded(agentId);
    compliance.ensureLoaded(agentId);
    loadDetailCommands(agentId);
  }

  function previewAgent(agentId) {
    setPreviewId(agentId);
    setRemoveError(null);
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  // Navigation depuis la Vue d'ensemble / EOL — `selectAgentId` ouvre directement la fiche ;
  // `filter` applique une pastille ("offline" de la Vue d'ensemble = tout ce qui n'est pas en
  // ligne, depuis la séparation hors ligne / silencieux → filtre "down", les deux pastilles
  // s'allument). Gardé sur `vanitasNav?.token` (voir bumpVanitasNav, ../navigation.js).
  useEffect(() => {
    if (!vanitasNav?.payload) return;
    const { selectAgentId, filter: navFilter } = vanitasNav.payload;
    if (selectAgentId) openAgent(selectAgentId);
    if (navFilter) setFilter(navFilter === "offline" ? "down" : navFilter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vanitasNav?.token]);

  async function runAction(call) {
    setRemoveError(null);
    try {
      const payload = await call();
      if (isErrorPayload(payload)) setRemoveError(payload.message);
      else agents.refresh();
    } catch (err) {
      setRemoveError(err.message);
    }
  }
  const handleAddToGroup = (agentId, groupId) => groupId && runAction(() => api.vanitas.addAgentToGroup(agentId, groupId));
  const handleRemoveFromGroup = (agentId, groupId) => runAction(() => api.vanitas.removeAgentFromGroup(agentId, groupId));
  const handleRemove = (agentId) => runAction(() => api.vanitas.removeAgent(agentId));

  const selectedAgent = selectedId ? list.find((a) => a.id === selectedId) ?? null : null;

  // Aperçu : chargement paresseux de l'inventaire (OS) et de la conformité du poste affiché.
  const preview = rows.find((a) => a.id === previewId) ?? rows[0] ?? null;
  useEffect(() => {
    if (!preview || selectedAgent) return;
    inventory.ensureLoaded(preview.id);
    compliance.ensureLoaded(preview.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preview?.id, selectedAgent]);

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
          setPreviewId(null);
          agents.refresh();
        }}
      />
    );
  }

  const isOn = (k) => filter === k || (filter === "down" && (k === "offline" || k === "silent"));
  const chips = [
    ["all", tr("vd.f.all"), counts.total, "var(--hud-accent)"],
    ["online", tr("vd.f.online"), counts.online, CONN_COLOR.online],
    ["offline", tr("vd.f.offline"), counts.offline, CONN_COLOR.offline],
    ["silent", tr("vd.f.silent"), counts.silent, CONN_COLOR.silent],
    ["cert", tr("vd.f.cert"), counts.cert, CVE_SEVERITY_COLORS.Medium],
    ["risk", tr("vd.f.risk"), counts.risk, CVE_SEVERITY_COLORS.Critical],
  ];

  return (
    <div className="vanitas-hud vdp">
      {agents.state.error && <p className="vanitas-hud-error">{agents.state.error}</p>}

      <section className="vdp-card vdp-sum" aria-label={tr("vd.sumAria")}>
        <div className="vdp-sum-col">
          <span className="vdp-lbl">{tr("vd.endpoints")}</span>
          <span className="vdp-val accent">{counts.total}</span>
          <span className="vdp-sub vdp-small">{tr("vd.enrolled")}</span>
        </div>
        <div className="vdp-sum-state">
          <span className="vdp-lbl">{tr("vd.connectivity")}</span>
          <span
            className="vdp-sum-bar"
            role="img"
            aria-label={`${tr("vd.leg.online", { count: counts.online })}, ${tr("vd.leg.offline", { count: counts.offline })}, ${tr("vd.leg.silent", { count: counts.silent })}`}
          >
            {["online", "offline", "silent"].map((k) => (
              <i key={k} style={{ flex: counts[k], background: CONN_COLOR[k] }} />
            ))}
          </span>
          <div className="vdp-legend">
            {["online", "offline", "silent"].map((k) => (
              <button key={k} type="button" className="vdp-leg" onClick={() => setFilter(k)}>
                <i style={{ background: CONN_COLOR[k] }} />
                {tr(`vd.leg.${k}`, { count: counts[k] })}
              </button>
            ))}
          </div>
        </div>
        <div className="vdp-sum-col vdp-sum-third">
          <span className="vdp-lbl">{tr("vd.certificates")}</span>
          <span className="vdp-val" style={counts.cert ? { color: CVE_SEVERITY_COLORS.Medium } : undefined}>
            {counts.cert}
          </span>
          <span className="vdp-sub vdp-small">{tr("vd.certSoon", { days: CERT_WARNING_DAYS })}</span>
        </div>
        <div className="vdp-sum-col vdp-sum-fourth">
          <span className="vdp-lbl">{tr("vd.agentVersionLbl")}</span>
          <span className="vdp-val vdp-val-sm">
            {latestAgentVersion ? `v${latestAgentVersion}` : "—"}{" "}
            <small>
              {counts.latest}/{counts.total}
            </small>
          </span>
          <span className="vdp-sub vdp-small">{tr("vd.behind", { count: counts.total - counts.latest })}</span>
        </div>
      </section>

      <div className="vdp-split">
        <section className="vdp-card vdp-list" aria-label={tr("vd.listTitle")}>
          <div className="vdp-list-head">
            <h2 className="vdp-h2">
              {rows.length === counts.total ? tr("vd.listTitle") : tr("vd.listOf", { shown: rows.length, count: counts.total })}
            </h2>
            <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting"}>
              <IconDownload />
              {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
            </button>
          </div>
          {exportState.error && <p className="error-note" style={{ margin: 0 }}>{exportState.error}</p>}
          <div className="vdp-toolbar">
            <label className="vdp-search-wrap">
              <span className="vdp-sr">{tr("vd.searchShort")}</span>
              <input type="search" className="vdp-search" placeholder={tr("vd.searchShort")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
            </label>
            <label className="vdp-sort">
              <span className="vdp-lbl">{tr("vv.sort")}</span>
              <select className="vdp-select" value={sortKey} onChange={(e) => setSortKey(e.target.value)}>
                <option value="lastSeen">{tr("vd.sort.lastSeen")}</option>
                <option value="hostname">{tr("vd.sort.hostname")}</option>
                <option value="certDays">{tr("vd.sort.cert")}</option>
                <option value="risk">{tr("vd.sort.risk")}</option>
              </select>
            </label>
          </div>
          <div className="vdp-chips" role="group" aria-label={tr("vd.filterAria")}>
            {chips.map(([k, label, n, color]) => (
              <button key={k} type="button" className={`vdp-chip${isOn(k) ? " on" : ""}`} aria-pressed={isOn(k)} onClick={() => setFilter(k)}>
                <i className="dot" style={{ background: color }} />
                {label} <b>{n}</b>
              </button>
            ))}
          </div>

          {agents.state.status === "loading" ? (
            <p className="vdp-empty">{tr("v.loading")}</p>
          ) : rows.length === 0 ? (
            <p className="vdp-empty">{counts.total === 0 ? tr("vd.emptyNoAgent") : tr("vd.emptyNoMatch")}</p>
          ) : (
            <div className="vdp-rows">
              {rows.map((a) => {
                const st = connState(a);
                const days = daysUntil(a.cert_not_after);
                const v = vulnByAgent.get(a.id);
                const isSel = preview?.id === a.id;
                return (
                  <button key={a.id} type="button" className={`vdp-row${isSel ? " sel" : ""}`} aria-pressed={isSel} onClick={() => previewAgent(a.id)}>
                    <span className="vdp-dot" style={{ background: CONN_COLOR[st] }} title={tr(`vd.state.${st}`)} />
                    <span className="vdp-host">{a.hostname}</span>
                    <span className="vdp-flags">
                      {v?.critical > 0 && (
                        <span className="vdp-pill" style={{ "--c": CVE_SEVERITY_COLORS.Critical }}>
                          {tr("vd.critBadge", { count: v.critical })}
                        </span>
                      )}
                      {days !== null && days < CERT_WARNING_DAYS && (
                        <span className="vdp-pill" style={{ "--c": toneVar(certTone(days)) }}>
                          {tr("vd.certBadge", { n: Math.max(0, Math.round(days)) })}
                        </span>
                      )}
                    </span>
                    <span className="vdp-meta">
                      <span>{fmtRelative(a.last_seen)}</span>
                      <span>·</span>
                      <span>{a.agent_version ? `v${a.agent_version}` : tr("vd.unknownVersion")}</span>
                      <span>·</span>
                      <span>{tr("vd.appsCount", { count: a.apps_count ?? 0 })}</span>
                      {(a.group_ids ?? []).map((gid) => {
                        const g = groupById.get(gid);
                        return g ? (
                          <span key={gid} className={`vdp-tag${g.rules ? " dyn" : ""}`}>
                            {g.name}
                          </span>
                        ) : null;
                      })}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        <div ref={detailRef} className="vdp-detail-slot">
          {preview ? (
            <DevicePreview
              key={preview.id}
              agent={preview}
              inv={inventory.state[preview.id]}
              vulns={vulnByAgent.get(preview.id)}
              compliance={compliance.state[preview.id]}
              commands={commandsByAgent.get(preview.id) ?? []}
              groupById={groupById}
              staticGroups={staticGroups}
              error={removeError}
              onOpen={() => openAgent(preview.id)}
              onAddGroup={(gid) => handleAddToGroup(preview.id, gid)}
              onRemoveGroup={(gid) => handleRemoveFromGroup(preview.id, gid)}
              onRemove={() => handleRemove(preview.id)}
            />
          ) : (
            <div className="vdp-card vdp-empty-panel">
              <p className="vdp-sub">{tr("vd.pick")}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DevicePreview({ agent, inv, vulns, compliance, commands, groupById, staticGroups, error, onOpen, onAddGroup, onRemoveGroup, onRemove }) {
  const st = connState(agent);
  const days = daysUntil(agent.cert_not_after);
  const certColor = toneVar(certTone(days) === "neutral" ? "good" : certTone(days));
  const certPct = days === null ? 0 : Math.max(0, Math.min(100, (days / CERT_VALIDITY_DAYS) * 100));
  const os = inv?.data?.os_caption ? `${inv.data.os_caption.replace(/^Microsoft\s+/, "")}${inv.data.os_version ? ` (${inv.data.os_version})` : ""}` : null;
  const results = compliance?.data?.results ?? [];
  const fail = results.filter((r) => r.compliant === false).length;
  const comp =
    compliance?.status === "loading" || !compliance
      ? { label: "…", color: undefined, sub: "" }
      : results.length === 0
        ? { label: tr("vd.comp.none"), color: undefined, sub: tr("vd.comp.noneSub") }
        : fail > 0
          ? { label: tr("vd.comp.ko"), color: CVE_SEVERITY_COLORS.Critical, sub: tr("vd.comp.failSub", { fail, count: results.length }) }
          : { label: tr("vd.comp.ok"), color: CVE_SEVERITY_COLORS.Low, sub: tr("vd.comp.okSub", { count: results.length }) };
  const diag = latestCommandResult(commands, "system_diagnostic");
  const diskPct =
    diag?.disk_total_bytes && diag?.disk_free_bytes != null ? Math.round((1 - diag.disk_free_bytes / diag.disk_total_bytes) * 100) : null;
  const memberIds = agent.group_ids ?? [];
  const addable = staticGroups.filter((g) => !memberIds.includes(g.id));

  return (
    <aside className="vdp-card vdp-detail" aria-label={tr("vd.previewAria")}>
      <div className="vdp-detail-head">
        <div className="vdp-detail-title">
          <h2>{agent.hostname}</h2>
          <span className="vdp-sub">
            {os ? `${os} · ` : ""}
            {tr("vd.agentVersion", { version: agent.agent_version ? `v${agent.agent_version}` : tr("vd.unknownVersion") })} · {agent.id.slice(0, 12)}…
          </span>
        </div>
        <span className="vdp-pill vdp-pill-lg" style={{ "--c": CONN_COLOR[st] }}>
          <i className="dot" style={{ background: CONN_COLOR[st] }} />
          {tr(`vd.state.${st}`)}
        </span>
      </div>
      {error && <p className="vanitas-hud-error" style={{ margin: 0 }}>{error}</p>}

      <div className="vdp-tiles">
        <div className="vdp-tile">
          <span className="vdp-lbl">{tr("vd.tile.lastSeen")}</span>
          <span className="vdp-tile-v">{fmtRelative(agent.last_seen)}</span>
          <span className="vdp-sub vdp-small">{fmtDateTime(agent.last_seen)}</span>
        </div>
        <div className="vdp-tile">
          <span className="vdp-lbl">{tr("vd.certificate")}</span>
          <span className="vdp-tile-v" style={{ color: certColor }}>
            {days === null ? "—" : tr("vd.daysShort", { n: Math.max(0, Math.round(days)) })}
          </span>
          <span className="vdp-seg">
            <i style={{ width: `${certPct}%`, background: certColor }} />
          </span>
        </div>
        <div className="vdp-tile">
          <span className="vdp-lbl">{tr("vd.tile.apps")}</span>
          <span className="vdp-tile-v">{agent.apps_count ?? 0}</span>
          <span className="vdp-sub vdp-small">{inv?.data?.collected_at ? tr("vd.invAt", { when: fmtRelative(inv.data.collected_at) }) : "—"}</span>
        </div>
        <div className="vdp-tile">
          <span className="vdp-lbl">{tr("vd.tile.vulns")}</span>
          <span className="vdp-tile-v">{vulns ? vulns.total : "…"}</span>
          <span className="vdp-seg">
            <i style={{ flex: vulns?.critical ?? 0, background: CVE_SEVERITY_COLORS.Critical }} />
            <i style={{ flex: vulns?.high ?? 0, background: CVE_SEVERITY_COLORS.High }} />
            <i style={{ flex: vulns?.medium ?? 0, background: CVE_SEVERITY_COLORS.Medium }} />
            <i style={{ flex: vulns?.low ?? 0, background: CVE_SEVERITY_COLORS.Low }} />
          </span>
        </div>
        <div className="vdp-tile">
          <span className="vdp-lbl">{tr("vd.tile.compliance")}</span>
          <span className="vdp-tile-v" style={comp.color ? { color: comp.color } : undefined}>
            {comp.label}
          </span>
          <span className="vdp-sub vdp-small">{comp.sub}</span>
        </div>
        <div className="vdp-tile">
          <span className="vdp-lbl">{tr("vd.tile.disk")}</span>
          <span className="vdp-tile-v">{diskPct === null ? "—" : `${diskPct} %`}</span>
          {diskPct === null ? (
            <span className="vdp-sub vdp-small">{tr("vd.noDiag")}</span>
          ) : (
            <span className="vdp-seg">
              <i style={{ width: `${diskPct}%`, background: diskPct >= 90 ? CVE_SEVERITY_COLORS.Critical : "var(--hud-accent)" }} />
            </span>
          )}
        </div>
      </div>

      <div className="vdp-block">
        <span className="vdp-lbl">{tr("vd.groups")}</span>
        <div className="vdp-groups">
          {memberIds.map((gid) => {
            const g = groupById.get(gid);
            if (!g) return null;
            const isDynamic = !!g.rules;
            return (
              <span key={gid} className={`vdp-tag${isDynamic ? " dyn" : ""}`} title={isDynamic ? tr("vd.dynamicMember", { rule: summarizeGroupRules(g.rules) }) : g.name}>
                {g.name}
                {!isDynamic && (
                  <button type="button" className="vdp-tag-x" aria-label={tr("vd.removeFromGroup", { group: g.name })} onClick={() => onRemoveGroup(gid)}>
                    ×
                  </button>
                )}
              </span>
            );
          })}
          {memberIds.length === 0 && <span className="vdp-sub">{tr("vd.noGroup")}</span>}
          {addable.length > 0 && (
            <select className="vdp-select vdp-select-sm" value="" onChange={(e) => onAddGroup(e.target.value)} aria-label={tr("vd.addGroup")}>
              <option value="">{tr("vd.addGroup")}</option>
              {addable.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      <div className="vdp-block">
        <span className="vdp-lbl">{tr("vd.lastCommands")}</span>
        {commands.length === 0 ? (
          <span className="vdp-sub">{tr("vd.noCommandShort")}</span>
        ) : (
          commands.slice(0, 3).map((c) => {
            const pending = c.status === "pending" || c.status === "running";
            const color = pending ? "var(--hud-accent)" : c.success ? CVE_SEVERITY_COLORS.Low : CVE_SEVERITY_COLORS.Critical;
            return (
              <div key={c.id} className="vdp-cmd">
                <span className="vdp-cmd-name">{COMMAND_LABELS[c.command_type] ?? c.command_type}</span>
                <span className="vdp-pill" style={{ "--c": color }}>
                  {tr(pending ? "vd.cmd.inProgress" : c.success ? "vd.cmd.ok" : "vd.cmd.failed")}
                </span>
                <span className="vdp-sub vdp-small">{fmtRelative(c.created_at)}</span>
              </div>
            );
          })
        )}
      </div>

      <div className="vdp-foot">
        <button type="button" className="vanitas-queue-btn" onClick={onOpen}>
          {tr("vd.openFull")}
        </button>
        <ConfirmButton label={tr("vd.remove")} confirmLabel={tr("vd.confirm")} className="vanitas-hud-purge-btn" onConfirm={onRemove} title={tr("vd.removeTitle")} />
      </div>
    </aside>
  );
}
