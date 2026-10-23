import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { isErrorPayload, useVanitasAgentVulnerabilities, useVanitasAgents, useVanitasGroups } from "../hooks/useDashboardData.js";
import VanitasGroupDetail from "./VanitasGroupDetail.jsx";
import { GroupRuleBuilder, summarizeGroupRules } from "./vanitasShared.jsx";
import { currentLocale, tr } from "../i18n/core.js";

function CreateGroupForm({ onCreated, onCancel }) {
  const [name, setName] = useState("");
  const [isDynamic, setIsDynamic] = useState(false);
  const [rules, setRules] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const hasValidRule = isDynamic && rules?.conditions?.length && rules.conditions.every((c) => c.value.trim());

  async function handleSubmit(e) {
    e.preventDefault();
    if (!name.trim()) return;
    if (isDynamic && !hasValidRule) return;
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.createGroup(name.trim(), isDynamic ? rules : null);
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        onCreated(payload?.id ?? null);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="vgp-new">
      <div className="vgp-row">
        <input
          type="text"
          className="vgp-input vgp-grow"
          placeholder={tr("vgp.namePlaceholder")}
          aria-label={tr("vgp.nameAria")}
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={busy}
          autoComplete="off"
          autoFocus
        />
        <span className="vgp-seg" role="group" aria-label={tr("vgp.typeAria")}>
          <button
            type="button"
            className={!isDynamic ? "on" : ""}
            aria-pressed={!isDynamic}
            onClick={() => {
              setIsDynamic(false);
              setRules(null);
            }}
          >
            {tr("vgp.static")}
          </button>
          <button type="button" className={isDynamic ? "on" : ""} aria-pressed={isDynamic} onClick={() => setIsDynamic(true)}>
            {tr("vgp.dynamic")}
          </button>
        </span>
      </div>
      {isDynamic ? (
        <>
          <GroupRuleBuilder rules={rules} onChange={setRules} disabled={busy} />
          <span className="vgp-sub">{tr("vg.dynamicNote")}</span>
        </>
      ) : (
        <span className="vgp-sub">{tr("vgp.staticNote")}</span>
      )}
      {error && <p className="error-note" style={{ margin: 0 }}>{error}</p>}
      <div className="vgp-row vgp-row-end">
        <button type="button" className="vanitas-ghost-btn" onClick={onCancel} disabled={busy}>
          {tr("vgd.cancel")}
        </button>
        <button type="submit" className="vanitas-queue-btn" disabled={busy || !name.trim() || (isDynamic && !hasValidRule)}>
          {busy ? tr("vg.creating") : tr("vg.create")}
        </button>
      </div>
    </form>
  );
}

/**
 * "Vanitas" > Inventaire > Groupes (2026-09-08, demande de Nicolas — "ranger les postes dans
 * des groupes si trop de devices et pas organisé", étendu le même soir en many-to-many +
 * groupes dynamiques par motif de nom).
 *
 * Refonte liste + détail (2026-10-23, maquette canvas validée par Nicolas) : bandeau de synthèse
 * (groupes statiques/dynamiques, couverture du parc — "sans groupe" mène à Postes filtré —,
 * groupes avec fenêtre de patch, groupe le plus exposé), liste avec recherche/pastilles et
 * formulaire de création dépliable, détail dans un panneau latéral (VanitasGroupDetail.jsx,
 * trois onglets) au lieu d'une page plein écran.
 *
 * Membres dérivés de `agent.group_ids` (déjà résolus côté serveur pour les deux types et les
 * sous-groupes, voir `group_membership.py::group_ids_for_agents`) — plus d'appel
 * `/groups/{id}/members` par groupe. Vulnérabilités chargées pour tout le parc (même cache que
 * Vulnérabilités / Postes) pour les moyennes par groupe. Classes `.vgp-*`.
 */
export default function VanitasGroupsTab({ onNavigateVanitas }) {
  const groups = useVanitasGroups();
  const agents = useVanitasAgents();
  const vulnerabilities = useVanitasAgentVulnerabilities();

  const [selectedGroupId, setSelectedGroupId] = useState(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [creating, setCreating] = useState(false);
  const detailRef = useRef(null);

  useEffect(() => {
    groups.ensureLoaded();
    agents.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    for (const a of agents.state.data ?? []) vulnerabilities.ensureLoaded(a.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents.state.data]);

  const groupList = groups.state.data ?? [];
  const agentList = agents.state.data ?? [];

  const membersByGroup = useMemo(() => {
    const map = new Map(groupList.map((g) => [g.id, []]));
    for (const a of agentList) for (const gid of a.group_ids ?? []) map.get(gid)?.push(a);
    return map;
  }, [groupList, agentList]);

  // Moyenne de CVE par poste, par groupe (même définition que "Vulnérabilités moyennes" du
  // détail) — `null` tant qu'un membre est encore en collecte.
  const avgVulnsByGroup = useMemo(() => {
    const map = new Map();
    for (const [gid, members] of membersByGroup) {
      if (members.length === 0) continue;
      if (members.some((a) => !vulnerabilities.state[a.id] || vulnerabilities.state[a.id].loading)) continue;
      map.set(gid, members.reduce((s, a) => s + (vulnerabilities.state[a.id].data?.length ?? 0), 0) / members.length);
    }
    return map;
  }, [membersByGroup, vulnerabilities.state]);

  const mostExposed = useMemo(() => {
    let best = null;
    for (const [gid, avg] of avgVulnsByGroup) if (!best || avg > best.avg) best = { gid, avg };
    return best ? { group: groupList.find((g) => g.id === best.gid), avg: best.avg } : null;
  }, [avgVulnsByGroup, groupList]);

  const staticCount = groupList.filter((g) => !g.rules).length;
  const dynamicCount = groupList.length - staticCount;
  const covered = agentList.filter((a) => (a.group_ids ?? []).length > 0).length;
  const orphans = agentList.length - covered;
  const patchCount = groupList.filter((g) => g.patch_enabled).length;

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return groupList
      .filter((g) => {
        if (filter === "static" && g.rules) return false;
        if (filter === "dynamic" && !g.rules) return false;
        return !q || g.name.toLowerCase().includes(q);
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [groupList, query, filter]);

  const selected = visible.find((g) => g.id === selectedGroupId) ?? visible[0] ?? null;

  function selectGroup(id) {
    setSelectedGroupId(id);
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function refreshAll() {
    groups.refresh();
    agents.refresh();
  }

  const loading = groups.state.status === "loading" || agents.state.status === "loading";
  if (loading) {
    return (
      <div className="vanitas-hud vgp">
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      </div>
    );
  }

  const fmtAvg = (n) => n.toLocaleString(currentLocale(), { minimumFractionDigits: 1, maximumFractionDigits: 1 });

  return (
    <div className="vanitas-hud vgp">
      {groups.state.error && <p className="vanitas-hud-error">{groups.state.error}</p>}

      <section className="vgp-card vgp-sum" aria-label={tr("vgp.sumAria")}>
        <div className="vgp-sum-col">
          <span className="vgp-lbl">{tr("vgp.groups")}</span>
          <span className="vgp-val accent">{groupList.length}</span>
          <span className="vgp-sub vgp-small">{tr("vgp.split", { static: staticCount, dynamic: dynamicCount })}</span>
        </div>
        <div className="vgp-sum-state">
          <span className="vgp-lbl">{tr("vgp.coverage")}</span>
          <span className="vgp-sum-bar" role="img" aria-label={`${tr("vgp.covered", { count: covered })}, ${tr("vgp.orphans", { count: orphans })}`}>
            <i className="cov" style={{ flex: covered }} />
            <i className="orph" style={{ flex: orphans }} />
          </span>
          <div className="vgp-legend">
            <span className="vgp-leg static">
              <i className="cov" />
              {tr("vgp.covered", { count: covered })}
            </span>
            {orphans > 0 ? (
              <button type="button" className="vgp-leg" onClick={() => onNavigateVanitas?.("vanitas-devices", { filter: "nogroup" })}>
                <i className="orph" />
                {tr("vgp.orphansLink", { count: orphans })}
              </button>
            ) : (
              <span className="vgp-leg static">
                <i className="orph" />
                {tr("vgp.orphans", { count: 0 })}
              </span>
            )}
          </div>
        </div>
        <div className="vgp-sum-col vgp-sum-third">
          <span className="vgp-lbl">{tr("vgp.patchWindow")}</span>
          <span className="vgp-val">
            {patchCount} <small>/ {groupList.length}</small>
          </span>
          <span className="vgp-sub vgp-small">{tr("vgp.withWindow")}</span>
        </div>
        <div className="vgp-sum-col vgp-sum-fourth">
          <span className="vgp-lbl">{tr("vgp.mostExposed")}</span>
          {mostExposed?.group ? (
            <>
              <button type="button" className="vgp-exposed" onClick={() => selectGroup(mostExposed.group.id)}>
                {mostExposed.group.name}
              </button>
              <span className="vgp-sub vgp-small">{tr("vgp.avgCve", { n: fmtAvg(mostExposed.avg) })}</span>
            </>
          ) : (
            <span className="vgp-sub">—</span>
          )}
        </div>
      </section>

      <div className="vgp-split">
        <section className="vgp-card vgp-list" aria-label={tr("vgp.listTitle")}>
          <div className="vgp-list-head">
            <h2 className="vgp-h2">{tr("vgp.listTitle")}</h2>
            <button type="button" className="vanitas-queue-btn" onClick={() => setCreating((v) => !v)} aria-expanded={creating}>
              {creating ? tr("vgp.close") : tr("vgp.new")}
            </button>
          </div>
          {creating && (
            <CreateGroupForm
              onCancel={() => setCreating(false)}
              onCreated={(id) => {
                setCreating(false);
                if (id) setSelectedGroupId(id);
                setFilter("all");
                setQuery("");
                refreshAll();
              }}
            />
          )}
          <div className="vgp-row">
            <label className="vgp-search-wrap">
              <span className="vgp-sr">{tr("vgp.searchShort")}</span>
              <input type="search" className="vgp-input" placeholder={tr("vgp.searchShort")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
            </label>
            <span className="vgp-chips" role="group" aria-label={tr("vgp.typeAria")}>
              {[
                ["all", tr("vgp.f.all"), groupList.length],
                ["static", tr("vgp.f.static"), staticCount],
                ["dynamic", tr("vgp.f.dynamic"), dynamicCount],
              ].map(([k, label, n]) => (
                <button key={k} type="button" className={`vgp-chip${filter === k ? " on" : ""}`} aria-pressed={filter === k} onClick={() => setFilter(k)}>
                  {label} <b>{n}</b>
                </button>
              ))}
            </span>
          </div>

          {groupList.length === 0 ? (
            <p className="vgp-empty">{tr("vg.empty")}</p>
          ) : visible.length === 0 ? (
            <p className="vgp-empty">{tr("vgp.noMatch")}</p>
          ) : (
            <div className="vgp-rows">
              {visible.map((g) => {
                const isDyn = !!g.rules;
                const isSel = selected?.id === g.id;
                const count = membersByGroup.get(g.id)?.length ?? g.device_count ?? 0;
                return (
                  <button key={g.id} type="button" className={`vgp-grp${isSel ? " sel" : ""}`} aria-pressed={isSel} onClick={() => selectGroup(g.id)}>
                    <span className={`vgp-ico${isDyn ? " dyn" : ""}`} aria-hidden="true">
                      {isDyn ? "⟳" : g.name.charAt(0).toUpperCase()}
                    </span>
                    <span className="vgp-grp-name">{g.name}</span>
                    <span className="vgp-count">
                      {tr("vgp.endpoints", { count })}
                    </span>
                    <span className="vgp-grp-meta">
                      <span className={`vgp-tag${isDyn ? " dyn" : ""}`}>{tr(isDyn ? "vgp.dynamic" : "vgp.static")}</span>
                      <span className="vgp-ellipsis">{isDyn ? summarizeGroupRules(g.rules) : tr("vgp.manual")}</span>
                      {g.patch_enabled && g.patch_window_start && (
                        <span>· {tr("vgp.patchShort", { start: g.patch_window_start, end: g.patch_window_end })}</span>
                      )}
                      {(g.child_group_ids ?? []).length > 0 && <span>· {tr("vg.subgroups", { count: g.child_group_ids.length })}</span>}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        <div ref={detailRef} className="vgp-detail-slot">
          {selected ? (
            <VanitasGroupDetail
              key={selected.id}
              group={selected}
              allGroups={groupList}
              agents={membersByGroup.get(selected.id) ?? []}
              allAgents={agentList}
              vulnerabilities={vulnerabilities.state}
              onNavigateVanitas={onNavigateVanitas}
              onChanged={refreshAll}
              onDeleted={() => {
                setSelectedGroupId(null);
                refreshAll();
              }}
            />
          ) : (
            <div className="vgp-card vgp-empty-panel">
              <p className="vgp-sub">{tr("vgp.pick")}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
