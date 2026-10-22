import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { invalidateCache } from "../cache.js";
import { isErrorPayload, useVanitasAgentPackages, useVanitasInstallers } from "../hooks/useDashboardData.js";
import { ConfirmButton, GroupRuleBuilder, isOnline, summarizeGroupRules } from "./vanitasShared.jsx";
import { tr } from "../i18n/core.js";

/**
 * Détail d'un groupe de postes (2026-09-08, demande de Nicolas). Deux métriques agrégées,
 * définies AVEC Nicolas (`AskUserQuestion`) plutôt que devinées :
 * - "Vulnérabilités moyennes par poste" — moyenne du NOMBRE de vulnérabilités détectées, sur
 *   les postes du groupe.
 * - "Taux de risque moyen" — moyenne, PAR POSTE, du CVSS MOYEN de ses vulnérabilités
 *   détectées (0 si aucune) — échelle 0-10 standard NVD, pas un score maison inventé.
 *
 * Les deux sont calculées ICI, côté client, à partir de `vulnerabilities` (déjà chargé par le
 * parent via `useVanitasAgentVulnerabilities`, un appel par membre — jamais plus qu'une
 * poignée d'agents à l'échelle de ce projet, même philosophie que
 * `VanitasVulnerabilitiesTab.jsx`). Aucune route d'agrégat dédiée côté serveur Vanitas.
 */
export default function VanitasGroupDetail({
  group,
  allGroups,
  agents,
  membersLoading = false,
  vulnerabilities,
  onBack,
  onChanged,
  onDeleted,
}) {
  const isDynamic = !!group.rules;
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(group.name);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  // Édition de la règle dynamique (2026-09-10, absente jusqu'ici — seul le nom se modifiait) —
  // `draftRules` initialisé à `null` (pas encore ouvert) plutôt que `group.rules` directement :
  // évite un état d'édition qui semblerait actif dès l'ouverture de la fiche.
  const [editingRules, setEditingRules] = useState(false);
  const [draftRules, setDraftRules] = useState(group.rules);
  const [rulesBusy, setRulesBusy] = useState(false);
  const [rulesError, setRulesError] = useState(null);

  // Groupes imbriqués (2026-09-10) — sélecteur limité aux groupes qui ne créeraient PAS de
  // cycle évident côté client (soi-même + enfants déjà imbriqués) ; le vrai contrôle de cycle
  // transitif reste fait côté serveur (`would_create_cycle`), ce filtre n'est qu'un confort
  // pour ne pas proposer les cas les plus évidents dans la liste déroulante.
  const [childBusy, setChildBusy] = useState(false);
  const [childError, setChildError] = useState(null);
  const [selectedChildId, setSelectedChildId] = useState("");
  const groupNameById = useMemo(() => {
    const map = new Map();
    for (const g of allGroups ?? []) map.set(g.id, g.name);
    return map;
  }, [allGroups]);
  const eligibleChildGroups = useMemo(
    () => (allGroups ?? []).filter((g) => g.id !== group.id && !group.child_group_ids?.includes(g.id)),
    [allGroups, group.id, group.child_group_ids]
  );

  // Push d'application (2026-09-08, "un peu comme dans Pandore, via les groupes") — catalogue
  // chargé ici (pas dans VanitasInstallersTab.jsx) pour bénéficier du même cache partagé,
  // jamais deux appels réseau indépendants pour la même liste selon la page ouverte en premier.
  const installers = useVanitasInstallers();
  const [selectedInstallerId, setSelectedInstallerId] = useState("");
  const [pushBusy, setPushBusy] = useState(false);
  const [pushError, setPushError] = useState(null);
  const [pushResult, setPushResult] = useState(null);

  // Mise à jour de l'agent (2026-09-11, revu le même jour — la mise à jour se fait maintenant
  // AUSSI automatiquement, voir `_vanitas_agent_health_loop` côté backend ; ce push manuel
  // couvre le cas "forcer tout un groupe immédiatement") — même cache partagé que
  // `VanitasInstallersTab.jsx` (catalogue d'upload), même raisonnement que `installers`
  // ci-dessus.
  const agentPackages = useVanitasAgentPackages();
  const [pushUpdateBusy, setPushUpdateBusy] = useState(false);
  const [pushUpdateError, setPushUpdateError] = useState(null);
  const [pushUpdateResult, setPushUpdateResult] = useState(null);

  useEffect(() => {
    installers.ensureLoaded();
    agentPackages.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const latestAgentPackage = agentPackages.state.data[0] ?? null;

  async function handlePushUpdate() {
    if (!latestAgentPackage) return;
    setPushUpdateBusy(true);
    setPushUpdateError(null);
    setPushUpdateResult(null);
    try {
      const payload = await api.vanitas.pushUpdateToGroup(group.id, latestAgentPackage.id);
      if (isErrorPayload(payload)) {
        setPushUpdateError(payload.message);
      } else {
        setPushUpdateResult(payload.queued);
      }
    } catch (err) {
      setPushUpdateError(err.message);
    } finally {
      setPushUpdateBusy(false);
    }
  }

  async function handlePushInstall() {
    if (!selectedInstallerId) return;
    setPushBusy(true);
    setPushError(null);
    setPushResult(null);
    try {
      const payload = await api.vanitas.pushInstallToGroup(group.id, selectedInstallerId);
      if (isErrorPayload(payload)) {
        setPushError(payload.message);
      } else {
        setPushResult(payload.queued);
        // "Applications déployées" (2026-09-10) partage le même cache — invalidé ici pour
        // qu'une visite juste après ce push reflète tout de suite le nouveau statut, même
        // raisonnement que le second point d'entrée depuis le catalogue.
        invalidateCache("vanitasInstallerDeployments");
      }
    } catch (err) {
      setPushError(err.message);
    } finally {
      setPushBusy(false);
    }
  }

  const memberStats = useMemo(() => {
    return agents.map((a) => {
      const entry = vulnerabilities[a.id];
      const vulns = entry?.data ?? [];
      const scored = vulns.filter((v) => typeof v.cvss_score === "number");
      const avgCvss = scored.length ? scored.reduce((s, v) => s + v.cvss_score, 0) / scored.length : 0;
      return { agent: a, loading: entry?.loading ?? true, vulnCount: vulns.length, avgCvss };
    });
  }, [agents, vulnerabilities]);

  const stillCollecting = memberStats.some((m) => m.loading);
  const avgVulnCount = memberStats.length ? memberStats.reduce((s, m) => s + m.vulnCount, 0) / memberStats.length : 0;
  const avgRiskRate = memberStats.length ? memberStats.reduce((s, m) => s + m.avgCvss, 0) / memberStats.length : 0;

  async function handleRename(e) {
    e.preventDefault();
    if (!name.trim() || name.trim() === group.name) {
      setRenaming(false);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.updateGroup(group.id, { name: name.trim() });
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        setRenaming(false);
        onChanged();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.deleteGroup(group.id);
      if (isErrorPayload(payload)) {
        setError(payload.message);
        setBusy(false);
      } else {
        onDeleted();
      }
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  function startEditingRules() {
    setRulesError(null);
    setDraftRules(group.rules);
    setEditingRules(true);
  }

  async function handleSaveRules() {
    if (!draftRules?.conditions?.length || draftRules.conditions.some((c) => !c.value.trim())) return;
    setRulesBusy(true);
    setRulesError(null);
    try {
      const payload = await api.vanitas.updateGroup(group.id, { rules: draftRules });
      if (isErrorPayload(payload)) {
        setRulesError(payload.message);
      } else {
        setEditingRules(false);
        onChanged();
      }
    } catch (err) {
      setRulesError(err.message);
    } finally {
      setRulesBusy(false);
    }
  }

  async function handleAddChild() {
    if (!selectedChildId) return;
    setChildBusy(true);
    setChildError(null);
    try {
      const payload = await api.vanitas.addChildGroup(group.id, selectedChildId);
      if (isErrorPayload(payload)) {
        setChildError(payload.message);
      } else {
        setSelectedChildId("");
        onChanged();
      }
    } catch (err) {
      setChildError(err.message);
    } finally {
      setChildBusy(false);
    }
  }

  async function handleRemoveChild(childId) {
    setChildError(null);
    try {
      const payload = await api.vanitas.removeChildGroup(group.id, childId);
      if (isErrorPayload(payload)) setChildError(payload.message);
      else onChanged();
    } catch (err) {
      setChildError(err.message);
    }
  }

  async function handleRemoveMember(agentId) {
    setError(null);
    try {
      const payload = await api.vanitas.removeAgentFromGroup(agentId, group.id);
      if (isErrorPayload(payload)) setError(payload.message);
      else onChanged();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="vanitas-hud">
      <button type="button" className="vanitas-detail-back" onClick={onBack}>
        {tr("vgd.back")}
      </button>

      <div className="vanitas-hud-card-head" style={{ marginBottom: "16px" }}>
        {renaming ? (
          <form onSubmit={handleRename} style={{ display: "flex", gap: "8px" }}>
            <input className="filter-input" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} autoFocus />
            <button type="submit" className="vanitas-queue-btn" disabled={busy}>
              {tr("vgd.save")}
            </button>
          </form>
        ) : (
          <h2 style={{ fontSize: "18px" }}>
            {group.name}{" "}
            <span className={`vanitas-hud-status-pill ${isDynamic ? "pending" : "ok"}`} style={{ marginLeft: "6px" }}>
              {tr(isDynamic ? "vg.dynamic" : "vg.static")}
            </span>{" "}
            <button type="button" className="vanitas-ov-tile-link" onClick={() => setRenaming(true)}>
              {tr("vgd.rename")}
            </button>
            {isDynamic && !editingRules && (
              <button type="button" className="vanitas-ov-tile-link" onClick={startEditingRules}>
                {tr("vgd.editRule")}
              </button>
            )}
          </h2>
        )}
        <ConfirmButton
          label={tr("vgd.delete")}
          confirmLabel={tr("v.confirm")}
          className="vanitas-danger-btn"
          disabled={busy}
          onConfirm={handleDelete}
        />
      </div>
      {error && <p className="error-note">{error}</p>}

      {isDynamic && !editingRules && (
        <p className="cve-small" style={{ marginTop: "-10px", marginBottom: "16px" }}>
          {tr("vgd.rule", { rule: summarizeGroupRules(group.rules) })}
        </p>
      )}
      {isDynamic && editingRules && (
        <div className="vanitas-hud-card vanitas-hud-frame" style={{ marginBottom: "20px" }}>
          <div className="vanitas-hud-card-head">
            <h2>{tr("vgd.editRuleTitle")}</h2>
          </div>
          <GroupRuleBuilder rules={draftRules} onChange={setDraftRules} disabled={rulesBusy} />
          {rulesError && <p className="error-note" style={{ marginTop: "10px" }}>{rulesError}</p>}
          <div style={{ display: "flex", gap: "8px", marginTop: "12px" }}>
            <button type="button" className="vanitas-ghost-btn" onClick={() => setEditingRules(false)} disabled={rulesBusy}>
              {tr("vgd.cancel")}
            </button>
            <button
              type="button"
              className="vanitas-queue-btn"
              onClick={handleSaveRules}
              disabled={rulesBusy || !draftRules?.conditions?.length || draftRules.conditions.some((c) => !c.value.trim())}
            >
              {rulesBusy ? tr("vgd.saving") : tr("vgd.saveRule")}
            </button>
          </div>
        </div>
      )}

      <div className="vanitas-hud-strip">
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-accent)" }}>
          <div className="label">
            {tr("vgd.kpi.endpoints")}
            <span className="tag">{tr("vgd.kpi.group")}</span>
          </div>
          <div className="value">{agents.length}</div>
          <div className="bar">
            <i style={{ width: "100%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-warn)" }}>
          <div className="label">
            {tr("vgd.kpi.avgVulns")}
            <span className="tag">{tr("vgd.kpi.perEndpoint")}</span>
          </div>
          <div className="value">{avgVulnCount.toFixed(1)}</div>
          <div className="bar">
            <i style={{ width: avgVulnCount ? "100%" : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-high)" }}>
          <div className="label">
            {tr("vgd.kpi.avgRisk")}
            <span className="tag">CVSS 0-10</span>
          </div>
          <div className="value">{avgRiskRate.toFixed(1)}</div>
          <div className="bar">
            <i style={{ width: `${Math.min(100, avgRiskRate * 10)}%` }} />
          </div>
        </div>
      </div>
      <p className="cve-small" style={{ marginTop: "-10px", marginBottom: "16px" }}>
        {tr("vgd.method", { count: agents.length })}
        {stillCollecting && tr("vgd.collecting")}
      </p>

      {/* Groupes imbriqués (2026-09-10, revue de la fonctionnalité comparée à Intune/Jamf/
          Tanium — "pas de groupes imbriqués") : un groupe, statique OU dynamique, peut
          contenir d'autres groupes — leurs membres résolus s'ajoutent toujours à l'union (voir
          la barre "Postes" du bandeau KPI ci-dessus, qui compte déjà ces membres imbriqués). */}
      <div className="vanitas-hud-card vanitas-hud-frame" style={{ marginBottom: "20px" }}>
        <div className="vanitas-hud-card-head">
          <h2>{tr("vgd.subgroups")}</h2>
          <span className="vanitas-hud-card-note">{tr("vgd.subgroupsNote")}</span>
        </div>
        {(group.child_group_ids ?? []).length === 0 ? (
          <p className="vanitas-hud-empty-note">{tr("vgd.noSubgroup")}</p>
        ) : (
          <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", marginBottom: "12px" }}>
            {group.child_group_ids.map((childId) => (
              <span key={childId} className="vanitas-hud-chip active">
                <span className="led" />
                {groupNameById.get(childId) ?? childId}
                <button
                  type="button"
                  onClick={() => handleRemoveChild(childId)}
                  style={{ marginLeft: "6px", background: "none", border: "none", color: "inherit", cursor: "pointer", padding: 0 }}
                  aria-label={tr("vgd.removeSubgroupAria")}
                >
                  ✕
                </button>
              </span>
            ))}
          </div>
        )}
        {childError && <p className="error-note" style={{ marginBottom: "10px" }}>{childError}</p>}
        {eligibleChildGroups.length > 0 && (
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <select
              className="filter-input"
              style={{ flex: "none", width: "260px" }}
              value={selectedChildId}
              onChange={(e) => setSelectedChildId(e.target.value)}
              disabled={childBusy}
            >
              <option value="">{tr("vgd.chooseNest")}</option>
              {eligibleChildGroups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
            <button type="button" className="vanitas-queue-btn" onClick={handleAddChild} disabled={childBusy || !selectedChildId}>
              {childBusy ? tr("vgd.adding") : tr("vgd.nest")}
            </button>
          </div>
        )}
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame" style={{ marginBottom: "20px" }}>
        <div className="vanitas-hud-card-head">
          <h2>{tr("vgd.pushApp")}</h2>
          <span className="vanitas-hud-card-note">{tr("vgd.pushAppNote")}</span>
        </div>
        {installers.state.data.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            {tr("vgd.noInstaller")}
          </p>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <select
              className="filter-input"
              style={{ flex: "none", width: "260px" }}
              value={selectedInstallerId}
              onChange={(e) => {
                setSelectedInstallerId(e.target.value);
                setPushResult(null);
              }}
              disabled={pushBusy}
            >
              <option value="">{tr("vgd.chooseInstaller")}</option>
              {installers.state.data.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.name}
                  {i.version ? ` · v${i.version}` : ""}
                </option>
              ))}
            </select>
            <ConfirmButton
              label={tr("vgd.pushToGroup")}
              confirmLabel={tr("v.confirm")}
              className="vanitas-danger-btn"
              disabled={pushBusy || !selectedInstallerId}
              onConfirm={handlePushInstall}
              title={tr("vgd.pushInstallTitle")}
            />
            {pushResult !== null && (
              <span className="vanitas-hud-status-pill ok">
                {tr("vgd.queued", { count: pushResult })}
              </span>
            )}
          </div>
        )}
        {pushError && <p className="error-note" style={{ marginTop: "10px" }}>{pushError}</p>}
        {pushResult !== null && (
          <p className="cve-small" style={{ marginTop: "10px" }}>
            {tr("vgd.resultsCommands")}
          </p>
        )}
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame" style={{ marginBottom: "20px" }}>
        <div className="vanitas-hud-card-head">
          <h2>{tr("vgd.pushUpdate")}</h2>
          <span className="vanitas-hud-card-note">{tr("vgd.pushUpdateNote")}</span>
        </div>
        {!latestAgentPackage ? (
          <p className="vanitas-hud-empty-note">
            {tr("vgd.noPackage")}
          </p>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <span className="vanitas-hud-status-pill pending">v{latestAgentPackage.version}</span>
            <ConfirmButton
              label={tr("vgd.pushToGroup")}
              confirmLabel={tr("v.confirm")}
              className="vanitas-danger-btn"
              disabled={pushUpdateBusy}
              onConfirm={handlePushUpdate}
              title={tr("vgd.pushUpdateTitle")}
            />
            {pushUpdateResult !== null && (
              <span className="vanitas-hud-status-pill ok">
                {tr("vgd.queued", { count: pushUpdateResult })}
              </span>
            )}
          </div>
        )}
        {pushUpdateError && <p className="error-note" style={{ marginTop: "10px" }}>{pushUpdateError}</p>}
        {pushUpdateResult !== null && (
          <p className="cve-small" style={{ marginTop: "10px" }}>
            {tr("vgd.resultsLog")}
          </p>
        )}
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>{tr("vgd.members")}</h2>
        </div>
        {membersLoading ? (
          <p className="vanitas-hud-empty-note">{tr("vgd.loadingMembers")}</p>
        ) : agents.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            {isDynamic
              ? tr("vgd.noMatchRule", { rule: summarizeGroupRules(group.rules) })
              : tr("vgd.noMember")}
          </p>
        ) : (
          <div className="vanitas-hud-table-wrap">
            <table className="vanitas-hud-table">
              <thead>
                <tr>
                  <th>{tr("vgd.col.endpoint")}</th>
                  <th>{tr("vgd.col.status")}</th>
                  <th>{tr("vgd.col.vulns")}</th>
                  <th>{tr("vgd.col.avgCvss")}</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {memberStats.map((m) => (
                  <tr key={m.agent.id}>
                    <td className="vanitas-hud-host">
                      <span className="name">{m.agent.hostname}</span>
                    </td>
                    <td>
                      <span className={`vanitas-hud-status-pill ${isOnline(m.agent) ? "ok" : "bad"}`}>
                        {tr(isOnline(m.agent) ? "vgd.online" : "vgd.silent")}
                      </span>
                    </td>
                    <td>{m.loading ? "…" : m.vulnCount}</td>
                    <td className="cve-mono cve-small">{m.loading ? "…" : m.avgCvss.toFixed(1)}</td>
                    <td>
                      {isDynamic ? (
                        <span className="cve-small" style={{ color: "var(--ink-faint)" }}>
                          {tr("vgd.autoMember")}
                        </span>
                      ) : (
                        <button type="button" className="vanitas-queue-btn" onClick={() => handleRemoveMember(m.agent.id)}>
                          {tr("vgd.removeFromGroup")}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
