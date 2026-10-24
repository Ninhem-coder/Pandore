import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { invalidateCache } from "../cache.js";
import { isErrorPayload, useVanitasAgentPackages, useVanitasInstallers } from "../hooks/useDashboardData.js";
import { CVE_SEVERITY_COLORS } from "../theme.js";
import { ConfirmButton, GroupRuleBuilder, fmtDate, isOnline, summarizeGroupRules } from "./vanitasShared.jsx";
import { currentLocale, tr } from "../i18n/core.js";

function fmtNumber(n, digits) {
  return n.toLocaleString(currentLocale(), { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

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
 *
 * Refonte liste + détail (2026-10-23, maquette canvas validée par Nicolas) : ce n'est plus une
 * page plein écran mais le PANNEAU latéral de VanitasGroupsTab.jsx (clé = group.id), en trois
 * onglets — Membres (nouveau : ajout d'un poste à un groupe statique, jusqu'ici seulement depuis
 * "Postes"), Actions (pousser une application / la mise à jour de l'agent), Sous-groupes. Les
 * membres sont dérivés de `agent.group_ids` (résolus côté serveur : règle, adhésion manuelle,
 * sous-groupes — `group_ids_for_agents`). Classes `.vgp-*`.
 */
export default function VanitasGroupDetail({
  group,
  allGroups,
  agents,
  allAgents,
  vulnerabilities,
  onChanged,
  onDeleted,
  onNavigateVanitas,
}) {
  const isDynamic = !!group.rules;
  const [renaming, setRenaming] = useState(false);
  const [name, setName] = useState(group.name);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("members");

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

  async function handleAddMember(agentId) {
    if (!agentId) return;
    setError(null);
    try {
      const payload = await api.vanitas.addAgentToGroup(agentId, group.id);
      if (isErrorPayload(payload)) setError(payload.message);
      else onChanged();
    } catch (err) {
      setError(err.message);
    }
  }

  const memberIds = new Set(agents.map((a) => a.id));
  const addableAgents = (allAgents ?? []).filter((a) => !memberIds.has(a.id));
  const onlineCount = agents.filter(isOnline).length;
  const riskColor = avgRiskRate >= 7 ? CVE_SEVERITY_COLORS.High : avgRiskRate >= 4 ? CVE_SEVERITY_COLORS.Medium : undefined;
  const behindCount = latestAgentPackage ? agents.filter((a) => a.agent_version && a.agent_version !== latestAgentPackage.version).length : 0;

  return (
    <aside className="vgp-card vgp-detail" aria-label={tr("vgp.detailAria")}>
      <div className="vgp-detail-head">
        <div className="vgp-detail-title">
          {renaming ? (
            <form onSubmit={handleRename} className="vgp-rename">
              <input className="vgp-input" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} autoFocus aria-label={tr("vgp.nameAria")} />
              <button type="submit" className="vanitas-queue-btn" disabled={busy}>
                {tr("vgd.save")}
              </button>
              <button type="button" className="vanitas-ghost-btn" onClick={() => setRenaming(false)} disabled={busy}>
                {tr("vgd.cancel")}
              </button>
            </form>
          ) : (
            <h2>{group.name}</h2>
          )}
          <span className="vgp-sub">
            {tr(isDynamic ? "vgp.typeDynamic" : "vgp.typeStatic")} · {tr("vgp.updated", { date: fmtDate(group.updated_at) })}
          </span>
        </div>
        {!renaming && (
          <button type="button" className="vanitas-ghost-btn" onClick={() => setRenaming(true)}>
            {tr("vgp.rename")}
          </button>
        )}
        <ConfirmButton label={tr("vg.delete")} confirmLabel={tr("v.confirm")} className="vanitas-danger-btn" disabled={busy} onConfirm={handleDelete} />
      </div>
      {error && <p className="error-note" style={{ margin: 0 }}>{error}</p>}

      {isDynamic && !editingRules && (
        <div className="vgp-rulebox">
          <span className="vgp-lbl vgp-accent">{tr("vgp.ruleLbl")}</span>
          <span className="vgp-rule-text">{summarizeGroupRules(group.rules)}</span>
          <button type="button" className="vanitas-ghost-btn" onClick={startEditingRules}>
            {tr("vgd.editRuleTitle")}
          </button>
        </div>
      )}
      {isDynamic && editingRules && (
        <div className="vgp-box">
          <span className="vgp-lbl">{tr("vgd.editRuleTitle")}</span>
          <GroupRuleBuilder rules={draftRules} onChange={setDraftRules} disabled={rulesBusy} />
          {rulesError && <p className="error-note" style={{ margin: 0 }}>{rulesError}</p>}
          <div className="vgp-row vgp-row-end">
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

      <div className="vgp-stats">
        <div className="vgp-tile">
          <span className="vgp-lbl">{tr("vgd.kpi.endpoints")}</span>
          <span className="vgp-tile-v">{agents.length}</span>
          <span className="vgp-sub vgp-small">{tr("vgp.onlineCount", { count: onlineCount })}</span>
        </div>
        <div className="vgp-tile" title={tr("vgd.method", { count: agents.length })}>
          <span className="vgp-lbl">{tr("vgp.cvePerEndpoint")}</span>
          <span className="vgp-tile-v">{stillCollecting ? "…" : fmtNumber(avgVulnCount, 1)}</span>
          <span className="vgp-sub vgp-small">{tr("vgp.average")}</span>
        </div>
        <div className="vgp-tile" title={tr("vgd.method", { count: agents.length })}>
          <span className="vgp-lbl">{tr("vgp.avgCvss")}</span>
          <span className="vgp-tile-v" style={riskColor && !stillCollecting ? { color: riskColor } : undefined}>
            {stillCollecting ? "…" : fmtNumber(avgRiskRate, 1)}
          </span>
          <span className="vgp-sub vgp-small">{tr("vgp.perEndpointAvg")}</span>
        </div>
        <div className="vgp-tile">
          <span className="vgp-lbl">{tr("vgp.patchWindow")}</span>
          <span className="vgp-tile-v vgp-tile-v-sm">
            {group.patch_enabled && group.patch_window_start ? `${group.patch_window_start} – ${group.patch_window_end}` : tr("vgp.none")}
          </span>
          <button type="button" className="vgp-link" onClick={() => onNavigateVanitas?.("vanitas-patch")}>
            {group.patch_enabled ? tr("vgp.grace", { count: group.patch_grace_days ?? 0 }) : tr("vgp.setPatch")}
          </button>
        </div>
      </div>

      <div className="vgp-tabs" role="tablist" aria-label={tr("vgp.tabsAria")}>
        {[
          ["members", tr("vgp.tab.members", { count: agents.length })],
          ["actions", tr("vgp.tab.actions")],
          ["nested", tr("vgp.tab.nested", { count: (group.child_group_ids ?? []).length })],
        ].map(([k, label]) => (
          <button key={k} type="button" role="tab" aria-selected={tab === k} className={`vgp-tab${tab === k ? " on" : ""}`} onClick={() => setTab(k)}>
            {label}
          </button>
        ))}
      </div>

      {tab === "members" && (
        <div className="vgp-members" role="tabpanel">
          {agents.length === 0 ? (
            <p className="vgp-sub" style={{ margin: 0 }}>
              {isDynamic ? tr("vgd.noMatchRule", { rule: summarizeGroupRules(group.rules) }) : tr("vgp.noMember")}
            </p>
          ) : (
            memberStats.map((m) => {
              const on = isOnline(m.agent);
              return (
                <div key={m.agent.id} className="vgp-mem">
                  <span className="vgp-dot" style={{ background: on ? CVE_SEVERITY_COLORS.Low : CVE_SEVERITY_COLORS.Medium }} title={tr(on ? "vgd.online" : "vgp.offline")} />
                  <button type="button" className="vgp-mem-host" onClick={() => onNavigateVanitas?.("vanitas-devices", { selectAgentId: m.agent.id })}>
                    {m.agent.hostname}
                  </button>
                  <span className="vgp-sub vgp-small vgp-hide-s">{m.loading ? "…" : tr("vgp.cveCount", { count: m.vulnCount })}</span>
                  <span className="vgp-sub vgp-small vgp-hide-s">{m.loading ? "…" : `CVSS ${fmtNumber(m.avgCvss, 1)}`}</span>
                  {isDynamic ? (
                    <span className="vgp-tag dyn" title={tr("vgd.autoMember")}>
                      {tr("vgp.auto")}
                    </span>
                  ) : (
                    <button type="button" className="vanitas-ghost-btn vgp-btn-xs" onClick={() => handleRemoveMember(m.agent.id)}>
                      {tr("vgp.removeMember")}
                    </button>
                  )}
                </div>
              );
            })
          )}
          {!isDynamic && addableAgents.length > 0 && (
            <select className="vgp-select vgp-add" value="" onChange={(e) => handleAddMember(e.target.value)} aria-label={tr("vgp.addMember")}>
              <option value="">{tr("vgp.addMember")}</option>
              {addableAgents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname}
                </option>
              ))}
            </select>
          )}
        </div>
      )}

      {tab === "actions" && (
        <div className="vgp-actions" role="tabpanel">
          <div className="vgp-box">
            <span className="vgp-lbl">{tr("vgd.pushApp")}</span>
            <span className="vgp-sub">{tr("vgp.pushAppHint")}</span>
            {installers.state.data.length === 0 ? (
              <span className="vgp-sub">{tr("vgd.noInstaller")}</span>
            ) : (
              <div className="vgp-row">
                <select
                  className="vgp-select vgp-grow"
                  value={selectedInstallerId}
                  onChange={(e) => {
                    setSelectedInstallerId(e.target.value);
                    setPushResult(null);
                  }}
                  disabled={pushBusy}
                  aria-label={tr("vgd.chooseInstaller")}
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
                  label={tr("vgp.deployTo", { count: agents.length })}
                  confirmLabel={tr("v.confirm")}
                  className="vanitas-danger-btn"
                  disabled={pushBusy || !selectedInstallerId || agents.length === 0}
                  onConfirm={handlePushInstall}
                  title={tr("vgd.pushInstallTitle")}
                />
              </div>
            )}
            {pushError && <p className="error-note" style={{ margin: 0 }}>{pushError}</p>}
            {pushResult !== null && (
              <span className="vgp-sub">
                <b className="vgp-ok">{tr("vgd.queued", { count: pushResult })}</b> — {tr("vgd.resultsCommands")}
              </span>
            )}
          </div>

          <div className="vgp-box">
            <span className="vgp-lbl">{tr("vgp.updateAgent")}</span>
            {!latestAgentPackage ? (
              <span className="vgp-sub">{tr("vgd.noPackage")}</span>
            ) : (
              <>
                <span className="vgp-sub">{tr("vgp.updateHint", { version: latestAgentPackage.version, count: behindCount })}</span>
                <div className="vgp-row">
                  <ConfirmButton
                    label={tr("vgp.pushVersion", { version: latestAgentPackage.version })}
                    confirmLabel={tr("v.confirm")}
                    className="vanitas-danger-btn"
                    disabled={pushUpdateBusy || agents.length === 0}
                    onConfirm={handlePushUpdate}
                    title={tr("vgd.pushUpdateTitle")}
                  />
                </div>
              </>
            )}
            {pushUpdateError && <p className="error-note" style={{ margin: 0 }}>{pushUpdateError}</p>}
            {pushUpdateResult !== null && (
              <span className="vgp-sub">
                <b className="vgp-ok">{tr("vgd.queued", { count: pushUpdateResult })}</b> — {tr("vgd.resultsLog")}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Groupes imbriqués (2026-09-10) : les membres résolus des sous-groupes s'ajoutent à
          l'union — déjà comptés dans "Postes" ci-dessus (`group_ids` résolus côté serveur). */}
      {tab === "nested" && (
        <div className="vgp-actions" role="tabpanel">
          <span className="vgp-sub">{tr("vgp.nestedHint")}</span>
          <div className="vgp-row">
            {(group.child_group_ids ?? []).length === 0 ? (
              <span className="vgp-sub">{tr("vgd.noSubgroup")}</span>
            ) : (
              group.child_group_ids.map((childId) => (
                <span key={childId} className="vgp-tag">
                  {groupNameById.get(childId) ?? childId}
                  <button type="button" className="vgp-tag-x" onClick={() => handleRemoveChild(childId)} aria-label={tr("vgd.removeSubgroupAria")}>
                    ×
                  </button>
                </span>
              ))
            )}
          </div>
          {childError && <p className="error-note" style={{ margin: 0 }}>{childError}</p>}
          {eligibleChildGroups.length > 0 && (
            <div className="vgp-row">
              <select className="vgp-select vgp-grow" value={selectedChildId} onChange={(e) => setSelectedChildId(e.target.value)} disabled={childBusy} aria-label={tr("vgd.chooseNest")}>
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
      )}
    </aside>
  );
}
