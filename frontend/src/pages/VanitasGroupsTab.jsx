import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import {
  isErrorPayload,
  useVanitasAgentVulnerabilities,
  useVanitasAgents,
  useVanitasGroupMembers,
  useVanitasGroups,
} from "../hooks/useDashboardData.js";
import VanitasGroupDetail from "./VanitasGroupDetail.jsx";
import { ConfirmButton, GroupRuleBuilder, fmtDate, summarizeGroupRules } from "./vanitasShared.jsx";

function CreateGroupForm({ onCreated }) {
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
        setName("");
        setRules(null);
        setIsDynamic(false);
        onCreated();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="vanitas-hud-toolbar" style={{ flexWrap: "wrap", alignItems: "flex-start" }}>
      <div className="vanitas-hud-search" style={{ flex: "1 1 220px" }}>
        <span className="prompt">&gt;</span>
        <input
          type="text"
          placeholder="nom du nouveau groupe..."
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={busy}
          autoComplete="off"
        />
      </div>
      <div className="vanitas-hud-chips">
        <button
          type="button"
          className={`vanitas-hud-chip${!isDynamic ? " active" : ""}`}
          onClick={() => {
            setIsDynamic(false);
            setRules(null);
          }}
        >
          <span className="led" />STATIQUE
        </button>
        <button
          type="button"
          className={`vanitas-hud-chip${isDynamic ? " active" : ""}`}
          onClick={() => setIsDynamic(true)}
        >
          <span className="led" />DYNAMIQUE
        </button>
      </div>
      <button type="submit" className="vanitas-queue-btn" disabled={busy || !name.trim() || (isDynamic && !hasValidRule)}>
        {busy ? "Création…" : "Créer le groupe"}
      </button>
      {error && (
        <p className="error-note" style={{ margin: 0, width: "100%" }}>
          {error}
        </p>
      )}
      {isDynamic && (
        <div style={{ width: "100%" }}>
          <GroupRuleBuilder rules={rules} onChange={setRules} disabled={busy} />
          <p className="vanitas-hud-empty-note" style={{ margin: "10px 0 0" }}>
            Membres calculés automatiquement selon la règle ci-dessus — jamais d'affectation
            manuelle sur ce type de groupe. Plusieurs conditions se combinent en ET (toutes
            requises) ou en OU (au moins une), au choix.
          </p>
        </div>
      )}
    </form>
  );
}

/**
 * "Vanitas" > Inventaire > Groupes (2026-09-08, demande de Nicolas — "ranger les postes dans
 * des groupes si trop de devices et pas organisé", étendu le même soir en many-to-many +
 * groupes dynamiques par motif de nom, "les deux" confirmé via AskUserQuestion). Motif HUD
 * standard (bandeau + table + master/detail en état LOCAL, jamais `onNavigate` — voir
 * `VanitasDevicesTab.jsx`/`VanitasDeviceDetail.jsx`, le précédent exact confirmé par
 * exploration avant de coder).
 *
 * L'affectation d'un poste à un groupe STATIQUE se fait depuis "Postes" (liste ou fiche) —
 * cette page se concentre sur la création/le renommage/la suppression de groupes et la vue
 * agrégée par groupe (voir VanitasGroupDetail.jsx). `device_count` vient directement du
 * serveur (déjà correct pour les deux types — statique via la table de jointure, dynamique via
 * `fnmatch` — plus besoin de le recalculer côté client comme au jalon v1).
 */
export default function VanitasGroupsTab() {
  const groups = useVanitasGroups();
  const agents = useVanitasAgents();
  const groupMembers = useVanitasGroupMembers();
  const vulnerabilities = useVanitasAgentVulnerabilities();

  const [selectedGroupId, setSelectedGroupId] = useState(null);
  const [deleteError, setDeleteError] = useState(null);

  useEffect(() => {
    groups.ensureLoaded();
    agents.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (selectedGroupId) groupMembers.ensureLoaded(selectedGroupId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedGroupId]);

  const selectedMembersState = selectedGroupId ? groupMembers.state[selectedGroupId] : null;

  // Une fois les hostnames membres connus, charge leur rapprochement CVE (déjà mis en cache
  // par agent) pour le calcul du "taux de risque moyen" du groupe — VanitasGroupDetail.jsx ne
  // fait lui-même aucun appel réseau, seulement de la présentation.
  useEffect(() => {
    if (!selectedMembersState || selectedMembersState.loading) return;
    const hostnames = new Set(selectedMembersState.data ?? []);
    for (const a of agents.state.data ?? []) {
      if (hostnames.has(a.hostname)) vulnerabilities.ensureLoaded(a.id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedMembersState, agents.state.data]);

  function selectGroup(groupId) {
    setSelectedGroupId(groupId);
  }

  async function handleDelete(groupId) {
    setDeleteError(null);
    try {
      const payload = await api.vanitas.deleteGroup(groupId);
      if (isErrorPayload(payload)) {
        setDeleteError(payload.message);
      } else {
        groups.refresh();
        agents.refresh();
      }
    } catch (err) {
      setDeleteError(err.message);
    }
  }

  const selectedGroup = selectedGroupId ? groups.state.data.find((g) => g.id === selectedGroupId) ?? null : null;
  const selectedMemberHostnames = useMemo(
    () => new Set(selectedMembersState?.data ?? []),
    [selectedMembersState]
  );
  const selectedGroupAgents = useMemo(
    () => (agents.state.data ?? []).filter((a) => selectedMemberHostnames.has(a.hostname)),
    [agents.state.data, selectedMemberHostnames]
  );

  if (selectedGroup) {
    return (
      <VanitasGroupDetail
        key={selectedGroup.id}
        group={selectedGroup}
        allGroups={groups.state.data}
        agents={selectedGroupAgents}
        membersLoading={!selectedMembersState || selectedMembersState.loading}
        vulnerabilities={vulnerabilities.state}
        onBack={() => setSelectedGroupId(null)}
        onChanged={() => {
          groups.refresh();
          agents.refresh();
          groupMembers.ensureLoaded(selectedGroup.id);
        }}
        onDeleted={() => {
          setSelectedGroupId(null);
          groups.refresh();
          agents.refresh();
        }}
      />
    );
  }

  const loading = groups.state.status === "loading" || agents.state.status === "loading";

  if (loading) {
    return (
      <div className="vanitas-hud">
        <p className="vanitas-hud-empty-note">CHARGEMENT…</p>
      </div>
    );
  }

  return (
    <div className="vanitas-hud">
      {groups.state.error && <p className="vanitas-hud-error">{groups.state.error}</p>}
      {deleteError && <p className="vanitas-hud-error">{deleteError}</p>}

      <div className="vanitas-hud-card vanitas-hud-frame" style={{ marginBottom: "20px" }}>
        <div className="vanitas-hud-card-head">
          <h2>Créer un groupe</h2>
        </div>
        <CreateGroupForm onCreated={groups.refresh} />
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>
            {groups.state.data.length} groupe{groups.state.data.length > 1 ? "s" : ""}
          </h2>
          <span className="vanitas-hud-card-note">CLIC LIGNE → DÉTAIL DU GROUPE</span>
        </div>
        {groups.state.data.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            Aucun groupe créé pour l'instant — utile pour ranger les postes une fois le parc plus
            fourni.
          </p>
        ) : (
          <div className="vanitas-hud-table-wrap">
            <table className="vanitas-hud-table">
              <thead>
                <tr>
                  <th>Nom</th>
                  <th>Type</th>
                  <th>Postes</th>
                  <th>Modifié le</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {groups.state.data.map((g) => (
                  <tr
                    key={g.id}
                    tabIndex={0}
                    role="button"
                    aria-label={`Ouvrir le groupe ${g.name}`}
                    onClick={() => selectGroup(g.id)}
                  >
                    <td className="vanitas-hud-host">
                      <span className="name">{g.name}</span>
                      {summarizeGroupRules(g.rules) && <span className="id">{summarizeGroupRules(g.rules)}</span>}
                      {g.child_group_ids?.length > 0 && (
                        <span className="id">
                          + {g.child_group_ids.length} sous-groupe{g.child_group_ids.length > 1 ? "s" : ""}
                        </span>
                      )}
                    </td>
                    <td>
                      <span className={`vanitas-hud-status-pill ${g.rules ? "pending" : "ok"}`}>
                        {g.rules ? "DYNAMIQUE" : "STATIQUE"}
                      </span>
                    </td>
                    <td>
                      <span className="vanitas-hud-apps-badge">{g.device_count}</span>
                    </td>
                    <td className="cve-small">{fmtDate(g.updated_at)}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <ConfirmButton
                        label="Supprimer"
                        confirmLabel="Confirmer ?"
                        className="vanitas-danger-btn"
                        onConfirm={() => handleDelete(g.id)}
                      />
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
