import { useEffect, useMemo, useState } from "react";
import { IconDownload } from "../components/icons.jsx";
import { exportEolToExcel } from "../export.js";
import { useVanitasAgentEol, useVanitasAgents, useVanitasInstallers } from "../hooks/useDashboardData.js";

const TYPE_LABEL_FR = { dotnet: ".NET Framework", os: "Système d'exploitation", software: "Logiciel" };

// Mot-clé simple pour rapprocher une occurrence EOL d'un installeur du catalogue Vanitas
// (point 5 de la revue comparative — "suggérer une mise à jour si une version plus récente
// est déjà au catalogue"). Volontairement approximatif : une correspondance de nom ne prouve
// pas que la version au catalogue est strictement plus récente, juste qu'il vaut la peine
// d'aller vérifier — même esprit que le rapprochement CVE↔logiciel déjà "volontairement
// approximatif" ailleurs dans ce projet (defender/anssi.py). `dotnetfx`/`windows` exclus : ni
// l'un ni l'autre n'est un "installeur" qu'on pousse via Vanitas.
const SLUG_MATCH_WORD = {
  chrome: "chrome",
  firefox: "firefox",
  nodejs: "node",
  php: "php",
  mysql: "mysql",
  postgresql: "postgres",
  "notepad-plus-plus": "notepad",
  "oracle-jdk": "java",
};

/**
 * "Vanitas" > Sécurité > Logiciels obsolètes (EOL) — jalon du 2026-09-08, réécrit le
 * 2026-09-10 (revue comparative demandée par Nicolas — Lansweeper/Intune/endoflife.date) :
 * dates RÉELLES (voir `backend/vanitas/eol.py`) au lieu d'un simple constat binaire, distinction
 * "déjà EOL" / "bientôt obsolète", et suggestion de mise à jour depuis le catalogue Vanitas
 * quand une correspondance existe.
 *
 * Même motif que les autres pages Vanitas fleet-wide sans route dédiée côté serveur : un appel
 * `api.vanitas.agentEol(id)` par agent connu (ici via `useVanitasAgentEol`, un `useKeyedFetch`
 * partagé — même précédent que `useVanitasAgentInventory`, VanitasDevicesTab.jsx).
 */
export default function VanitasEolTab({ onNavigateVanitas, vanitasNav }) {
  const agents = useVanitasAgents();
  const eol = useVanitasAgentEol();
  const installers = useVanitasInstallers();
  const [query, setQuery] = useState("");

  useEffect(() => {
    agents.ensureLoaded();
    installers.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Navigation depuis la Vue d'ensemble (2026-09-11) — "Logiciels EOL — détail" transmet le nom
  // du poste concerné pour pré-remplir la recherche déjà en place, plutôt qu'un nouveau
  // mécanisme de filtre dédié.
  useEffect(() => {
    if (!vanitasNav?.payload?.query) return;
    setQuery(vanitasNav.payload.query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vanitasNav?.token]);

  useEffect(() => {
    for (const agent of agents.state.data ?? []) {
      eol.ensureLoaded(agent.id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents.state.data]);

  const allRows = useMemo(() => {
    const rows = [];
    for (const agent of agents.state.data ?? []) {
      const entry = eol.state[agent.id];
      if (!entry || entry.loading) continue;
      for (const finding of entry.data ?? []) {
        rows.push({ ...finding, agentId: agent.id, hostname: agent.hostname });
      }
    }
    // Le plus urgent en premier : déjà EOL avant "bientôt", puis échéance la plus proche.
    rows.sort((a, b) => {
      if (a.is_eol !== b.is_eol) return a.is_eol ? -1 : 1;
      return (a.days_until_eol ?? 0) - (b.days_until_eol ?? 0);
    });
    return rows;
  }, [agents.state.data, eol.state]);

  const [exportState, setExportState] = useState({ status: "idle", error: null });
  async function handleExport() {
    setExportState({ status: "exporting", error: null });
    try {
      await exportEolToExcel(allRows, TYPE_LABEL_FR);
      setExportState({ status: "idle", error: null });
    } catch (err) {
      setExportState({ status: "idle", error: err.message || "Échec de l'export Excel." });
    }
  }

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return allRows;
    return allRows.filter(
      (r) =>
        r.hostname?.toLowerCase().includes(q) ||
        r.name?.toLowerCase().includes(q) ||
        r.message?.toLowerCase().includes(q)
    );
  }, [allRows, query]);

  // Rapprochement catalogue (point 5) — calculé une fois pour toute la page plutôt que par
  // ligne, `installers.state.data` étant déjà chargé en entier (aucun coût réseau ajouté).
  const catalogMatch = (row) => {
    const word = SLUG_MATCH_WORD[row.product_slug];
    if (!word) return null;
    return (installers.state.data ?? []).find((i) => i.name?.toLowerCase().includes(word)) ?? null;
  };

  const affectedHostCount = useMemo(() => new Set(allRows.map((r) => r.hostname)).size, [allRows]);
  const alreadyEolCount = allRows.filter((r) => r.is_eol).length;
  const upcomingCount = allRows.filter((r) => !r.is_eol).length;

  const stillCollecting = (agents.state.data ?? []).some((a) => eol.state[a.id]?.loading);
  const loading = agents.state.status === "loading";

  if (loading) {
    return (
      <div className="vanitas-hud">
        <p className="vanitas-hud-empty-note">CHARGEMENT…</p>
      </div>
    );
  }

  return (
    <div className="vanitas-hud">
      {agents.state.error && <p className="vanitas-hud-error">{agents.state.error}</p>}

      <div className="vanitas-hud-strip">
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-accent)" }}>
          <div className="label">
            Occurrences EOL<span className="tag">PARC</span>
          </div>
          <div className="value">{allRows.length}</div>
          <div className="bar">
            <i style={{ width: allRows.length ? "100%" : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-high)" }}>
          <div className="label">
            Déjà EOL<span className="tag">URGENT</span>
          </div>
          <div className="value">{alreadyEolCount}</div>
          <div className="bar">
            <i style={{ width: allRows.length ? `${Math.round((alreadyEolCount / allRows.length) * 100)}%` : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-warn)" }}>
          <div className="label">
            Bientôt obsolète<span className="tag">≤ 90J</span>
          </div>
          <div className="value">{upcomingCount}</div>
          <div className="bar">
            <i style={{ width: allRows.length ? `${Math.round((upcomingCount / allRows.length) * 100)}%` : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-accent2)" }}>
          <div className="label">
            Postes concernés<span className="tag">TOTAL</span>
          </div>
          <div className="value">{affectedHostCount}</div>
          <div className="bar">
            <i
              style={{
                width: (agents.state.data ?? []).length ? `${Math.round((affectedHostCount / agents.state.data.length) * 100)}%` : "0%",
              }}
            />
          </div>
        </div>
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>{rows.length} occurrences</h2>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <span className="vanitas-hud-card-note">
              {stillCollecting ? "collecte en cours…" : "dates réelles endoflife.date — voir vanitas/eol.py"}
            </span>
            <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting"}>
              <IconDownload />
              {exportState.status === "exporting" ? "Export…" : "Exporter Excel"}
            </button>
          </div>
        </div>
        {exportState.error && <p className="error-note" style={{ margin: "0 0 12px" }}>{exportState.error}</p>}

        <div className="vanitas-hud-toolbar">
          <div className="vanitas-hud-search">
            <span className="prompt">&gt;</span>
            <input
              type="text"
              placeholder="grep --hostname/--logiciel ..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoComplete="off"
            />
          </div>
        </div>

        {(agents.state.data ?? []).length === 0 ? (
          <p className="vanitas-hud-empty-note">Aucun agent enrôlé pour l'instant.</p>
        ) : rows.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            {allRows.length === 0
              ? "Aucun logiciel/OS obsolète ou bientôt obsolète détecté sur le parc actuel."
              : "Aucun résultat pour ce filtre."}
          </p>
        ) : (
          <div className="vanitas-hud-table-wrap">
            <table className="vanitas-hud-table vanitas-vuln-table">
              <colgroup>
                <col style={{ width: "15%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "13%" }} />
                <col style={{ width: "22%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "20%" }} />
                <col style={{ width: "10%" }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Poste</th>
                  <th>Type</th>
                  <th>État</th>
                  <th>Logiciel/OS</th>
                  <th>Version</th>
                  <th>Constat</th>
                  <th>Catalogue</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => {
                  const match = catalogMatch(r);
                  return (
                    <tr key={`${r.agentId}-${r.type}-${r.name}-${i}`}>
                      <td className="vanitas-hud-host">
                        <span className="name">{r.hostname}</span>
                      </td>
                      <td>{TYPE_LABEL_FR[r.type] || r.type}</td>
                      <td>
                        <span className={`vanitas-hud-status-pill ${r.is_eol ? "bad" : "warn"}`}>
                          {r.is_eol ? "EOL" : "Bientôt"}
                        </span>
                      </td>
                      <td>{r.name}</td>
                      <td className="vanitas-hud-cmd-none">{r.version || "—"}</td>
                      <td>{r.message}</td>
                      <td>
                        {match ? (
                          <button
                            type="button"
                            className="vanitas-ghost-btn"
                            title={`« ${match.name}${match.version ? " v" + match.version : ""} » déjà au catalogue — à vérifier, correspondance approximative`}
                            onClick={() => onNavigateVanitas?.("vanitas-installers")}
                          >
                            ↑ MàJ au catalogue
                          </button>
                        ) : (
                          <span className="cve-small">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
