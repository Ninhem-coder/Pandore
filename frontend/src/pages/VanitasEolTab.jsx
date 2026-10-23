import { useEffect, useMemo, useRef, useState } from "react";
import { IconDownload } from "../components/icons.jsx";
import { exportEolToExcel } from "../export.js";
import { useVanitasAgentEol, useVanitasAgents, useVanitasInstallers } from "../hooks/useDashboardData.js";
import { localizedTable, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";
import { fmtDate } from "./vanitasShared.jsx";

const TYPE_LABEL = localizedTable("veol.type", ["dotnet", "os", "software"]);

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
 * Refonte produits + détail (2026-10-23, maquette canvas validée par Nicolas) : les occurrences
 * (poste × produit) sont REGROUPÉES par produit/version — "Windows 10 22H2" sur 4 postes = une
 * entrée, les postes passent dans le détail — avec bandeau de synthèse (produits, postes, état en
 * barre, source), pastilles État/Type et détail dans un panneau latéral. L'export Excel garde une
 * ligne par occurrence (inchangé). Classes `.veo-*`.
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
  const [stateFilter, setStateFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [selectedKey, setSelectedKey] = useState(null);
  const detailRef = useRef(null);

  useEffect(() => {
    agents.ensureLoaded();
    installers.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Navigation depuis la Vue d'ensemble (2026-09-11) — "Logiciels EOL — détail" transmet le nom
  // du poste concerné pour pré-remplir la recherche (qui porte aussi sur les postes de chaque
  // produit), plutôt qu'un nouveau mécanisme de filtre dédié.
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
      await exportEolToExcel(allRows, TYPE_LABEL);
      setExportState({ status: "idle", error: null });
    } catch (err) {
      setExportState({ status: "idle", error: err.message || tr("v.exportFailed") });
    }
  }

  // Rapprochement catalogue (point 5) — `installers.state.data` déjà chargé en entier (aucun
  // coût réseau ajouté).
  const catalogMatch = (row) => {
    const word = SLUG_MATCH_WORD[row.product_slug];
    if (!word) return null;
    return (installers.state.data ?? []).find((i) => i.name?.toLowerCase().includes(word)) ?? null;
  };

  // Regroupe les occurrences par produit/version — même tri que `allRows` (déjà trié, l'ordre
  // d'insertion de la Map le conserve).
  const products = useMemo(() => {
    const byKey = new Map();
    for (const r of allRows) {
      const key = `${r.type}::${r.name}::${r.version || ""}`;
      let p = byKey.get(key);
      if (!p) {
        p = {
          key,
          type: r.type,
          name: r.name,
          version: r.version,
          is_eol: r.is_eol,
          days_until_eol: r.days_until_eol,
          eol_date: r.eol_date,
          message: r.message,
          product_slug: r.product_slug,
          devices: [],
        };
        byKey.set(key, p);
      }
      p.devices.push({ agentId: r.agentId, hostname: r.hostname, version: r.version });
    }
    return [...byKey.values()];
  }, [allRows]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return products.filter((p) => {
      if (stateFilter === "eol" && !p.is_eol) return false;
      if (stateFilter === "soon" && p.is_eol) return false;
      if (typeFilter !== "all" && p.type !== typeFilter) return false;
      if (!q) return true;
      return (
        `${p.name} ${p.version || ""}`.toLowerCase().includes(q) ||
        (p.message || "").toLowerCase().includes(q) ||
        p.devices.some((d) => d.hostname?.toLowerCase().includes(q))
      );
    });
  }, [products, query, stateFilter, typeFilter]);

  const selected = visible.find((p) => p.key === selectedKey) ?? visible[0] ?? null;

  function selectProduct(key) {
    setSelectedKey(key);
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  const affectedHostCount = useMemo(() => new Set(allRows.map((r) => r.hostname)).size, [allRows]);
  const alreadyEolCount = allRows.filter((r) => r.is_eol).length;
  const upcomingCount = allRows.length - alreadyEolCount;
  const typeCounts = useMemo(() => {
    const c = { os: 0, dotnet: 0, software: 0 };
    for (const p of products) if (c[p.type] !== undefined) c[p.type]++;
    return c;
  }, [products]);
  const productStateCounts = { all: products.length, eol: products.filter((p) => p.is_eol).length };
  productStateCounts.soon = products.length - productStateCounts.eol;

  const stillCollecting = (agents.state.data ?? []).some((a) => eol.state[a.id]?.loading);
  const loading = agents.state.status === "loading";

  if (loading) {
    return (
      <div className="vanitas-hud veo">
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      </div>
    );
  }

  const agentTotal = (agents.state.data ?? []).length;
  const deadline = (p) =>
    p.is_eol
      ? p.eol_date
        ? tr("veol.since", { date: fmtDate(p.eol_date) })
        : tr("veol.noDate")
      : tr("veol.inDays", { count: Math.max(0, Math.round(p.days_until_eol ?? 0)) });
  const selMatch = selected ? catalogMatch(selected) : null;

  return (
    <div className="vanitas-hud veo">
      {agents.state.error && <p className="vanitas-hud-error">{agents.state.error}</p>}

      <section className="veo-card veo-sum" aria-label={tr("veol.sumAria")}>
        <div className="veo-sum-col">
          <span className="veo-lbl">{tr("veol.products")}</span>
          <span className="veo-val accent">{products.length}</span>
          <span className="veo-sub veo-small">
            {stillCollecting ? tr("vv.collecting") : tr("veol.occurrencesSub", { count: allRows.length })}
          </span>
        </div>
        <div className="veo-sum-col">
          <span className="veo-lbl">{tr("vv.kpi.affected")}</span>
          <span className="veo-val">
            {affectedHostCount} <small>/ {agentTotal}</small>
          </span>
          <span className="veo-sub veo-small">{tr("veol.atLeastOne")}</span>
        </div>
        <div className="veo-sum-state">
          <span className="veo-lbl">{tr("veol.byState")}</span>
          <span className="veo-sum-bar" role="img" aria-label={`${tr("veol.leg.eol", { count: alreadyEolCount })}, ${tr("veol.leg.soon", { count: upcomingCount })}`}>
            <i className="eol" style={{ flex: alreadyEolCount }} />
            <i className="soon" style={{ flex: upcomingCount }} />
          </span>
          <div className="veo-legend">
            <button type="button" className="veo-leg" onClick={() => setStateFilter("eol")}>
              <i className="eol" />
              {tr("veol.leg.eol", { count: alreadyEolCount })}
            </button>
            <button type="button" className="veo-leg" onClick={() => setStateFilter("soon")}>
              <i className="soon" />
              {tr("veol.leg.soon", { count: upcomingCount })}
            </button>
          </div>
        </div>
        <div className="veo-sum-col veo-sum-fourth">
          <span className="veo-lbl">{tr("veol.source")}</span>
          <span className="veo-source">endoflife.date</span>
          <span className="veo-sub veo-small">{tr("veol.sourceSub")}</span>
        </div>
      </section>

      <div className="veo-split">
        <section className="veo-card veo-list" aria-label={tr("veol.listTitle")}>
          <div className="veo-list-head">
            <h2 className="veo-h2">{tr("veol.listTitle")}</h2>
            <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting"}>
              <IconDownload />
              {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
            </button>
          </div>
          {exportState.error && <p className="error-note" style={{ margin: 0 }}>{exportState.error}</p>}
          <label className="veo-search-wrap">
            <span className="veo-sr">{tr("veol.searchShort")}</span>
            <input type="search" className="veo-search" placeholder={tr("veol.searchShort")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
          </label>
          <div className="veo-filters">
            <span className="veo-field">
              <span className="veo-lbl">{tr("veol.state")}</span>
              <span className="veo-chips" role="group" aria-label={tr("veol.state")}>
                {["all", "eol", "soon"].map((k) => (
                  <button key={k} type="button" className={`veo-chip${stateFilter === k ? " on" : ""}`} aria-pressed={stateFilter === k} onClick={() => setStateFilter(k)}>
                    {tr(`veol.chip.${k}`)} <b>{productStateCounts[k]}</b>
                  </button>
                ))}
              </span>
            </span>
            <span className="veo-field">
              <span className="veo-lbl">{tr("veol.typeLbl")}</span>
              <span className="veo-chips" role="group" aria-label={tr("veol.typeLbl")}>
                {["all", "os", "dotnet", "software"].map((k) => (
                  <button key={k} type="button" className={`veo-chip${typeFilter === k ? " on" : ""}`} aria-pressed={typeFilter === k} onClick={() => setTypeFilter(k)}>
                    {tr(`veol.chip.${k === "all" ? "allType" : k}`)} <b>{k === "all" ? products.length : typeCounts[k]}</b>
                  </button>
                ))}
              </span>
            </span>
          </div>

          {agentTotal === 0 ? (
            <p className="veo-empty">{tr("vv.noAgent")}</p>
          ) : visible.length === 0 ? (
            <p className="veo-empty">{products.length === 0 ? (stillCollecting ? tr("vv.collecting") : tr("veol.noEol")) : tr("vv.noResult")}</p>
          ) : (
            <div className="veo-rows">
              {visible.map((p) => {
                const isSel = selected?.key === p.key;
                return (
                  <button key={p.key} type="button" className={`veo-prod ${p.is_eol ? "eol" : "soon"}${isSel ? " sel" : ""}`} aria-pressed={isSel} onClick={() => selectProduct(p.key)}>
                    <span className="veo-prod-stripe" />
                    <span className="veo-prod-name">
                      {p.name}
                      {p.version ? ` ${p.version}` : ""}
                    </span>
                    <span className={`veo-pill ${p.is_eol ? "eol" : "soon"}`}>{p.is_eol ? "EOL" : tr("veol.soon")}</span>
                    <span className="veo-prod-meta">
                      <span className="veo-tag">{TYPE_LABEL[p.type] || p.type}</span>
                      <span>{deadline(p)}</span>
                      <span>·</span>
                      <span className="veo-ink">{tr("vv.endpoints", { count: p.devices.length })}</span>
                      {catalogMatch(p) && (
                        <>
                          <span>·</span>
                          <span className="veo-accent">{tr("veol.updateInCatalog")}</span>
                        </>
                      )}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        <div ref={detailRef} className="veo-detail-slot">
          {selected ? (
            <aside className={`veo-card veo-detail ${selected.is_eol ? "eol" : "soon"}`} aria-label={tr("veol.detailAria")}>
              <div className="veo-detail-head">
                <div className="veo-detail-title">
                  <h2>
                    {selected.name}
                    {selected.version ? ` ${selected.version}` : ""}
                  </h2>
                  <span className="veo-sub">{TYPE_LABEL[selected.type] || selected.type}</span>
                </div>
                <span className={`veo-pill ${selected.is_eol ? "eol" : "soon"}`}>{selected.is_eol ? "EOL" : tr("veol.soon")}</span>
              </div>

              <div className="veo-deadline">
                <div className="veo-sum-col">
                  <span className="veo-lbl">{tr("veol.eolDate")}</span>
                  <span className="veo-val veo-deadline-date">{selected.eol_date ? fmtDate(selected.eol_date) : "—"}</span>
                </div>
                <span className="veo-deadline-msg">{selected.message || deadline(selected)}</span>
              </div>

              {selMatch ? (
                <div className="veo-match">
                  <span className="veo-lbl veo-accent">{tr("veol.catalogTitle")}</span>
                  <span>
                    {trRich("veol.catalogText", { name: <b>{`${selMatch.name}${selMatch.version ? ` v${selMatch.version}` : ""}`}</b> })}
                  </span>
                  <span className="veo-sub veo-small">{tr("veol.catalogWarn")}</span>
                  <button type="button" className="vanitas-queue-btn" onClick={() => onNavigateVanitas?.("vanitas-installers")}>
                    {tr("veol.deployFrom")}
                  </button>
                </div>
              ) : (
                <p className="veo-sub" style={{ margin: 0 }}>
                  {tr("veol.noCatalog")}
                </p>
              )}

              <div className="veo-devices">
                <span className="veo-lbl">{tr("veol.devices", { count: selected.devices.length })}</span>
                {selected.devices.map((d) => (
                  <button
                    key={d.agentId}
                    type="button"
                    className="veo-dev"
                    onClick={() => onNavigateVanitas?.("vanitas-devices", { selectAgentId: d.agentId })}
                  >
                    <span className="veo-mono">{d.hostname}</span>
                    <span className="veo-mono veo-muted">{d.version ? `v${d.version}` : "—"}</span>
                  </button>
                ))}
              </div>
            </aside>
          ) : (
            <div className="veo-card veo-empty-panel">
              <p className="veo-sub">{tr("veol.pick")}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
