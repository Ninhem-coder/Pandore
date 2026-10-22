import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { useVulnerabilityInventory, useAnssiMatches } from "../hooks/useDashboardData.js";
import { CVE_SEVERITY_COLORS, GENERIC_PALETTE } from "../theme.js";
import { IconDownload } from "../components/icons.jsx";
import AnssiCard from "../components/AnssiCard.jsx";
import { exportCveToExcel } from "../export.js";
import { currentLocale, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

/**
 * Onglet "Vulnérabilités" (sous-catégorie Sécurité, à côté de "Conformité").
 *
 * v4 (2026-09-02, maquette validée par Nicolas — "je trouve la page vulnérabilités pas du tout
 * ergonomique [...] des onglets quand tu clique sur une cve [...] base-toi sur d'autres
 * solutions d'inventaire de vulnérabilité") : reprend l'architecture v3 (table complète sans
 * plafond, recherche unifiée — voir plus bas) et retravaille l'ERGONOMIE :
 * - Bandeau KPI (total CVE / logiciel le + exposé / moyenne appareils-CVE / logiciels distincts)
 *   calculé côté client depuis l'inventaire déjà chargé, aucun nouvel appel réseau.
 * - Recherche avec icône + "Recherches suggérées" (les logiciels les plus exposés, dérivés du
 *   même inventaire).
 * - Table : icône+éditeur par logiciel, exposition en barre visuelle relative au max du parc.
 * - Popup en ONGLETS (Description / Détails techniques / Appareils exposés (N)) — inspirée de
 *   Tenable.io/Qualys VMDR/ServiceNow VR (capture fournie par Nicolas) — plutôt qu'un long
 *   scroll vertical qui mélangeait tout.
 * - Onglet "Description" enrichi d'un bloc "Renseignement externe" (demande explicite de
 *   Nicolas sur la maquette) : avis CERT-FR/ANSSI rapproché de CETTE CVE (réutilise
 *   `get_anssi_matches`, déjà utilisé par le rail ANSSI de cette même page) + signaux
 *   d'exploitation EPSS/exploit-in-the-wild/kit d'exploit (catalogue Microsoft TVM, déjà
 *   interrogé pour severity/CVSS, ces 3 champs n'étaient simplement jamais extraits avant ce
 *   jour — voir `_fetch_vuln_metadata` côté backend).
 *
 * v3 (2026-09-01) : remplace l'ancien duo "formulaire de recherche (search_vulnerabilities,
 * jusqu'à 20 résultats en cartes) + inventaire plafonné (get_top_vulnerabilities, jusqu'à 200
 * lignes enrichies)" par UNE SEULE table listant TOUTES les CVE du parc
 * (`get_vulnerability_inventory` — un seul `summarize` Advanced Hunting, 14 898 CVE distinctes
 * mesurées sur le tenant de production, aucune troncature), filtrée/triée côté client — la barre
 * de recherche EST le filtre de cette table, pas un 2e mécanisme séparé. Un clic ANSSI ou une
 * recherche globale (masthead) passent par le MÊME point d'entrée (`focusQuery`) plutôt que de
 * relancer un appel réseau dédié.
 *
 * Contrepartie assumée de "toutes, sans plafond" : l'inventaire n'a PAS sévérité/CVSS/exploit/
 * correctif (ces champs viennent du catalogue TVM Microsoft, un aller-retour PAR CVE —
 * praticable pour LA CVE cliquée, jamais pour 14 898 lignes d'un coup). Seuls CVE/logiciel/
 * éditeur/appareils exposés (déjà dans l'agrégat KQL, gratuits) sont listés dans la table ; le
 * détail complet (sévérité, CVSS, description, EPSS, exploit, appareils, chemins, export) reste
 * chargé À LA DEMANDE au clic sur une ligne, via `search_vulnerabilities(cve_code, 1)`.
 *
 * ⚠️ "1ère détection"/"Dernière détection" (onglet Détails techniques) ne sont PAS des dates de
 * publication de la CVE : DeviceTvmSoftwareVulnerabilities ne porte aucune date par ligne
 * (vérifié contre le schéma officiel Microsoft). Ces deux colonnes viennent de `LastSeenTime`
 * (DeviceTvmSoftwareEvidenceBeta) : la fenêtre pendant laquelle le LOGICIEL vulnérable a été vu
 * sur le disque des devices exposés — voir le commentaire détaillé dans
 * defender/vulnerabilities.py::search_vulnerabilities.
 *
 * "Exporter Excel" en pied de popup (une CVE = un export), génère le fichier entièrement côté
 * navigateur (voir ../export.js et ../selectors.js::buildCveExportData) à partir des données
 * déjà chargées pour cette CVE — aucun nouvel appel API.
 */

const CVE_PATTERN = /^cve[\s-]?\d{4}[\s-]?\d+$/i;
// [key, translation key]
const TABLE_COLUMNS = [
  ["cve", "vuln.col.cve"],
  ["software", "vuln.col.software"],
  ["devices", "vuln.col.devices"],
];
// Nombre de <tr> RENDUS par palier — les données sont TOUJOURS chargées/filtrées/triées en
// entier, seul le nombre de lignes effectivement dans le DOM est borné et extensible via
// "Afficher N de plus" : 14 898 <tr> d'un coup ralentiraient le navigateur pour rien.
const REVEAL_STEP = 200;

function formatDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(currentLocale(), { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatEpss(epss) {
  if (typeof epss !== "number" || Number.isNaN(epss)) return "—";
  const pct = epss <= 1 ? epss * 100 : epss;
  return `${pct.toFixed(1)} %`;
}

function isSafeHttpUrl(value) {
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

/** Même mécanique que LibraryIcon/AppIcon ailleurs sur ce dashboard : pastille à l'initiale,
 * teinte déterministe (GENERIC_PALETTE + hash du nom) — dupliquée plutôt qu'importée, convention
 * déjà en place sur ce dashboard (petits utilitaires purs répétés par fichier). */
function hashString(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0;
  return Math.abs(h);
}

/** Exportée (2026-09-02) : réutilisée par DeviceOverviewTab.jsx pour la table de
 * vulnérabilités redessinée de la Vue Appareil 360°. */
export function SoftwareIcon({ name }) {
  const label = (name || "?").trim();
  const color = GENERIC_PALETTE[hashString(label.toLowerCase()) % GENERIC_PALETTE.length];
  return (
    <span className="vuln-sw-icon" style={{ color }}>
      {label.slice(0, 1).toUpperCase()}
    </span>
  );
}

/** Exportée (2026-09-02) : réutilisée par DeviceOverviewTab.jsx pour la table de
 * vulnérabilités redessinée de la Vue Appareil 360° — même badge de sévérité que la page
 * "Vulnérabilités" normale, pas une redérivation. */
export function SeverityBadge({ severity }) {
  const color = CVE_SEVERITY_COLORS[severity] || CVE_SEVERITY_COLORS.Unknown;
  return (
    <span className="cve-badge" style={{ borderColor: `${color}66`, color }}>
      {severity || tr("common.unknown")}
    </span>
  );
}

/** Un chemin (disque ou registre) par ligne, sans troncature — chaque device a sa PROPRE ligne
 * (voir VulnDeviceTable plus bas), donc un chemin peut prendre toute la largeur disponible et
 * passer à la ligne au besoin. */
function PathList({ paths }) {
  if (!paths || paths.length === 0) return <span className="cve-small">{tr("vuln.noEvidence")}</span>;
  return (
    <div className="vuln-path-list">
      {paths.map((p, i) => (
        <div key={i} className="vuln-path-line">
          {p}
        </div>
      ))}
    </div>
  );
}

/** Tableau "un device par ligne" pour une CVE, filtrable par nom de device/groupe RBAC. */
function VulnDeviceTable({ devices, query }) {
  const filtered = useMemo(() => {
    const q = (query || "").trim().toLowerCase();
    if (!q) return devices;
    return devices.filter(
      (d) => d.hostname.toLowerCase().includes(q) || (d.rbac_group || "").toLowerCase().includes(q)
    );
  }, [devices, query]);

  if (!devices || devices.length === 0) {
    return <p className="empty">{tr("vuln.noExposedDevice")}</p>;
  }
  if (filtered.length === 0) {
    return <p className="empty">{tr("vuln.noDeviceMatch", { query })}</p>;
  }
  return (
    <div className="cve-table-wrap vuln-device-table-wrap">
      <table className="cve-device-table vuln-device-table">
        <thead>
          <tr>
            <th>{tr("vuln.col.device")}</th>
            <th>{tr("vuln.col.rbacGroup")}</th>
            <th>{tr("vuln.col.diskPaths")}</th>
            <th>{tr("vuln.col.registryPaths")}</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((d) => (
            <tr key={d.hostname}>
              <td className="cve-cell-name">{d.hostname}</td>
              <td className="cve-small">{d.rbac_group || "—"}</td>
              <td>
                <PathList paths={d.disk_paths} />
              </td>
              <td>
                <PathList paths={d.registry_paths} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** État + logique d'export Excel pour une CVE. */
function useExportExcel(v) {
  const [state, setState] = useState({ status: "idle", error: null });

  async function handleExport() {
    setState({ status: "exporting", error: null });
    try {
      await exportCveToExcel(v);
      setState({ status: "idle", error: null });
    } catch (err) {
      // Génération/téléchargement entièrement local (write-excel-file/universal, voir
      // export.js) : un échec ici n'est jamais un problème réseau, plutôt un environnement
      // qui bloque les téléchargements déclenchés par script — affiché tel quel plutôt que
      // silencieusement ignoré (même philosophie "jamais disparaître en silence" que le
      // reste de l'app, voir compliance_detail.py côté backend).
      setState({ status: "idle", error: err.message || tr("vuln.exportFailed") });
    }
  }

  return { ...state, handleExport };
}

/**
 * Bandeau KPI (2026-09-02) — 4 tuiles calculées côté client depuis l'inventaire déjà chargé en
 * entier (`inventory.state.data`), aucun nouvel appel réseau : la liste est déjà triée par
 * appareils exposés décroissant côté backend (`order by DeviceCount desc`), donc le "logiciel le
 * + exposé" est simplement `data[0]` — pas besoin de reparcourir 14 898 lignes pour le trouver.
 */
function KpiStrip({ data }) {
  const stats = useMemo(() => {
    if (data.length === 0) return null;
    const top = data[0];
    const distinctSoftware = new Set(data.map((v) => (v.software_name || "").toLowerCase()).filter(Boolean));
    const totalDevices = data.reduce((sum, v) => sum + (v.affected_count || 0), 0);
    return {
      total: data.length,
      topName: top.software_name || top.software_vendor || "—",
      topCount: top.affected_count,
      avgPerCve: totalDevices / data.length,
      distinctCount: distinctSoftware.size,
    };
  }, [data]);

  if (!stats) return null;

  return (
    <div className="vuln-kpi-strip">
      <div className="vuln-kpi">
        <span className="lbl">{tr("vuln.kpi.total")}</span>
        <span className="val">{stats.total.toLocaleString(currentLocale())}</span>
        <span className="note">{tr("vuln.kpi.noCap")}</span>
      </div>
      <div className="vuln-kpi accent-star">
        <span className="lbl">{tr("vuln.kpi.topSoftware")}</span>
        <span className="val" style={{ fontSize: "16px" }}>
          {stats.topName}
        </span>
        <span className="note">
          {trRich("vuln.kpi.devices", { n: <b>{stats.topCount}</b> })}
        </span>
      </div>
      <div className="vuln-kpi accent-low">
        <span className="lbl">{tr("vuln.kpi.avg")}</span>
        <span className="val">{stats.avgPerCve.toLocaleString(currentLocale(), { minimumFractionDigits: 1, maximumFractionDigits: 1 })}</span>
        <span className="note">{tr("vuln.kpi.wholeFleet")}</span>
      </div>
      <div className="vuln-kpi accent-amber">
        <span className="lbl">{tr("vuln.kpi.distinct")}</span>
        <span className="val">{stats.distinctCount.toLocaleString(currentLocale())}</span>
        <span className="note">{tr("vuln.kpi.withCve")}</span>
      </div>
    </div>
  );
}

/**
 * Inventaire COMPLET des CVE du parc — colonne principale de la page. Chargé une seule fois au
 * montage (voir VulnerabilitiesTab), filtré/trié ENTIÈREMENT côté client sur les données déjà en
 * mémoire : la recherche ci-dessous n'est pas un second appel réseau, juste un filtre sur ce qui
 * est déjà chargé.
 */
function CveInventoryTable({ inventory, search, onSearchChange, onSelectCve }) {
  const [sort, setSort] = useState({ key: "devices", dir: -1 });
  const [visibleCount, setVisibleCount] = useState(REVEAL_STEP);

  const data = inventory.state.data;
  const total = data.length;
  const maxExposure = data[0]?.affected_count || 1;

  // Recherches suggérées (2026-09-02) : les logiciels les plus exposés du parc, dérivés du même
  // inventaire (déjà trié par appareils exposés décroissant côté backend) — le premier logiciel
  // distinct rencontré en parcourant la liste dans l'ordre EST forcément celui avec le plus de
  // devices exposés pour sa pire CVE, pas besoin d'un tri séparé.
  const suggested = useMemo(() => {
    const seen = new Set();
    const out = [];
    for (const v of data) {
      const key = (v.software_name || "").toLowerCase();
      if (!key || seen.has(key)) continue;
      seen.add(key);
      out.push(v.software_name);
      if (out.length >= 6) break;
    }
    return out;
  }, [data]);

  const filteredSorted = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = q
      ? data.filter(
          (v) =>
            v.cve_code.toLowerCase().includes(q) ||
            (v.software_name || "").toLowerCase().includes(q) ||
            (v.software_vendor || "").toLowerCase().includes(q)
        )
      : data;
    const dir = sort.dir;
    return filtered.slice().sort((a, b) => {
      switch (sort.key) {
        case "cve":
          return a.cve_code.localeCompare(b.cve_code) * dir;
        case "software":
          return (a.software_name || "").localeCompare(b.software_name || "") * dir;
        case "devices":
        default:
          return (a.affected_count - b.affected_count) * dir;
      }
    });
  }, [data, search, sort]);

  // Repart de REVEAL_STEP à chaque changement de filtre/tri — un "Afficher N de plus" déjà
  // cliqué sur un ancien filtre n'aurait plus de sens une fois celui-ci changé.
  useEffect(() => {
    setVisibleCount(REVEAL_STEP);
  }, [search, sort]);

  function toggleSort(key) {
    setSort((s) => (s.key === key ? { key, dir: -s.dir } : { key, dir: -1 }));
  }

  const visibleRows = filteredSorted.slice(0, visibleCount);
  const remaining = filteredSorted.length - visibleRows.length;

  if (inventory.state.status === "loading") {
    return (
      <div className="vuln-table-card">
        <p className="card-note" style={{ padding: "22px" }}>
          {tr("vuln.loadingInventory")}
        </p>
      </div>
    );
  }
  if (inventory.state.status === "error") {
    return (
      <div className="vuln-table-card">
        <p className="error-note" style={{ padding: "22px" }}>
          {inventory.state.error}
        </p>
      </div>
    );
  }
  if (total === 0) {
    return (
      <div className="vuln-table-card">
        <p className="empty" style={{ padding: "22px" }}>
          {tr("vuln.noCve")}
        </p>
      </div>
    );
  }

  return (
    <>
      <KpiStrip data={data} />

      <div className="vuln-search-block">
        <div className="vuln-search-input-wrap">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
            <circle cx="9" cy="9" r="6.5" />
            <path d="M18 18l-4.3-4.3" strokeLinecap="round" />
          </svg>
          <input
            className="filter-input vuln-table-search-main"
            type="text"
            placeholder={tr("vuln.searchPlaceholder")}
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
          />
        </div>
        {search.trim() && (
          <p className="card-note vuln-table-result-count">
            {tr("vuln.results", { count: filteredSorted.length, search })}
          </p>
        )}
        {!search.trim() && suggested.length > 0 && (
          <div className="vuln-chip-row">
            <span className="lbl">{tr("vuln.suggested")}</span>
            {suggested.map((name) => (
              <button key={name} type="button" className="vuln-sugg-chip" onClick={() => onSearchChange(name)}>
                <SoftwareIcon name={name} />
                {name}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="vuln-table-card">
        <div className="card-head">
          <h2>{tr("vuln.title")}</h2>
          <span className="card-note">{tr("vuln.sortedByDevices")}</span>
        </div>

        <div className="vuln-table-wrap">
          <table className="vuln-inventory-table">
            <thead>
              <tr>
                {TABLE_COLUMNS.map(([key, labelKey]) => (
                  <th key={key} className={sort.key === key ? "sorted" : ""} onClick={() => toggleSort(key)}>
                    {tr(labelKey)}
                    {sort.key === key && <span className="vuln-table-sort-arrow">{sort.dir === 1 ? "↑" : "↓"}</span>}
                  </th>
                ))}
                <th aria-hidden="true"></th>
              </tr>
            </thead>
            <tbody>
              {visibleRows.length === 0 ? (
                <tr>
                  <td colSpan={TABLE_COLUMNS.length + 1} className="empty">
                    {tr("vuln.noCveForFilter")}
                  </td>
                </tr>
              ) : (
                visibleRows.map((v) => (
                  <tr key={v.cve_code} onClick={() => onSelectCve(v)}>
                    <td className="cve-mono vuln-table-cve-cell">{v.cve_code}</td>
                    <td>
                      <div className="vuln-sw-cell">
                        <SoftwareIcon name={v.software_name} />
                        <div>
                          <div className="vuln-sw-name">{v.software_name || "—"}</div>
                          {v.software_vendor && <div className="vuln-table-vendor">{v.software_vendor}</div>}
                        </div>
                      </div>
                    </td>
                    <td>
                      <div className="vuln-exp-cell">
                        <div className="vuln-exp-bar-track">
                          <div
                            className="vuln-exp-bar-fill"
                            style={{ width: `${Math.max(4, (v.affected_count / maxExposure) * 100).toFixed(0)}%` }}
                          />
                        </div>
                        <span className="vuln-exp-num cve-mono">{v.affected_count}</span>
                      </div>
                    </td>
                    <td className="vuln-table-chevron">
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" aria-hidden="true">
                        <path d="M6 3l5 5-5 5" />
                      </svg>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {remaining > 0 && (
          <button type="button" className="vuln-show-more-btn" onClick={() => setVisibleCount((c) => c + REVEAL_STEP)}>
            {tr("vuln.showMore", { step: Math.min(REVEAL_STEP, remaining), remaining })}
          </button>
        )}
      </div>
    </>
  );
}

// [key, translation key]
const DETAIL_TABS = [
  ["desc", "vuln.tab.desc"],
  ["details", "vuln.tab.details"],
  ["devices", "vuln.tab.devices"],
];

/** 3ᵉ onglet SCOPÉ à un appareil (2026-09-02, maquette validée — DeviceOverviewTab.jsx) — juste
 * les chemins disque/registre où ce logiciel a été détecté SUR CET appareil précis, pas la
 * liste fleet-wide (`VulnDeviceTable`). `entry` = l'élément de `v.devices` (déjà chargé par
 * `search_vulnerabilities`, aucun nouvel appel) dont `hostname` correspond au device — `null`
 * si ce device n'apparaît pas dans la liste (n'a jamais eu d'évidence logicielle retrouvée
 * pour cette CVE, cas déjà géré ailleurs dans ce fichier pour PathList). Couleurs dédiées
 * (ambre = disque, `--star` bleu = registre) — même idiom que "Suivi CVE" (CveWatchTab.jsx,
 * classes DIFFÉRENTES par convention, pas de couplage entre ces deux pages). */
function DeviceScopedPaths({ entry }) {
  if (!entry) {
    return <p className="empty cve-small">{tr("vuln.noPathForDevice")}</p>;
  }
  const disk = entry.disk_paths || [];
  const registry = entry.registry_paths || [];
  return (
    <div className="vuln-modal-device-paths">
      <div className="vuln-modal-path-col">
        <span className="vuln-modal-path-col-label disk">
          <span className="dot" />
          {tr("vuln.col.diskPaths")}
        </span>
        {disk.length > 0 ? (
          disk.map((p, i) => (
            <div key={i} className="vuln-modal-path-line disk">
              {p}
            </div>
          ))
        ) : (
          <p className="vuln-modal-path-empty">{tr("vuln.noDiskPath")}</p>
        )}
      </div>
      <div className="vuln-modal-path-col">
        <span className="vuln-modal-path-col-label registry">
          <span className="dot" />
          {tr("vuln.col.registryPaths")}
        </span>
        {registry.length > 0 ? (
          registry.map((p, i) => (
            <div key={i} className="vuln-modal-path-line registry">
              {p}
            </div>
          ))
        ) : (
          <p className="vuln-modal-path-empty">{tr("vuln.noRegistryPath")}</p>
        )}
      </div>
    </div>
  );
}

/**
 * Popup de détail d'une CVE, en ONGLETS (2026-09-02, maquette validée — voir docstring du
 * fichier). Même chrome que les autres popups du dashboard (`.wizard-overlay`/`.wizard-shell`),
 * mêmes mécanismes Échap/clic en dehors.
 *
 * `row` (la ligne d'inventaire cliquée) ne porte QUE cve_code/software_vendor/software_name/
 * affected_count — "Logiciel concerné" et le compte de l'onglet "Appareils exposés" s'affichent
 * donc instantanément, tout le reste attend le détail complet
 * (`search_vulnerabilities(cve_code, 1)`).
 */
/** Exporté (2026-09-02) : réutilisé tel quel par DeviceOverviewTab.jsx pour l'onglet
 * "Vulnérabilités" de la Vue Appareil 360° ("cliquer dessus comme dans les vuln normal",
 * demande de Nicolas) — même popup, pas une redérivation qui risquerait de diverger. `row` n'a
 * besoin que de `cve_code`/`software_vendor`/`software_name` (`affected_count` optionnel, la
 * pane appareil n'a pas cette donnée fleet-wide — le badge de compte sur l'onglet "Appareils
 * exposés" reste alors simplement vide, pas un bug). */
export function CveDetailModal({ row, onClose, anssiState, deviceScope }) {
  const shellRef = useRef(null);
  const [state, setState] = useState({ status: "loading", data: null, error: null });
  const [activeTab, setActiveTab] = useState("desc");
  const [deviceQuery, setDeviceQuery] = useState("");

  useEffect(() => {
    if (!row) return undefined;
    setActiveTab("desc");
    setDeviceQuery("");
    setState({ status: "loading", data: null, error: null });
    let cancelled = false;
    api.searchVulnerabilities(row.cve_code, 1).then(
      (payload) => {
        if (cancelled) return;
        const list = Array.isArray(payload) ? payload : [];
        if (list.length === 1 && list[0]?.error) {
          setState({ status: "error", data: null, error: list[0].message });
        } else if (list.length === 0) {
          setState({ status: "error", data: null, error: tr("vuln.noDetail") });
        } else {
          setState({ status: "done", data: list[0], error: null });
        }
      },
      (err) => {
        if (!cancelled) setState({ status: "error", data: null, error: err.message });
      }
    );
    return () => {
      cancelled = true;
    };
  }, [row]);

  useEffect(() => {
    if (!row) return undefined;
    function handleKeyDown(e) {
      if (e.key === "Escape") onClose();
    }
    function handlePointerDown(e) {
      if (shellRef.current && !shellRef.current.contains(e.target)) onClose();
    }
    document.addEventListener("keydown", handleKeyDown);
    document.addEventListener("pointerdown", handlePointerDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("pointerdown", handlePointerDown);
    };
  }, [row, onClose]);

  const v = state.data;
  // Appelé inconditionnellement (règle des Hooks) même quand `v` est encore `null` — le
  // bouton "Exporter" n'est rendu que lorsque `state.status === "done"`.
  const { status: exportStatus, error: exportError, handleExport } = useExportExcel(v);

  const anssiMatch = useMemo(() => {
    if (!row || !anssiState?.data) return null;
    const code = row.cve_code.toLowerCase();
    return anssiState.data.find((m) => Array.isArray(m.cve) && m.cve.some((c) => c.toLowerCase() === code)) || null;
  }, [row, anssiState?.data]);

  // Onglet "Chemins" scopé à un appareil (2026-09-02) — `v.devices` est déjà chargé pour la
  // page normale (VulnDeviceTable, fleet-wide), on retrouve juste l'entrée de CE device dedans,
  // aucun nouvel appel réseau.
  const deviceScopedEntry = useMemo(() => {
    if (!deviceScope || !v?.devices) return null;
    const needle = deviceScope.toLowerCase();
    return v.devices.find((d) => (d.hostname || "").toLowerCase() === needle) || null;
  }, [deviceScope, v]);
  const deviceScopedPathCount = deviceScopedEntry
    ? (deviceScopedEntry.disk_paths?.length || 0) + (deviceScopedEntry.registry_paths?.length || 0)
    : 0;

  if (!row) return null;

  return (
    <div className="wizard-overlay">
      <div className="wizard-shell vuln-modal-shell" ref={shellRef} role="dialog" aria-modal="true" aria-label={row.cve_code}>
        <div className="wizard-header">
          <SoftwareIcon name={row.software_name} />
          <div className="wizard-header-text">
            <div className="vuln-modal-title-row">
              <h2 className="cve-mono">{row.cve_code}</h2>
              {v ? (
                <>
                  <SeverityBadge severity={v.severity} />
                  {typeof v.cvss_score === "number" && <span className="badge cvss">CVSS {v.cvss_score.toFixed(1)}</span>}
                </>
              ) : null}
            </div>
            <p className="card-note">
              {trRich("vuln.affectedSoftware", { name: <b>{row.software_name || tr("vuln.unidentified")}</b> })}
              {row.software_vendor ? ` · ${row.software_vendor}` : ""}
            </p>
          </div>
          <button type="button" className="deployed-detail-close" onClick={onClose} aria-label={tr("common.closeAria")}>
            <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        <div className="vuln-modal-tabbar">
          {DETAIL_TABS.map(([key, labelKey]) => (
            <button
              key={key}
              type="button"
              className={`vuln-modal-tab${activeTab === key ? " active" : ""}`}
              onClick={() => setActiveTab(key)}
            >
              {tr(key === "devices" && deviceScope ? "vuln.tab.paths" : labelKey)}
              {key === "devices" && <span className="count">{deviceScope ? deviceScopedPathCount : row.affected_count}</span>}
            </button>
          ))}
        </div>

        <div className="wizard-step-body vuln-modal-tab-body">
          {state.status === "loading" ? (
            <p className="card-note vuln-modal-loading">{tr("vuln.loadingDetail")}</p>
          ) : state.status === "error" ? (
            <p className="error-note vuln-modal-loading">{state.error}</p>
          ) : activeTab === "desc" ? (
            <>
              {v.description ? (
                <div className="vuln-modal-description-block">
                  <p className="vuln-modal-description">{v.description}</p>
                </div>
              ) : (
                <p className="empty cve-small">{tr("vuln.noDescription")}</p>
              )}

              <p className="vuln-modal-section-title">{tr("vuln.externalIntel")}</p>
              <div className="vuln-intel-grid">
                <div className="vuln-intel-card anssi">
                  <div className="vuln-intel-card-head">
                    <span className="vuln-intel-icon">
                      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M10 2l7 3v5c0 4.5-3 7.5-7 8.5-4-1-7-4-7-8.5V5l7-3z" />
                        <path d="M7.3 10l1.9 1.9L13 8" />
                      </svg>
                    </span>
                    <div>
                      <span className="vuln-intel-title">{tr("vuln.certfrMatch")}</span>
                      <span className="vuln-intel-ref">
                        {anssiState?.status === "loading" ? tr("vuln.searching") : tr("vuln.window14")}
                      </span>
                    </div>
                  </div>
                  {anssiMatch ? (
                    <>
                      <p className="vuln-intel-desc">
                        <span className="cve-mono">{anssiMatch.certfr_ref}</span>
                        {anssiMatch.published ? tr("vuln.publishedOn", { date: anssiMatch.published }) : ""}
                        <br />
                        {tr("vuln.matchedByName", { title: anssiMatch.title })}
                      </p>
                      {isSafeHttpUrl(anssiMatch.url) && (
                        <a className="vuln-intel-link" href={anssiMatch.url} target="_blank" rel="noreferrer">
                          {tr("vuln.seeAdvisory")}
                        </a>
                      )}
                    </>
                  ) : (
                    <p className="vuln-intel-desc">
                      {anssiState?.status === "loading"
                        ? "…"
                        : tr("vuln.noAdvisory14")}
                    </p>
                  )}
                </div>

                <div className="vuln-intel-card threat">
                  <div className="vuln-intel-card-head">
                    <span className="vuln-intel-icon">
                      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M10 2.5l8 14H2l8-14z" />
                        <path d="M10 8.2v3.4M10 14.2v.1" />
                      </svg>
                    </span>
                    <div>
                      <span className="vuln-intel-title">{tr("vuln.exploitSignals")}</span>
                      <span className="vuln-intel-ref">{tr("vuln.tvmCatalog")}</span>
                    </div>
                  </div>
                  <div className="vuln-threat-rows">
                    <div className="vuln-threat-row">
                      <span>{tr("vuln.epss")}</span>
                      <b>{formatEpss(v.epss)}</b>
                    </div>
                    <div className="vuln-threat-row">
                      <span>{tr("vuln.exploitInWild")}</span>
                      <b className={v.exploit_in_wild ? "v-bad" : "v-ok"}>{tr(v.exploit_in_wild ? "common.yes" : "common.no")}</b>
                    </div>
                    <div className="vuln-threat-row">
                      <span>{tr("vuln.exploitKit")}</span>
                      <b className={v.exploit_kit ? "v-bad" : "v-ok"}>{tr(v.exploit_kit ? "common.yes" : "common.no")}</b>
                    </div>
                  </div>
                </div>
              </div>
              <p className="vuln-intel-footnote">
                {tr("vuln.anssiFootnote")}
              </p>
            </>
          ) : activeTab === "details" ? (
            <div className="vuln-modal-meta-grid">
              <div className="vuln-modal-meta-tile">
                <span className="lbl">{tr("vuln.severity")}</span>
                <span className="v">
                  <SeverityBadge severity={v.severity} />
                </span>
              </div>
              <div className="vuln-modal-meta-tile">
                <span className="lbl">CVSS</span>
                <span className="v mono">{typeof v.cvss_score === "number" ? v.cvss_score.toFixed(1) : "—"}</span>
              </div>
              <div className="vuln-modal-meta-tile">
                <span className="lbl">{tr("vuln.exploitability")}</span>
                <span className="v">{v.exploitability_level || "—"}</span>
              </div>
              <div className={`vuln-modal-meta-tile${v.security_update_available ? " ok" : " warn"}`}>
                <span className="lbl">{tr("vuln.patchAvailable")}</span>
                <span className="v">{v.security_update_available ? tr("common.yes") : tr("vuln.notKnown")}</span>
              </div>
              <div className="vuln-modal-meta-tile">
                <span className="lbl">{tr("vuln.firstSeen")}</span>
                <span className="v mono" style={{ fontSize: "12.5px" }}>
                  {formatDateTime(v.first_seen)}
                </span>
              </div>
              <div className="vuln-modal-meta-tile">
                <span className="lbl">{tr("vuln.lastSeen")}</span>
                <span className="v mono" style={{ fontSize: "12.5px" }}>
                  {formatDateTime(v.last_seen)}
                </span>
              </div>
            </div>
          ) : deviceScope ? (
            <DeviceScopedPaths entry={deviceScopedEntry} />
          ) : (
            <>
              <div className="vuln-dev-search">
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
                  <circle cx="9" cy="9" r="6.5" />
                  <path d="M18 18l-4.3-4.3" strokeLinecap="round" />
                </svg>
                <input
                  className="filter-input"
                  type="text"
                  placeholder={tr("vuln.filterDevices")}
                  value={deviceQuery}
                  onChange={(e) => setDeviceQuery(e.target.value)}
                />
              </div>
              <VulnDeviceTable devices={v.devices} query={deviceQuery} />
            </>
          )}
        </div>

        {state.status === "done" && (
          <div className="vuln-modal-foot">
            <span className="vuln-modal-foot-hint">{tr("vuln.escHint")}</span>
            <div>
              <button
                type="button"
                className="vuln-export-button"
                onClick={handleExport}
                disabled={exportStatus === "exporting"}
                aria-label={tr("vuln.exportAria", { cve: v.cve_code })}
              >
                <IconDownload />
                {exportStatus === "exporting" ? tr("vuln.exporting") : tr("vuln.exportExcel")}
              </button>
              {exportError && <p className="error-note vuln-export-error">{exportError}</p>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function VulnerabilitiesTab({ initialQuery }) {
  const inventory = useVulnerabilityInventory();
  const anssi = useAnssiMatches();
  // Recherche = filtre de la table — un seul état partagé par le champ de recherche, la
  // recherche globale (masthead) et le clic sur un avis ANSSI.
  const [search, setSearch] = useState("");
  const [detailCve, setDetailCve] = useState(null);
  // Avis ANSSI à l'origine du filtre actuel (pour le bandeau de contexte ci-dessous et le
  // surlignage dans AnssiCard) — effacé dès que l'utilisateur retape lui-même dans le champ.
  const [selectedMatch, setSelectedMatch] = useState(null);
  // CVE en attente d'ouverture automatique une fois l'inventaire chargé (voir `focusQuery` et
  // l'effet juste en dessous) — bug réel trouvé en revue le 2026-09-02 : `focusQuery` appelée
  // AVANT la fin du chargement des ~15000 lignes de l'inventaire (recherche globale/clic ANSSI
  // dès l'arrivée sur cette page) ne trouvait jamais la CVE dans un `inventory.state.data`
  // encore vide, et la popup ne s'ouvrait alors JAMAIS — silencieusement, le champ de
  // recherche se remplissait quand même, masquant l'absence d'ouverture automatique.
  const [pendingCveQuery, setPendingCveQuery] = useState(null);

  useEffect(() => {
    inventory.ensureLoaded();
    anssi.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Point d'entrée unique pour "aller vers" une CVE ou un logiciel : filtre TOUJOURS la table,
  // et ouvre EN PLUS la popup directement si le texte est une CVE exacte déjà présente dans
  // l'inventaire chargé.
  function focusQuery(rawQuery) {
    const trimmed = (rawQuery || "").trim();
    setSearch(trimmed);
    if (!trimmed || !CVE_PATTERN.test(trimmed)) {
      setPendingCveQuery(null);
      return;
    }
    const found = inventory.state.data.find((v) => v.cve_code.toLowerCase() === trimmed.toLowerCase());
    if (found) {
      setDetailCve(found);
      setPendingCveQuery(null);
    } else if (inventory.state.status !== "done") {
      // Pas encore chargé (ou pas encore fini) — retenter dès que l'effet ci-dessous verra
      // `status` passer à "done", plutôt que d'abandonner silencieusement.
      setPendingCveQuery(trimmed);
    } else {
      setPendingCveQuery(null);
    }
  }

  useEffect(() => {
    if (!pendingCveQuery || inventory.state.status !== "done") return;
    const found = inventory.state.data.find((v) => v.cve_code.toLowerCase() === pendingCveQuery.toLowerCase());
    if (found) setDetailCve(found);
    setPendingCveQuery(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingCveQuery, inventory.state.status]);

  function handleSearchChange(value) {
    setSearch(value);
    setSelectedMatch(null);
  }

  // Recherche globale (masthead) : un texte tapé dans le masthead atterrit ici via
  // `initialQuery`. Clé sur `initialQuery?.token` (pas `initialQuery?.query`) : Dashboard.jsx
  // l'incrémente à CHAQUE recherche, y compris si le texte tapé est identique à la fois
  // précédente.
  useEffect(() => {
    if (!initialQuery?.query) return;
    setSelectedMatch(null);
    focusQuery(initialQuery.query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery?.token]);

  // Clic sur un avis ANSSI rapproché : la CVE isolée si l'avis en a résolu une, sinon le nom du
  // logiciel rapproché — même point d'entrée `focusQuery` que la recherche globale.
  function handleSelectMatch(match) {
    const matchQuery = match?.cve?.length > 0 ? match.cve[0] : match?.matched_query;
    if (!matchQuery) return;
    focusQuery(matchQuery);
    setSelectedMatch(match);
  }

  return (
    <div className="vuln-layout">
      <div className="vuln-main">
        {selectedMatch && (
          <p className="vuln-anssi-context">
            {trRich("vuln.filteredFrom", { ref: <span className="cve-mono">{selectedMatch.certfr_ref}</span>, title: selectedMatch.title })}
          </p>
        )}
        <CveInventoryTable inventory={inventory} search={search} onSearchChange={handleSearchChange} onSelectCve={setDetailCve} />
      </div>

      <div className="vuln-rail">
        <div className="vuln-rail-title">{tr("vuln.railTitle")}</div>
        <AnssiCard onSelectMatch={handleSelectMatch} selectedRef={selectedMatch?.certfr_ref} />
      </div>

      <CveDetailModal row={detailCve} onClose={() => setDetailCve(null)} anssiState={anssi.state} />
    </div>
  );
}
