import { useEffect, useMemo, useState } from "react";
import { useAuth } from "../AuthContext.jsx";
import CopyButton from "../components/CopyButton.jsx";
import { useVanitasInstallers } from "../hooks/useDashboardData.js";
import { fmtBytes, fmtDateTime, fmtRelative, hasVanitasAccess } from "./vanitasShared.jsx";
import { currentLocale, tr } from "../i18n/core.js";

/**
 * "Vanitas" > Catalogue d'application (2026-09-09, retour de Nicolas — "je pensais faire en
 * sorte d'avoir Application dans l'onglet Administration pour rajouter faire des modifications
 * sur une application et Catalogue d'application en dessous de Vue d'ensemble avec toutes les
 * applications qu'on a publié depuis Application dans un premier temps") : remontée en item nu
 * juste sous "Vue d'ensemble" (comme "Catalogue d'application" côté Pandore, `Sidebar.jsx`),
 * accessible à TOUT compte connecté — la distinction admin/lecture ne porte que sur l'AJOUT/la
 * MODIFICATION (`VanitasInstallersTab.jsx`, "Application" sous "Administration"), jamais sur la
 * simple consultation, même philosophie que le catalogue Pandore (`GET .../app-library` déjà
 * lecture libre).
 *
 * "Dans un premier temps" (mot de Nicolas) : liste en lecture seule des installeurs déjà
 * publiés, aucune action d'écriture ici (ni ajout, ni modification, ni suppression — tout ça
 * reste dans "Application"). Même hook `useVanitasInstallers()` que la page d'administration,
 * même cache partagé — parcourir ce catalogue ne redéclenche jamais l'appel réseau si
 * "Application" a déjà été visitée dans la session (et réciproquement).
 *
 * Refonte (2026-10-23, maquette canvas validée par Nicolas, même langage que la Vue d'ensemble
 * "bento") : 4 chiffres de synthèse DÉRIVÉS de la même liste (nombre, formats, taille totale,
 * dernière publication — aucune donnée nouvelle), filtres par format, tri, bascule Cartes/Liste
 * (mémorisée par navigateur) et copie de la commande d'installation. Classes `.vcat-*`.
 */

// Format déduit de l'extension du fichier d'origine — même règle que `sourceTypeFromFileName`
// (VanitasInstallersTab.jsx), étendue à EXE pour le filtre (l'assistant, lui, n'en a pas besoin).
const FORMATS = ["MSI", "EXE", "PS1", "other"];
const FORMAT_TONE = { MSI: "accent", EXE: "warn", PS1: "accent2", other: "neutral" };
const VIEW_STORAGE_KEY = "vanitasCatalogView";

function formatOf(fileName) {
  const ext = (fileName || "").split(".").pop().toUpperCase();
  return FORMATS.includes(ext) ? ext : "other";
}

function formatLabel(format) {
  return format === "other" ? tr("vcat.format.other") : format;
}

function readStoredView() {
  try {
    return localStorage.getItem(VIEW_STORAGE_KEY) === "list" ? "list" : "cards";
  } catch {
    return "cards";
  }
}

function PackageIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" aria-hidden="true">
      <path d="M10 2.5l6.5 3.5v8L10 17.5 3.5 14V6z" />
      <path d="M3.5 6L10 9.5 16.5 6M10 9.5v8" />
    </svg>
  );
}

export default function VanitasAppCatalogTab({ onNavigateVanitas }) {
  const installers = useVanitasInstallers();
  const { user } = useAuth();
  const [query, setQuery] = useState("");
  const [format, setFormat] = useState("all");
  const [sort, setSort] = useState("recent");
  const [view, setView] = useState(readStoredView);

  useEffect(() => {
    installers.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function changeView(next) {
    setView(next);
    try {
      localStorage.setItem(VIEW_STORAGE_KEY, next);
    } catch {
      // Préférence de confort seulement — rien de bloquant si le stockage est indisponible.
    }
  }

  const all = useMemo(
    () => (installers.state.data ?? []).map((i) => ({ ...i, format: formatOf(i.original_filename) })),
    [installers.state.data]
  );

  const stats = useMemo(() => {
    const byFormat = { MSI: 0, EXE: 0, PS1: 0, other: 0 };
    let totalBytes = 0;
    let latest = null;
    for (const i of all) {
      byFormat[i.format]++;
      totalBytes += Number(i.size_bytes) || 0;
      if (!latest || new Date(i.uploaded_at) > new Date(latest.uploaded_at)) latest = i;
    }
    return { byFormat, totalBytes, latest };
  }, [all]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = all.filter((i) => {
      if (format !== "all" && i.format !== format) return false;
      if (!q) return true;
      return [i.name, i.version, i.original_filename].filter(Boolean).join(" ").toLowerCase().includes(q);
    });
    return filtered.sort((a, b) => {
      if (sort === "name") return (a.name || "").localeCompare(b.name || "", currentLocale());
      if (sort === "size") return (Number(b.size_bytes) || 0) - (Number(a.size_bytes) || 0);
      return new Date(b.uploaded_at) - new Date(a.uploaded_at);
    });
  }, [all, query, format, sort]);

  const canManage = hasVanitasAccess(user, "applications", "read");
  const presentFormats = FORMATS.filter((f) => stats.byFormat[f] > 0);
  const loading = installers.state.status === "loading";

  return (
    <div className="vanitas-hud vcat">
      {installers.state.error && <p className="vanitas-hud-error">{installers.state.error}</p>}

      <section className="vcat-stats" aria-label={tr("vcat.statsAria")}>
        <div className="vcat-card vcat-stat">
          <span className="vcat-lbl">{tr("vcat.stat.published")}</span>
          <span className="vcat-val accent">{loading ? "—" : all.length}</span>
          <span className="vcat-sub">{tr("vcat.stat.publishedSub")}</span>
        </div>
        <div className="vcat-card vcat-stat">
          <span className="vcat-lbl">{tr("vcat.stat.formats")}</span>
          <span
            className="vcat-format-bar"
            role="img"
            aria-label={presentFormats.map((f) => `${stats.byFormat[f]} ${formatLabel(f)}`).join(", ")}
          >
            {presentFormats.map((f) => (
              <i key={f} className={`tone-${FORMAT_TONE[f]}`} style={{ flex: stats.byFormat[f] }} />
            ))}
          </span>
          <span className="vcat-sub vcat-format-legend">
            {presentFormats.length === 0
              ? "—"
              : presentFormats.map((f) => (
                  <span key={f}>
                    <b>{stats.byFormat[f]}</b> {formatLabel(f)}
                  </span>
                ))}
          </span>
        </div>
        <div className="vcat-card vcat-stat">
          <span className="vcat-lbl">{tr("vcat.stat.size")}</span>
          <span className="vcat-val">{stats.totalBytes ? fmtBytes(stats.totalBytes) : "—"}</span>
          <span className="vcat-sub">{tr("vcat.stat.sizeSub")}</span>
        </div>
        <div className="vcat-card vcat-stat">
          <span className="vcat-lbl">{tr("vcat.stat.latest")}</span>
          <span className="vcat-latest">{stats.latest?.name ?? "—"}</span>
          {stats.latest && (
            <span className="vcat-sub" title={fmtDateTime(stats.latest.uploaded_at)}>
              {tr("vcat.stat.latestSub", { version: stats.latest.version || "—", when: fmtRelative(stats.latest.uploaded_at) })}
            </span>
          )}
        </div>
      </section>

      <section className="vcat-card vcat-panel" aria-label={tr("page.vanitas-app-catalog")}>
        {/* Catalogue vide : ni barre d'outils ni compteur (rien à filtrer/trier), un vrai état vide
            à la place — icône réticule de la charte (§10), action vers "Application" si le compte
            y a accès. */}
        {!loading && all.length === 0 ? (
          <div className="vcat-emptystate">
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
              <circle cx="24" cy="24" r="16" />
              <circle cx="24" cy="24" r="6" />
              <path d="M24 4v8M24 36v8M4 24h8M36 24h8" />
            </svg>
            <h2 className="vcat-h2">{tr("vcat.emptyTitle")}</h2>
            <p className="vcat-sub">{tr(canManage ? "vcat.emptyText" : "vcat.emptyTextReadOnly")}</p>
            {canManage && (
              <button type="button" className="vcat-primary" onClick={() => onNavigateVanitas?.("vanitas-installers")}>
                {tr("vcat.addInstaller")}
              </button>
            )}
          </div>
        ) : (
          <>
        <div className="vcat-toolbar">
          <label className="vcat-search-wrap">
            <span className="vcat-sr">{tr("vcat.searchPlaceholder")}</span>
            <input
              type="search"
              className="vcat-search"
              placeholder={tr("vcat.searchPlaceholder")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoComplete="off"
            />
          </label>
          <div className="vcat-chips" role="group" aria-label={tr("vcat.filterAria")}>
            {["all", ...presentFormats].map((f) => (
              <button
                key={f}
                type="button"
                className={`vcat-chip${format === f ? " on" : ""}`}
                aria-pressed={format === f}
                onClick={() => setFormat(f)}
              >
                {f === "all" ? tr("vcat.all") : formatLabel(f)} <b>{f === "all" ? all.length : stats.byFormat[f]}</b>
              </button>
            ))}
          </div>
          <label className="vcat-sort">
            <span className="vcat-lbl">{tr("vcat.sort")}</span>
            <select className="vcat-select" value={sort} onChange={(e) => setSort(e.target.value)}>
              <option value="recent">{tr("vcat.sort.recent")}</option>
              <option value="name">{tr("vcat.sort.name")}</option>
              <option value="size">{tr("vcat.sort.size")}</option>
            </select>
          </label>
          <div className="vcat-seg" role="group" aria-label={tr("vcat.view")}>
            <button type="button" className={view === "cards" ? "on" : ""} aria-pressed={view === "cards"} onClick={() => changeView("cards")}>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
                <rect x="1.5" y="1.5" width="4.5" height="4.5" rx="1" />
                <rect x="8" y="1.5" width="4.5" height="4.5" rx="1" />
                <rect x="1.5" y="8" width="4.5" height="4.5" rx="1" />
                <rect x="8" y="8" width="4.5" height="4.5" rx="1" />
              </svg>
              {tr("vcat.view.cards")}
            </button>
            <button type="button" className={view === "list" ? "on" : ""} aria-pressed={view === "list"} onClick={() => changeView("list")}>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
                <path d="M2 3.5h10M2 7h10M2 10.5h10" />
              </svg>
              {tr("vcat.view.list")}
            </button>
          </div>
        </div>

        <div className="vcat-meta">
          <span className="vcat-sub">{tr("vcat.count", { filtered: rows.length, count: all.length })}</span>
          {canManage && (
            <button type="button" className="vcat-link" onClick={() => onNavigateVanitas?.("vanitas-installers")}>
              {tr("vcat.manageLink")}
            </button>
          )}
        </div>

        {loading ? (
          <div className="vcat-grid" aria-busy="true">
            <span className="vcat-sr">{tr("v.loading")}</span>
            {Array.from({ length: 6 }, (_, i) => (
              <div className="vcat-card vcat-app" key={i}>
                <span className="vcat-sk" style={{ width: "60%", height: 16 }} />
                <span className="vcat-sk" style={{ width: "80%", height: 12 }} />
                <span className="vcat-sk" style={{ width: "100%", height: 32 }} />
              </div>
            ))}
          </div>
        ) : rows.length === 0 ? (
          <div className="vcat-nomatch">
            <svg width="40" height="40" viewBox="0 0 48 48" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
              <circle cx="24" cy="24" r="16" />
              <circle cx="24" cy="24" r="6" />
              <path d="M24 4v8M24 36v8M4 24h8M36 24h8" />
            </svg>
            <span className="vcat-h2">{tr("vcat.noMatch")}</span>
            <button
              type="button"
              className="vcat-chip"
              onClick={() => {
                setQuery("");
                setFormat("all");
              }}
            >
              {tr("vcat.clearFilters")}
            </button>
          </div>
        ) : view === "cards" ? (
          <div className="vcat-grid">
            {rows.map((i) => (
              <article className={`vcat-card vcat-app tone-${FORMAT_TONE[i.format]}`} key={i.id}>
                <div className="vcat-app-head">
                  <span className="vcat-ico">
                    <PackageIcon />
                  </span>
                  <span className="vcat-app-id">
                    <span className="vcat-app-name">{i.name}</span>
                    {i.version && <span className="vcat-mono vcat-muted">v{i.version}</span>}
                  </span>
                  <span className="vcat-tag">{formatLabel(i.format)}</span>
                </div>
                <span className="vcat-mono vcat-muted vcat-ellipsis" title={i.original_filename}>
                  {i.original_filename}
                </span>
                <div className="vcat-cmd">
                  <code title={i.install_command}>{i.install_command}</code>
                  <CopyButton className="vcat-copy" text={i.install_command} />
                </div>
                <div className="vcat-app-foot">
                  <span>{fmtBytes(i.size_bytes)}</span>
                  <span title={fmtDateTime(i.uploaded_at)}>{tr("vcat.published", { when: fmtRelative(i.uploaded_at) })}</span>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <div className="vcat-table-wrap">
            <table className="vcat-table">
              <thead>
                <tr>
                  <th>{tr("vcat.col.name")}</th>
                  <th>{tr("vcat.col.format")}</th>
                  <th className="vcat-hide-sm">{tr("vcat.col.file")}</th>
                  <th>{tr("vcat.col.command")}</th>
                  <th>{tr("vcat.col.size")}</th>
                  <th className="vcat-hide-sm">{tr("vcat.col.published")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((i) => (
                  <tr key={i.id} className={`tone-${FORMAT_TONE[i.format]}`}>
                    <td>
                      <span className="vcat-app-name">{i.name}</span>{" "}
                      {i.version && <span className="vcat-mono vcat-muted">v{i.version}</span>}
                    </td>
                    <td>
                      <span className="vcat-tag">{formatLabel(i.format)}</span>
                    </td>
                    <td className="vcat-hide-sm vcat-mono vcat-muted">{i.original_filename}</td>
                    <td className="vcat-table-cmd">
                      <div className="vcat-cmd">
                        <code title={i.install_command}>{i.install_command}</code>
                        <CopyButton className="vcat-copy" text={i.install_command} />
                      </div>
                    </td>
                    <td className="vcat-mono vcat-nowrap">{fmtBytes(i.size_bytes)}</td>
                    <td className="vcat-hide-sm vcat-muted vcat-nowrap" title={fmtDateTime(i.uploaded_at)}>
                      {fmtRelative(i.uploaded_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
          </>
        )}
      </section>
    </div>
  );
}
