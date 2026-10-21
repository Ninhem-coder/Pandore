import { useCallback, useEffect, useState } from "react";
import { api } from "../api.js";
import { CVE_SEVERITY_COLORS } from "../theme.js";
import { IconBookmark } from "../components/icons.jsx";

/**
 * Onglet "Suivi CVE" (sous-catégorie Defender > Vulnérabilité, 2026-08-10) : liste de CVE
 * "épinglées" par Nicolas, re-vérifiées automatiquement côté backend (defender/watchlist.py
 * + boucle de fond dans api_server.py, toutes les WATCHLIST_REFRESH_SECONDS, 1h par défaut)
 * plutôt qu'une recherche ponctuelle comme VulnerabilitiesTab.jsx. Même esprit visuel que
 * "Gains rapides" (SecureScoreTab.jsx : `.card-head h2` = chip ambre, ligne numérotée
 * `.reco-row`) mais avec le code CVE à la place du libellé de gain, et les devices
 * actuellement exposés à la place de recommandations (`.cve-watch-list`) — jusqu'au
 * 2026-08-28, cette liste défilait en interne au-delà de ~6 lignes ; retiré depuis (voir plus
 * bas) pour qu'un accordéon déplié n'ait jamais besoin de scroller.
 *
 * Remplace la maquette 100% frontend du 2026-08-10 (`MOCK_WATCHED_CVES` codée en dur,
 * perdue au rechargement) — la persistance et le rafraîchissement automatique sont
 * maintenant réels, côté serveur.
 *
 * Chaque device listé dans une carte est, par construction de search_vulnerabilities
 * (defender/tools.py), un device EXPOSÉ AU MOMENT de la dernière vérification — cette
 * fonction ne renvoie que les lignes qui matchent encore la CVE dans
 * DeviceTvmSoftwareVulnerabilities. Il n'existe donc pas de notion de device "corrigé" à
 * afficher séparément : un device qui n'apparaît plus dans la liste après un rafraîchissement
 * a simplement disparu du résultat (corrigé, ou device réinstallé/désonboardé) plutôt que de
 * passer par un état "fixed" explicite.
 *
 * Chaque ligne device est cliquable (2026-08-10, demande de Nicolas) et révèle en accordéon
 * les évidences logicielles du device pour cette CVE (chemins disque/registre, mêmes champs
 * que VulnDeviceTable dans VulnerabilitiesTab.jsx) — même mécanique grid-template-rows
 * 0fr→1fr que l'accordéon par politique de ComplianceOsGrid.jsx (`.compliance-policy-*`),
 * mais sous des noms de classe dédiés (`.cve-watch-details`/`.cve-watch-body`) pour ne pas
 * hériter des séparateurs pointillés propres au contexte "liste de politiques" — ici les
 * lignes sont déjà espacées par `.cve-watch-list`. Plusieurs devices peuvent être ouverts en
 * même temps (pas un accordéon exclusif comme ComplianceOsGrid) : comparer les évidences de
 * deux devices l'un sous l'autre est un cas d'usage plausible, contrairement aux politiques
 * de conformité qui n'ont pas vocation à être comparées entre elles.
 *
 * Redesign de l'évidence dépliée (2026-08-28, retour de Nicolas : "plus lisible et avec plus
 * de couleur" + "je n'aie pas besoin de scroller et que j'aie toutes les informations" +
 * "agrandi le tableau [...] tu peux prendre plus de place sur la longueur de la page") — trois
 * changements : (1) `.cve-watch-list` ne défile plus en interne (voir styles.css, retire le
 * `max-height`/`overflow-y` du 2026-08-10, contredit par cette demande plus récente et plus
 * précise) ; (2) disque/registre passent d'un empilement vertical à deux colonnes côte à côte
 * (`.cve-watch-evidence`, grid 2 colonnes) ; (3) chaque chemin devient une puce colorée
 * (`.cve-watch-path-line`, fond distinct + liseré ambre pour disque / `--star` bleu pour
 * registre) plutôt qu'une ligne de texte grisée — classes dédiées à cet accordéon
 * (`.cve-watch-path-*`/`.cve-watch-evidence-*`), la page reste indépendante de
 * VulnerabilitiesTab.jsx::PathList (`.vuln-path-*`, inchangée). Page passée en
 * `.dossier--wide` (Dashboard.jsx) pour donner à ces deux colonnes la place de respirer.
 */

function formatDateTime(iso) {
  if (!iso) return "jamais";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function SeverityBadge({ severity }) {
  const color = CVE_SEVERITY_COLORS[severity] || CVE_SEVERITY_COLORS.Unknown;
  return (
    <span className="cve-badge" style={{ borderColor: `${color}66`, color }}>
      {severity || "Inconnu"}
    </span>
  );
}

/** Un chemin (disque ou registre) par ligne, sans troncature — classes DÉDIÉES à cet
 * accordéon (`cve-watch-path-*`, redesign 2026-08-28 : "plus lisible et avec plus de
 * couleur") plutôt que les `.vuln-path-*` partagées avec VulnerabilitiesTab.jsx::PathList
 * (qui reste, elle, inchangée — cette page ne touche jamais aux classes d'une autre, voir
 * l'en-tête du fichier). `tone` ("disk"/"registry") colore le liseré gauche de chaque puce. */
function PathList({ paths, tone }) {
  if (!paths || paths.length === 0) return <span className="cve-small">Aucun chemin retrouvé</span>;
  return (
    <div className="cve-watch-path-list">
      {paths.map((p, i) => (
        <div key={i} className={`cve-watch-path-line cve-watch-path-line-${tone}`}>
          {p}
        </div>
      ))}
    </div>
  );
}

/** Une ligne device, cliquable pour révéler ses évidences (chemins disque/registre) en
 * accordéon — voir le commentaire d'en-tête du fichier pour le choix de classes CSS dédiées
 * plutôt que de réutiliser telles quelles .compliance-policy-*. */
function CveWatchDeviceRow({ device, index, open, onToggle }) {
  const evidenceCount = (device.disk_paths?.length || 0) + (device.registry_paths?.length || 0);
  return (
    <div className={`cve-watch-details${open ? " open" : ""}`}>
      <button
        type="button"
        className="cve-watch-row"
        onClick={() => onToggle(device.hostname)}
        aria-expanded={open}
      >
        <svg className="caret" viewBox="0 0 16 16" fill="none">
          <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span className="reco-rank">{String(index + 1).padStart(2, "0")}</span>
        <div className="reco-main">
          <span className="reco-name">{device.hostname}</span>
          <span className="reco-meta">
            {device.rbac_group || "Groupe RBAC inconnu"}
            {evidenceCount > 0 ? ` · ${evidenceCount} chemin${evidenceCount > 1 ? "s" : ""} d'évidence` : ""}
          </span>
        </div>
        <span className="badge high">Exposé</span>
      </button>
      <div className="cve-watch-body">
        <div className="cve-watch-body-inner">
          <div className="cve-watch-evidence">
            <div className="cve-watch-evidence-col">
              <span className="cve-watch-evidence-label cve-watch-evidence-label-disk">
                <span className="cve-watch-evidence-dot" />
                Chemin(s) disque
              </span>
              <PathList paths={device.disk_paths} tone="disk" />
            </div>
            <div className="cve-watch-evidence-col">
              <span className="cve-watch-evidence-label cve-watch-evidence-label-registry">
                <span className="cve-watch-evidence-dot" />
                Chemin(s) registre
              </span>
              <PathList paths={device.registry_paths} tone="registry" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Liste scrollable des devices actuellement exposés à une CVE suivie — même
 * conteneur/scrollbar que .risk-list/.new-list (Vue d'ensemble) et .compliance-os-grid,
 * pour rester cohérent avec le reste du dashboard plutôt qu'un 4e style de scrollbar.
 *
 * `openHosts` (un Set, pas un seul id) vit ICI plutôt que dans CveWatchCard ou CveWatchTab :
 * il est local à la liste d'UNE CVE, réinitialisé à chaque nouveau montage (changement de
 * résultat après un rafraîchissement recrée la liste de toute façon), et plusieurs devices
 * de la même CVE peuvent rester ouverts simultanément (voir en-tête du fichier). */
function CveWatchDeviceList({ devices }) {
  const [openHosts, setOpenHosts] = useState(() => new Set());

  if (!devices || devices.length === 0) {
    return <p className="empty">Aucun device exposé lors de la dernière vérification.</p>;
  }

  function toggle(hostname) {
    setOpenHosts((prev) => {
      const next = new Set(prev);
      if (next.has(hostname)) {
        next.delete(hostname);
      } else {
        next.add(hostname);
      }
      return next;
    });
  }

  return (
    <div className="cve-watch-list">
      {devices.map((d, i) => (
        <CveWatchDeviceRow key={d.hostname} device={d} index={i} open={openHosts.has(d.hostname)} onToggle={toggle} />
      ))}
    </div>
  );
}

function CveWatchCard({ entry, onRemove, onRefresh, refreshing }) {
  const result = entry.result;
  const affectedCount = result?.affected_count ?? 0;

  return (
    <div className="card cve-watch-card">
      <div className="card-head">
        <h2 className="cve-mono">{entry.cve_code}</h2>
        <span className="card-note">
          {affectedCount} device{affectedCount > 1 ? "s" : ""} exposé{affectedCount > 1 ? "s" : ""} · vérifié le{" "}
          {formatDateTime(entry.last_checked)}
        </span>
        <div className="cve-watch-actions">
          <button
            type="button"
            className="cve-watch-refresh"
            onClick={() => onRefresh(entry.cve_code)}
            disabled={refreshing}
          >
            {refreshing ? "Vérification…" : "Vérifier maintenant"}
          </button>
          <button
            type="button"
            className="cve-watch-remove"
            onClick={() => onRemove(entry.cve_code)}
            aria-label={`Ne plus suivre ${entry.cve_code}`}
            // Désactivé pendant un rafraîchissement en cours (revue de code du 2026-08-20) :
            // sans ça, un clic sur "Vérifier maintenant" suivi d'un clic rapide sur "Ne plus
            // suivre" avant la fin du refresh faisait courir les deux requêtes en parallèle —
            // si le refresh se terminait APRÈS la suppression, la CVE tout juste retirée
            // pouvait réapparaître au prochain `load()`.
            disabled={refreshing}
          >
            Ne plus suivre
          </button>
        </div>
      </div>

      {entry.last_error && (
        <p className="error-note cve-watch-error">Dernière vérification en échec : {entry.last_error}</p>
      )}

      {result && (
        <div className="vuln-meta-row">
          <div className="vuln-meta-item">
            <span className="vuln-meta-label">Sévérité</span>
            <SeverityBadge severity={result.severity} />
          </div>
          <div className="vuln-meta-item">
            <span className="vuln-meta-label">CVSS</span>
            <span className="cve-mono">{typeof result.cvss_score === "number" ? result.cvss_score.toFixed(1) : "—"}</span>
          </div>
          <div className="vuln-meta-item">
            <span className="vuln-meta-label">Exploit</span>
            <span>{result.exploitability_level || "—"}</span>
          </div>
          <div className="vuln-meta-item">
            <span className="vuln-meta-label">Correctif dispo.</span>
            <span>{result.security_update_available ? "Oui" : "Non connu"}</span>
          </div>
        </div>
      )}

      <CveWatchDeviceList devices={result?.devices} />
    </div>
  );
}

export default function CveWatchTab() {
  const [state, setState] = useState({ status: "loading", entries: [], error: null });
  const [input, setInput] = useState("");
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState(null);
  const [refreshingCve, setRefreshingCve] = useState(null);

  const load = useCallback(async () => {
    try {
      const entries = await api.watchedCves();
      setState({ status: "done", entries: Array.isArray(entries) ? entries : [], error: null });
    } catch (err) {
      setState({ status: "error", entries: [], error: err.message });
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function handleAdd(event) {
    event.preventDefault();
    const trimmed = input.trim();
    if (trimmed.length < 4) return;
    setAdding(true);
    setAddError(null);
    try {
      const result = await api.addWatchedCve(trimmed);
      if (result?.error) {
        setAddError(result.message);
      } else {
        setInput("");
        await load();
      }
    } catch (err) {
      setAddError(err.message);
    } finally {
      setAdding(false);
    }
  }

  async function handleRemove(cveCode) {
    try {
      await api.removeWatchedCve(cveCode);
      await load();
    } catch (err) {
      setState((s) => ({ ...s, error: err.message }));
    }
  }

  async function handleRefresh(cveCode) {
    setRefreshingCve(cveCode);
    try {
      await api.refreshWatchedCve(cveCode);
      await load();
    } catch (err) {
      setState((s) => ({ ...s, error: err.message }));
    } finally {
      setRefreshingCve(null);
    }
  }

  return (
    <>
      <div className="card">
        <div className="card-head">
          <h2>Ajouter une CVE à suivre</h2>
          <span className="card-note">re-vérifiée automatiquement, environ toutes les heures</span>
        </div>
        <form className="vuln-search-form" onSubmit={handleAdd}>
          <input
            type="text"
            className="vuln-search-input"
            placeholder="CVE-2024-3400…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            aria-label="Ajouter une CVE à suivre"
          />
          <button type="submit" className="vuln-search-button" disabled={adding}>
            {adding ? "Ajout…" : "Ajouter au suivi"}
          </button>
        </form>
        {addError && <p className="error-note">{addError}</p>}
        <p className="card-note vuln-search-hint">
          La première vérification se lance immédiatement après l'ajout ; les suivantes sont automatiques.
        </p>
      </div>

      {state.status === "loading" && (
        <div className="card">
          <p className="card-note">Chargement des CVE suivies…</p>
        </div>
      )}

      {state.status === "error" && (
        <div className="card">
          <p className="error-note">{state.error}</p>
        </div>
      )}

      {state.status === "done" && state.entries.length === 0 && (
        <div className="card">
          <div className="vuln-idle-note">
            <IconBookmark />
            <p>Aucune CVE suivie pour l'instant — ajoute-en une ci-dessus pour la garder à l'œil.</p>
          </div>
        </div>
      )}

      {state.status === "done" &&
        state.entries.map((entry) => (
          <CveWatchCard
            key={entry.cve_code}
            entry={entry}
            onRemove={handleRemove}
            onRefresh={handleRefresh}
            refreshing={refreshingCve === entry.cve_code}
          />
        ))}
    </>
  );
}
