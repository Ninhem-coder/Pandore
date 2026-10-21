import { useMemo, useRef, useState, useEffect, Fragment } from "react";
import { createPortal } from "react-dom";
import { useDefenderAlerts, useAlertDetails } from "../hooks/useDashboardData.js";
import { IconTarget, IconShield, IconMessage, IconLayers } from "../components/icons.jsx";
import {
  ALERT_SEVERITY_COLORS,
  ALERT_SEVERITY_LABEL_FR,
  ALERT_STATUS_COLORS,
  ALERT_STATUS_LABEL_FR,
  ALERT_CLASSIFICATION_COLORS,
  ALERT_CLASSIFICATION_LABEL_FR,
  GENERIC_PALETTE,
} from "../theme.js";

/** Couleurs par type d'entité (`evidence[].entityType`) — palette CATÉGORIELLE (GENERIC_PALETTE,
 * déjà utilisée pour Onboarding/OS dans ce dashboard), pas la palette sémantique de sévérité :
 * un type "Ip"/"Url" n'est pas intrinsèquement "dangereux", juste une catégorie différente
 * (2026-08-28, retour de Nicolas : "plus de couleur" sur le panneau de détail d'une alerte). */
const EVIDENCE_TYPE_COLORS = {
  File: GENERIC_PALETTE[0],
  Process: GENERIC_PALETTE[1],
  User: GENERIC_PALETTE[3],
  Ip: GENERIC_PALETTE[5],
  Url: GENERIC_PALETTE[6],
  MailBox: GENERIC_PALETTE[4],
  MailMessage: GENERIC_PALETTE[4],
};
import { buildDonutEntries } from "../selectors.js";

/**
 * Onglet "Widgets (test)" (2026-08-17, V42) — refonte demandée par Nicolas : les quatre
 * anciens widgets MDVM (V33-V41, voir mémoire de projet pour l'historique) sont retirés en
 * totalité et remplacés par un dashboard "Alertes Defender" à part entière, construit à
 * partir de recherche documentaire (Microsoft Learn — voir le lien en bas de page) sur le
 * schéma réel de l'API MDE native `/api/alerts` (defender/client.py::MDE_API_BASE, PAS
 * Microsoft Graph Security — vocabulaire différent).
 *
 * Statuts possibles (`status`) confirmés côté doc officielle : Unknown / New / InProgress /
 * Resolved — c'est la répartition "New et autre" demandée par Nicolas. Sévérité et
 * classification sont montrées en complément pour donner un vrai panorama, pas seulement le
 * statut brut.
 *
 * V42bis (2026-08-17, demande Nicolas) : "filtrer en fonction des colonnes en cliquant sur le
 * titre de la colonne" — remplace l'ancienne bande d'onglets "alert-status-tabs" (qui ne
 * filtrait que par statut) par un filtre par colonne façon Excel : cliquer sur un titre de
 * colonne ouvre un menu à cocher avec les valeurs présentes dans cette colonne (comptées en
 * tenant compte des AUTRES filtres déjà actifs, comme un tableau croisé). Le menu est
 * rendu via un portail React (`createPortal` sur `document.body`) plutôt qu'en `position:
 * absolute` dans la cellule d'en-tête : l'en-tête est `position: sticky` dans un conteneur
 * `overflow: auto` (`.cve-table-wrap`) ET `.card` porte `animation: riseIn … both`, qui fixe
 * un `transform` calculé en fin d'animation — cela crée un containing block qui casserait un
 * `position: fixed` classique. Le portail sur `document.body` contourne les deux problèmes
 * (écrêtage par overflow + containing block) ; sa position est calculée au clic via
 * `getBoundingClientRect()` du bouton d'en-tête.
 *
 * Un seul appel réseau au chargement (`useDefenderAlerts`, jusqu'à 200 alertes,
 * /api/defender/alerts déjà existant côté backend) — tout le reste (compteurs, camemberts,
 * filtres par colonne) est calculé côté client via useMemo, sans re-fetch au changement de
 * filtre.
 *
 * V43 (2026-08-17, demande Nicolas) : "je ne peux pas voir les détails, [...] défiler
 * l'alerte et regarder ce qu'il se passe" — chaque ligne de la liste est maintenant
 * cliquable et déplie un panneau de détail scrollable (description, détermination, état
 * d'investigation, techniques MITRE, commentaires d'analyste, preuves/evidence), construit
 * depuis GET /api/alerts/{id} (nouvel endpoint backend, `defender/tools.py::get_alert`, port
 * de "Get alert information by ID" — learn.microsoft.com/defender-endpoint/api/
 * get-alert-info-by-id) chargé à la demande via `useAlertDetails` (un cache par alertId, un
 * seul appel par alerte dépliée, jamais les 200 d'un coup — cet endpoint est limité à 100
 * appels/minute côté MDE). Ce détail exige spécifiquement le rôle Alert.ReadWrite.All (la
 * liste, elle, accepte Alert.Read.All OU Alert.ReadWrite.All).
 *
 * V45 (2026-08-17, demande Nicolas, une fois la page validée et déplacée dans "Analyse" —
 * voir Sidebar.jsx/Dashboard.jsx, V44) : "tu peux enlever cette partie" (la carte d'intro
 * explicative construite pendant le développement — historique de recherche, rappel des
 * statuts/sévérités/classifications, mode d'emploi des filtres) — retirée pour aligner cette
 * page permanente sur les autres (DefenderTab.jsx, IntuneTab.jsx, ...), qui vont directement
 * au bandeau KPI sans carte de présentation. Le titre affiché au-dessus de la page (masthead
 * de Dashboard.jsx, PAS un titre de ce fichier) est passé de "Widgets de test" à "Alertes
 * Defender" dans le même mouvement.
 *
 * V46 (2026-08-28, demande de Nicolas — "la page est trop synthétique", maquette HTML validée
 * avant implémentation) : trois enrichissements, tous à partir de champs DÉJÀ renvoyés par
 * /api/defender/alerts (aucun nouvel appel réseau, `defender/alerts.py::list_alerts` fait déjà
 * un passthrough complet de l'objet MDE — confirmé en direct contre le tenant de production le
 * 2026-08-28 : threatName/detectionSource/assignedTo/incidentId/rbacGroupName/resolvedTime
 * sont tous déjà présents sur chaque alerte de la liste, pas seulement sur le détail par id) :
 * 1. Sévérité en pastille+liseré coloré (au lieu d'un badge plein) en tête de ligne, menace
 *    nommée (`threatName`/repli `threatFamilyName`) en sous-titre du titre, deux nouvelles
 *    colonnes filtrables "Assigné à"/"Détection" (juste 2 entrées de plus dans
 *    FILTERABLE_COLUMNS, aucun nouveau mécanisme de filtre).
 * 2. Deux bascules "Masquer les informationnelles"/"Masquer les résolues" (accent `--star`,
 *    pas `--amber` : une dimension "affichage" distincte des filtres de contenu par colonne,
 *    même idiom que le filtre "Étoile" de DeployedAppsTab.jsx), ACTIVES PAR DÉFAUT — sauf
 *    garde-fou : si les deux combinées videraient la liste ENTIÈRE (confirmé en conditions
 *    réelles ce jour-là : les 50 seules alertes non résolues du tenant étaient TOUTES
 *    informationnelles, 0 alerte serait restée visible), elles sont neutralisées pour cet
 *    affichage avec un bandeau explicite plutôt qu'une page vide sans explication.
 * 3. Panneau de détail enrichi (classification, assigné à, ID d'incident, groupe RBAC, date de
 *    résolution) + deux classements dans le rail ("Menaces nommées"/"Sources de détection",
 *    `threatName`/`detectionSource` agrégés sur les 200 alertes) — deux champs jamais affichés
 *    nulle part dans le dashboard avant cette refonte.
 */

function normalizeStatus(a) {
  return a?.status && ALERT_STATUS_LABEL_FR[a.status] ? a.status : "Unknown";
}

function normalizeSeverity(a) {
  return a?.severity && ALERT_SEVERITY_COLORS[a.severity] ? a.severity : "UnSpecified";
}

/** Colonnes filtrables — chacune avec sa fonction d'extraction de valeur et son libellé
 * d'affichage. "Créée le" est volontairement exclue : un horodatage est quasi unique par
 * alerte, une liste à cocher n'y aurait aucun sens (voir docstring plus haut). Sévérité
 * remontée en tête (V46, maquette validée) — c'est la première chose à scanner d'un coup
 * d'œil ; "Assigné à"/"Détection" ajoutées le même jour, mêmes champs déjà présents sur
 * l'objet alerte, aucun nouveau mécanisme de filtre nécessaire. */
const FILTERABLE_COLUMNS = {
  severity: { label: "Sévérité", getValue: normalizeSeverity, formatValue: (v) => ALERT_SEVERITY_LABEL_FR[v] || v },
  title: { label: "Alerte", getValue: (a) => a.title || "—", formatValue: (v) => v },
  status: { label: "Statut", getValue: normalizeStatus, formatValue: (v) => ALERT_STATUS_LABEL_FR[v] || v },
  category: { label: "Catégorie", getValue: (a) => a.category || "—", formatValue: (v) => v },
  device: { label: "Device", getValue: (a) => a.computerDnsName || "—", formatValue: (v) => v },
  assignedTo: { label: "Assigné à", getValue: (a) => a.assignedTo || "Non assigné", formatValue: (v) => v },
  detectionSource: { label: "Détection", getValue: (a) => a.detectionSource || "—", formatValue: (v) => v },
};

/** `threatName` (spécifique, ex. "PUAMiner:Win32/CoinMiner") avec repli sur `threatFamilyName`
 * (plus générique, ex. "CoinMiner") — les deux ne sont pas toujours renseignés en même temps
 * sur le tenant de production (vérifié en direct le 2026-08-28), et il vaut mieux afficher le
 * moins spécifique des deux plutôt que rien du tout. `null` si aucun des deux (majorité des
 * alertes hors malware, ex. phishing/activité suspecte). */
function threatLabel(a) {
  return a?.threatName || a?.threatFamilyName || null;
}

/** Hash simple pour une couleur d'avatar déterministe (2026-08-28, redesign du panneau de
 * détail — avatar par initiale pour "Commentaires", même mécanique que `LibraryIcon`/
 * `EntryIcon` ailleurs dans ce dashboard, dupliquée ici par convention (petit utilitaire pur,
 * pas de risque de dérive à partager). */
function hashString(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0;
  return Math.abs(h);
}

/** Une alerte passe le filtre si, pour CHAQUE colonne filtrée (hors `skipKey`, la colonne
 * dont on est en train de recalculer les propres options), sa valeur est dans l'ensemble
 * autorisé. `null` = pas de filtre actif sur cette colonne. */
function passesFilters(alert, columnFilters, skipKey) {
  for (const key of Object.keys(FILTERABLE_COLUMNS)) {
    if (key === skipKey) continue;
    const allowed = columnFilters[key];
    if (!allowed) continue;
    if (!allowed.has(FILTERABLE_COLUMNS[key].getValue(alert))) return false;
  }
  return true;
}

/** Pastille + liseré coloré (V46, maquette validée) — remplace l'ancien badge plein
 * `AlertSeverityBadge` (retiré, plus aucun appelant) : la sévérité est la première chose à
 * scanner d'un coup d'œil en tête de ligne, un simple badge parmi 6 colonnes s'y prêtait
 * moins bien qu'un liseré de couleur dédié. */
function AlertSeverityCell({ severity }) {
  const key = ALERT_SEVERITY_COLORS[severity] ? severity : "UnSpecified";
  const color = ALERT_SEVERITY_COLORS[key];
  return (
    <span className="alert-sev-cell">
      <span className="alert-sev-stripe" style={{ background: color }} />
      <span className="alert-sev-label" style={{ color }}>
        {ALERT_SEVERITY_LABEL_FR[key]}
      </span>
    </span>
  );
}

function AlertStatusBadge({ status }) {
  const key = ALERT_STATUS_LABEL_FR[status] ? status : "Unknown";
  const color = ALERT_STATUS_COLORS[key];
  return (
    <span className="cve-badge" style={{ borderColor: `${color}66`, color }}>
      {ALERT_STATUS_LABEL_FR[key]}
    </span>
  );
}

function formatDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** mitreTechniques est documenté tantôt comme une chaîne, tantôt comme un tableau selon les
 * versions de la doc MDE — normalisé ici pour ne pas dépendre de la forme exacte renvoyée. */
function toArray(v) {
  if (Array.isArray(v)) return v;
  if (v == null || v === "") return [];
  return [v];
}

/** Résumé lisible d'une entrée `evidence`, selon son `entityType` — les champs pertinents
 * changent de nature selon le type d'entité (fichier/process/utilisateur/IP/URL), voir
 * defender/tools.py::get_alert pour la source de ces champs (port MDE natif). */
function describeEvidence(e) {
  switch (e.entityType) {
    case "File":
      return { primary: e.fileName || "—", secondary: e.filePath || e.sha256 || e.sha1 || "" };
    case "Process":
      return {
        primary: e.fileName || e.processCommandLine || "—",
        secondary: e.processCommandLine && e.fileName ? e.processCommandLine : `PID ${e.processId ?? "—"}${e.parentProcessId ? ` · parent ${e.parentProcessId}` : ""}`,
      };
    case "User":
      return {
        primary: e.accountName ? `${e.accountName}${e.domainName ? `@${e.domainName}` : ""}` : "—",
        secondary: e.userPrincipalName || "",
      };
    case "Ip":
      return { primary: e.ipAddress || "—", secondary: "" };
    case "Url":
      return { primary: e.url || "—", secondary: "" };
    case "MailBox":
    case "MailMessage":
      return { primary: e.emailSubject || e.accountName || "—", secondary: e.recipientEmailAddress || "" };
    default:
      return { primary: e.fileName || e.ipAddress || e.url || e.accountName || e.entityType || "—", secondary: "" };
  }
}

/** Panneau de détail déplié sous une ligne de la liste (V43) — jusqu'au 2026-08-28, un seul
 * conteneur scrollable (`.alert-detail-scroll`, `max-height: 420px`). Redesign (retour de
 * Nicolas — "je n'ai pas besoin de scrollé et que j'ai toutes les informations", "agrandi le
 * tableau si besoin tu peux prendre plus de place sur la longueur de la page") : `.alert-
 * detail-panel` ne défile plus (grandit avec la page) et répartit son contenu sur DEUX
 * colonnes (`.alert-detail-grid`) plutôt qu'un empilement vertical unique — exploite la
 * largeur de "Alertes Defender" (déjà en `.dossier--wide` depuis sa création). Colonne
 * gauche : description + fiche de métadonnées (lecture rapide). Colonne droite : MITRE +
 * commentaires + preuves (approfondissement). Liseré gauche coloré par SÉVÉRITÉ de l'alerte
 * (`severity`, prop ajoutée) — relie visuellement le panneau déplié à la pastille de sa ligne
 * juste au-dessus. */
function AlertDetailPanel({ detail, severity }) {
  if (!detail || detail.loading) {
    return <p className="card-note">Chargement du détail…</p>;
  }
  if (detail.error) {
    return (
      <div className="alert-detail-error">
        <p className="error-note">{detail.error}</p>
        <p className="card-note">
          Le détail d'une alerte (GET /api/alerts/&#123;id&#125;) exige spécifiquement le rôle
          applicatif <strong>Alert.ReadWrite.All</strong> côté Defender — la liste, elle,
          accepte aussi Alert.Read.All seul. Si l'erreur mentionne "Missing application
          roles", voir la procédure de correction déjà documentée pour ce dashboard (accord
          admin du rôle, puis redémarrage d'api_server.py).
        </p>
      </div>
    );
  }

  const d = detail.data || {};
  const mitre = toArray(d.mitreTechniques);
  const comments = Array.isArray(d.comments) ? d.comments : [];
  const evidence = Array.isArray(d.evidence) ? d.evidence : [];
  const relatedUser = d.relatedUser && typeof d.relatedUser === "object" ? d.relatedUser : null;
  // Champs ajoutés en V46 (2026-08-28) — déjà présents sur l'objet renvoyé par
  // GET /api/alerts/{id} (defender/alerts.py::get_alert, même passthrough MDE que la liste),
  // jamais affichés avant cette refonte.
  const classificationKey = d.classification && ALERT_CLASSIFICATION_COLORS[d.classification] ? d.classification : "Non classifiée";
  const classificationColor = ALERT_CLASSIFICATION_COLORS[classificationKey];
  const severityKey = ALERT_SEVERITY_COLORS[severity] ? severity : "UnSpecified";
  const severityColor = ALERT_SEVERITY_COLORS[severityKey];

  return (
    <div className="alert-detail-panel" style={{ "--alert-detail-accent": severityColor }}>
      {d.description && <p className="alert-detail-description">{d.description}</p>}

      <div className="alert-detail-grid">
        <div className="alert-detail-col">
          <div className="alert-detail-card">
            <div className="alert-detail-section-head">
              <IconLayers />
              <span>Détails</span>
            </div>
            <div className="alert-detail-meta">
              <div className="alert-detail-meta-item">
                <span className="alert-detail-meta-label">Classification</span>
                <span>
                  <span className="cve-badge" style={{ borderColor: `${classificationColor}66`, color: classificationColor }}>
                    {ALERT_CLASSIFICATION_LABEL_FR[classificationKey]}
                  </span>
                </span>
              </div>
              <div className="alert-detail-meta-item">
                <span className="alert-detail-meta-label">Détermination</span>
                <span>{d.determination || "—"}</span>
              </div>
              <div className="alert-detail-meta-item">
                <span className="alert-detail-meta-label">État investigation</span>
                <span>{d.investigationState || "—"}</span>
              </div>
              <div className="alert-detail-meta-item">
                <span className="alert-detail-meta-label">Utilisateur lié</span>
                <span>{relatedUser ? `${relatedUser.userName || "—"}${relatedUser.domainName ? `@${relatedUser.domainName}` : ""}` : "—"}</span>
              </div>
              <div className="alert-detail-meta-item">
                <span className="alert-detail-meta-label">Assigné à</span>
                <span>{d.assignedTo || "Non assigné"}</span>
              </div>
              <div className="alert-detail-meta-item">
                <span className="alert-detail-meta-label">ID d'incident</span>
                <span className="cve-mono">{d.incidentId ?? "—"}</span>
              </div>
              <div className="alert-detail-meta-item">
                <span className="alert-detail-meta-label">Groupe RBAC</span>
                <span>{d.rbacGroupName || "—"}</span>
              </div>
              {d.resolvedTime && (
                <div className="alert-detail-meta-item">
                  <span className="alert-detail-meta-label">Résolue le</span>
                  <span className="cve-mono cve-small">{formatDateTime(d.resolvedTime)}</span>
                </div>
              )}
            </div>
          </div>

          {mitre.length > 0 && (
            <div className="alert-detail-card">
              <div className="alert-detail-section-head alert-detail-section-head-mitre">
                <IconTarget />
                <span>Techniques MITRE ATT&amp;CK</span>
              </div>
              <div className="alert-detail-mitre">
                {mitre.map((t) => (
                  <span className="cve-badge alert-detail-mitre-badge" key={t}>
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="alert-detail-col">
          <div className="alert-detail-card">
            <div className="alert-detail-section-head">
              <IconMessage />
              <span>Commentaires{comments.length > 0 ? ` (${comments.length})` : ""}</span>
            </div>
            {comments.length === 0 ? (
              <p className="empty">Aucun commentaire d'analyste.</p>
            ) : (
              <div className="alert-detail-comments">
                {comments.map((c, i) => {
                  const author = c.createdBy || "—";
                  const avatarColor = GENERIC_PALETTE[hashString(author) % GENERIC_PALETTE.length];
                  return (
                    <div className="alert-detail-comment" key={i}>
                      <span className="alert-detail-comment-avatar" style={{ background: `${avatarColor}26`, color: avatarColor }}>
                        {author.trim().charAt(0).toUpperCase() || "?"}
                      </span>
                      <div className="alert-detail-comment-body">
                        <div className="alert-detail-comment-head">
                          <span>{author}</span>
                          <span className="cve-mono cve-small">{formatDateTime(c.createdTime)}</span>
                        </div>
                        <p>{c.comment}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="alert-detail-card">
            <div className="alert-detail-section-head alert-detail-section-head-evidence">
              <IconShield />
              <span>Preuves{evidence.length > 0 ? ` (${evidence.length})` : ""}</span>
            </div>
            {evidence.length === 0 ? (
              <p className="empty">Aucune preuve associée à cette alerte.</p>
            ) : (
              <div className="alert-detail-evidence">
                {evidence.map((e, i) => {
                  const { primary, secondary } = describeEvidence(e);
                  const typeColor = EVIDENCE_TYPE_COLORS[e.entityType] || "#7C8896";
                  return (
                    <div className="alert-detail-evidence-card" key={i}>
                      <span className="cve-badge alert-detail-evidence-type" style={{ borderColor: `${typeColor}66`, color: typeColor }}>
                        {e.entityType || "—"}
                      </span>
                      <div className="alert-detail-evidence-body">
                        <span className="alert-detail-evidence-primary">{primary}</span>
                        {secondary && <span className="alert-detail-evidence-secondary">{secondary}</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/** Menu de filtre par colonne (façon Excel), rendu en portail sur `document.body`. */
function ColumnFilterMenu({ anchorRect, options, selected, formatValue, onToggleValue, onOnly, onClear, onClose }) {
  const [search, setSearch] = useState("");
  const menuRef = useRef(null);

  useEffect(() => {
    function handlePointerDown(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) onClose();
    }
    function handleKeyDown(e) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [onClose]);

  const visibleOptions = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return options;
    return options.filter((o) => formatValue(o.value).toLowerCase().includes(q));
  }, [options, search, formatValue]);

  const menuWidth = 240;
  const style = {
    top: Math.round(anchorRect.bottom + 6),
    left: Math.round(Math.min(anchorRect.left, window.innerWidth - menuWidth - 12)),
  };

  return createPortal(
    <div className="alert-col-filter-menu" style={style} ref={menuRef}>
      {options.length > 8 && (
        <input
          type="text"
          className="alert-col-filter-search"
          placeholder="Rechercher une valeur…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          autoFocus
        />
      )}
      <div className="alert-col-filter-actions">
        <button type="button" onClick={onClear} disabled={!selected}>
          Tout cocher
        </button>
      </div>
      <div className="alert-col-filter-list">
        {visibleOptions.length === 0 && <p className="alert-col-filter-empty">Aucune valeur</p>}
        {visibleOptions.map((o) => (
          <label className="alert-col-filter-item" key={o.value}>
            <input
              type="checkbox"
              checked={!selected || selected.has(o.value)}
              onChange={() => onToggleValue(o.value)}
            />
            <span className="alert-col-filter-item-label">{formatValue(o.value)}</span>
            <span className="alert-col-filter-item-count">{o.count}</span>
            <button type="button" className="alert-col-filter-only" onClick={() => onOnly(o.value)}>
              seul
            </button>
          </label>
        ))}
      </div>
    </div>,
    document.body
  );
}

/** En-tête de colonne cliquable — ouvre `ColumnFilterMenu` positionné sous le bouton. */
function FilterableTh({ columnKey, label, isActive, isOpen, onToggleOpen, triggerRef }) {
  return (
    <th>
      <button
        type="button"
        ref={triggerRef}
        className={`alert-th-filter-btn${isActive ? " active" : ""}${isOpen ? " open" : ""}`}
        onClick={() => onToggleOpen(columnKey)}
      >
        {label}
        <svg className="alert-th-filter-icon" viewBox="0 0 12 10" width="9" height="8" aria-hidden="true">
          <path d="M0.5 0.5H11.5L7.2 5V9L4.8 7.8V5Z" fill="currentColor" />
        </svg>
      </button>
    </th>
  );
}

/** Camembert `conic-gradient` + légende (V47, 2026-08-28 — retour explicite de Nicolas : "tu
 * peux mettre à l'identique de la maquette" pour les camemberts et le bandeau KPI) —
 * remplace `DonutSvg`/`DonutLegend` (composants SVG partagés par TOUT le dashboard) sur CETTE
 * page seulement : la maquette approuvée montrait un grand cercle par carte avec le total au
 * centre, pas trois petits donuts SVG côte à côte dans une seule carte. `entries` = sortie de
 * `selectors.js::buildDonutEntries` (`{key, value, fraction, color, label}`), réutilisée telle
 * quelle — seul le RENDU change, pas le calcul des parts. */
function ConicDonut({ entries, centerText }) {
  let acc = 0;
  const stops = entries.map((e) => {
    const start = acc;
    acc += e.fraction * 100;
    return `${e.color} ${start}% ${acc}%`;
  });
  const background = entries.length > 0 ? `conic-gradient(${stops.join(", ")})` : "var(--panel-raised)";
  return (
    <div className="alert-donut" style={{ background }}>
      <div className="alert-donut-center">{centerText}</div>
    </div>
  );
}

function ConicDonutLegend({ entries }) {
  return (
    <div className="alert-donut-legend">
      {entries.map((e) => (
        <div className="alert-donut-legend-row" key={e.key}>
          <span className="alert-donut-legend-dot" style={{ background: e.color }} />
          <span className="alert-donut-legend-lbl">{e.label}</span>
          <span className="alert-donut-legend-cnt">{e.value}</span>
        </div>
      ))}
    </div>
  );
}

/** Classement "barre + valeur" pour les nouveaux rails "Menaces nommées"/"Sources de
 * détection" (V46) — classes dédiées (`.alert-rank-*`), pas de réutilisation d'un composant
 * de classement d'un autre onglet (convention déjà en place sur ce dashboard). `counts` est
 * un objet `{ libellé: nombre }` déjà agrégé par l'appelant. */
function RankList({ counts, max, emptyLabel }) {
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, max);
  if (entries.length === 0) return <p className="empty">{emptyLabel}</p>;
  const peak = entries[0][1];
  return (
    <div className="alert-rank-list">
      {entries.map(([name, n]) => (
        <div className="alert-rank-row" key={name}>
          <span className="alert-rank-name" title={name}>
            {name}
          </span>
          <span className="alert-rank-bar-track">
            <span className="alert-rank-bar-fill" style={{ width: `${(n / peak) * 100}%` }} />
          </span>
          <span className="alert-rank-val">{n}</span>
        </div>
      ))}
    </div>
  );
}

export default function WidgetsTestTab() {
  const { loading, alerts, error } = useDefenderAlerts();
  const alertDetails = useAlertDetails();
  const [expandedId, setExpandedId] = useState(null);
  const [columnFilters, setColumnFilters] = useState({});
  // Bascules "Masquer…" (V46) — actives par défaut (retour de Nicolas sur la maquette :
  // "j'aime beaucoup"), voir `toggleHidesEverything` plus bas pour le garde-fou anti-page-vide.
  const [hideInformational, setHideInformational] = useState(true);
  const [hideResolved, setHideResolved] = useState(true);
  // Recherche libre (titre/menace/device) — V46bis (2026-08-28, retour de Nicolas : "ça se
  // ressemble pas" à la maquette validée) : présente dans la maquette, jamais portée dans la
  // page réelle jusqu'ici. Filtre côté client, en plus des filtres de colonne/bascules —
  // aucun nouvel appel réseau, les 200 alertes sont déjà chargées.
  const [searchQuery, setSearchQuery] = useState("");
  const [openColumn, setOpenColumn] = useState(null);
  const [anchorRect, setAnchorRect] = useState(null);
  const thRefs = useRef({});
  const tableWrapRef = useRef(null);

  function handleToggleExpand(alertId) {
    setExpandedId((prev) => {
      const next = prev === alertId ? null : alertId;
      if (next) alertDetails.ensureLoaded(next);
      return next;
    });
  }

  // Ferme le menu ouvert si la colonne n'existe plus visuellement (scroll horizontal/vertical
  // du conteneur .cve-table-wrap) — plus simple et plus robuste que de recalculer la position
  // en continu, et l'en-tête étant sticky il ne bouge de toute façon pas en scroll vertical À
  // L'INTÉRIEUR du tableau. Le menu (`position: fixed`, positionné une fois via
  // `getBoundingClientRect` — coordonnées VIEWPORT, pas relatives à .cve-table-wrap) reste en
  // revanche décroché de son bouton si c'est la FENÊTRE qui scrolle (`.main-content` n'a pas
  // de hauteur/overflow contraint) — bug relevé à la revue de code du 2026-08-20 : seul le
  // scroll du tableau était écouté, pas celui de `window`. On ferme aussi sur scroll/resize de
  // la fenêtre, par cohérence avec le comportement du scroll interne (fermer plutôt que
  // recalculer en continu).
  useEffect(() => {
    const wrap = tableWrapRef.current;
    if (!wrap || openColumn === null) return;
    function handleScroll() {
      setOpenColumn(null);
      setAnchorRect(null);
    }
    wrap.addEventListener("scroll", handleScroll);
    window.addEventListener("scroll", handleScroll, true);
    window.addEventListener("resize", handleScroll);
    return () => {
      wrap.removeEventListener("scroll", handleScroll);
      window.removeEventListener("scroll", handleScroll, true);
      window.removeEventListener("resize", handleScroll);
    };
  }, [openColumn]);

  function handleToggleOpen(columnKey) {
    if (openColumn === columnKey) {
      setOpenColumn(null);
      setAnchorRect(null);
      return;
    }
    const el = thRefs.current[columnKey];
    if (el) setAnchorRect(el.getBoundingClientRect());
    setOpenColumn(columnKey);
  }

  // `filters` par défaut = columnFilters (l'état du render courant), mais handleToggleValue
  // ci-dessous passe explicitement `prev` (l'état updater le plus frais) plutôt que de laisser
  // cette fonction fermer sur le `columnFilters` du render où handleToggleValue a été défini —
  // sans ce paramètre, deux clics rapprochés sur des filtres différents avant qu'un re-render
  // n'ait eu lieu pouvaient calculer `allValues` à partir d'un columnFilters périmé (revue de
  // code du 2026-08-17), et donc écraser l'un des deux changements de filtre.
  function optionsFor(columnKey, filters = columnFilters) {
    const { getValue } = FILTERABLE_COLUMNS[columnKey];
    const counts = new Map();
    for (const a of alerts) {
      if (!passesFilters(a, filters, columnKey)) continue;
      const v = getValue(a);
      counts.set(v, (counts.get(v) || 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([value, count]) => ({ value, count }))
      .sort((a, b) => b.count - a.count);
  }

  function handleToggleValue(columnKey, value) {
    setColumnFilters((prev) => {
      const options = optionsFor(columnKey, prev);
      const allValues = options.map((o) => o.value);
      const current = prev[columnKey] ? new Set(prev[columnKey]) : new Set(allValues);
      if (current.has(value)) current.delete(value);
      else current.add(value);
      const next = { ...prev };
      if (current.size === allValues.length) delete next[columnKey];
      else next[columnKey] = current;
      return next;
    });
  }

  function handleOnly(columnKey, value) {
    setColumnFilters((prev) => ({ ...prev, [columnKey]: new Set([value]) }));
  }

  function handleClear(columnKey) {
    setColumnFilters((prev) => {
      const next = { ...prev };
      delete next[columnKey];
      return next;
    });
  }

  function resetAllFilters() {
    setColumnFilters({});
  }

  const activeFilterCount = Object.keys(columnFilters).length;

  const byStatus = useMemo(() => {
    const counts = { New: 0, InProgress: 0, Resolved: 0, Unknown: 0 };
    for (const a of alerts) counts[normalizeStatus(a)] += 1;
    return counts;
  }, [alerts]);

  const bySeverity = useMemo(() => {
    const counts = {};
    for (const a of alerts) counts[normalizeSeverity(a)] = (counts[normalizeSeverity(a)] || 0) + 1;
    return counts;
  }, [alerts]);

  const byClassification = useMemo(() => {
    const counts = {};
    for (const a of alerts) {
      const key = a.classification && ALERT_CLASSIFICATION_COLORS[a.classification] ? a.classification : "Non classifiée";
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, [alerts]);

  const statusEntries = useMemo(
    () => buildDonutEntries(byStatus, { colors: ALERT_STATUS_COLORS, labels: ALERT_STATUS_LABEL_FR }),
    [byStatus]
  );
  const severityEntries = useMemo(
    () => buildDonutEntries(bySeverity, { colors: ALERT_SEVERITY_COLORS, labels: ALERT_SEVERITY_LABEL_FR }),
    [bySeverity]
  );
  const classificationEntries = useMemo(
    () => buildDonutEntries(byClassification, { colors: ALERT_CLASSIFICATION_COLORS, labels: ALERT_CLASSIFICATION_LABEL_FR }),
    [byClassification]
  );

  // "Menaces nommées"/"Sources de détection" (V46) — agrégées sur les 200 alertes brutes,
  // comme les 3 camemberts ci-dessus (pas sur `filteredAlerts`, qui bouge avec les filtres de
  // colonne/bascules — ces classements donnent un panorama stable du lot entier).
  const threatCounts = useMemo(() => {
    const counts = {};
    for (const a of alerts) {
      const label = threatLabel(a);
      if (!label) continue;
      counts[label] = (counts[label] || 0) + 1;
    }
    return counts;
  }, [alerts]);

  const detectionSourceCounts = useMemo(() => {
    const counts = {};
    for (const a of alerts) {
      const label = a.detectionSource || "Inconnue";
      counts[label] = (counts[label] || 0) + 1;
    }
    return counts;
  }, [alerts]);

  const columnFilteredAlerts = useMemo(
    () => alerts.filter((a) => passesFilters(a, columnFilters, null)),
    [alerts, columnFilters]
  );

  const toggleFilteredAlerts = useMemo(
    () =>
      columnFilteredAlerts.filter(
        (a) => !(hideInformational && normalizeSeverity(a) === "Informational") && !(hideResolved && normalizeStatus(a) === "Resolved")
      ),
    [columnFilteredAlerts, hideInformational, hideResolved]
  );

  // Garde-fou anti-page-vide (V46) — confirmé en conditions réelles le 2026-08-28 contre le
  // tenant de production : les 50 seules alertes non résolues du lot étaient TOUTES
  // informationnelles (0 alerte New/InProgress d'une autre sévérité ce jour-là). Les deux
  // bascules combinées auraient donc vidé la liste ENTIÈREMENT, en silence — neutralisées
  // pour CET affichage plutôt que ça (voir `.alert-toggle-fallback-note` sous le tableau),
  // cohérent avec la philosophie du reste de l'app ("jamais disparaître en silence").
  const toggleHidesEverything = toggleFilteredAlerts.length === 0 && columnFilteredAlerts.length > 0;
  const filteredAlerts = toggleHidesEverything ? columnFilteredAlerts : toggleFilteredAlerts;

  // Recherche libre, appliquée EN PLUS des filtres de colonne/bascules ci-dessus — jamais
  // prise en compte dans `toggleHidesEverything` (une recherche à 0 résultat n'a rien à voir
  // avec le garde-fou anti-page-vide des bascules, c'est un état normal "aucun résultat pour
  // cette recherche").
  const visibleAlerts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return filteredAlerts;
    return filteredAlerts.filter((a) => {
      const haystack = `${a.title || ""} ${threatLabel(a) || ""} ${a.computerDnsName || ""}`.toLowerCase();
      return haystack.includes(q);
    });
  }, [filteredAlerts, searchQuery]);

  // Options des pastilles Sévérité/Statut — calculées une fois par rendu plutôt qu'à chaque
  // itération de `.map()` ci-dessous (optionsFor recalcule sur les 200 alertes à chaque appel).
  const severityChipOptions = optionsFor("severity");
  const statusChipOptions = optionsFor("status");

  return (
    <>
      {error && (
        <div className="card">
          <p className="error-note">{error}</p>
          <p className="card-note">
            Si l'erreur mentionne "Missing application roles" / "Alert.Read.All" : c'est un
            problème de permission Entra ID déjà identifié sur l'app registration Defender
            (rôle applicatif Alert.Read.All manquant), pas un bug de ce dashboard — voir la
            mémoire de projet pour la procédure de correction (Entra ID → App registrations →
            app Defender → API permissions → ajouter Alert.Read.All → accord admin → redémarrer
            api_server.py).
          </p>
        </div>
      )}

      {!error && (
        <>
          {/* V47bis (2026-08-28, retour de Nicolas : "la barre avec les kpi en haut et sur le
              côté à droite", comme la maquette) — le bandeau KPI sort du rail (336px, trop
              étroit pour 4 colonnes lisibles) pour une bande pleine largeur AU-DESSUS des deux
              colonnes, exactement la position de la maquette. Le rail garde les camemberts +
              classements ("sur le côté à droite"), qui eux restaient déjà à droite. */}
          <div className="alert-kpi-strip">
            <div className="alert-kpi-card">
              <div className="alert-kpi-label">Total</div>
              <div className="alert-kpi-value">{loading ? "—" : alerts.length}</div>
              <div className="alert-kpi-sub">200 dernières, toutes sévérités</div>
            </div>
            <div className="alert-kpi-card tone-new">
              <div className="alert-kpi-label">Nouvelles</div>
              <div className="alert-kpi-value">{loading ? "—" : byStatus.New}</div>
              <div className="alert-kpi-sub">à trier</div>
            </div>
            <div className="alert-kpi-card tone-progress">
              <div className="alert-kpi-label">En cours</div>
              <div className="alert-kpi-value">{loading ? "—" : byStatus.InProgress}</div>
              <div className="alert-kpi-sub">en investigation</div>
            </div>
            <div className="alert-kpi-card tone-resolved">
              <div className="alert-kpi-label">Résolues</div>
              <div className="alert-kpi-value">{loading ? "—" : byStatus.Resolved}</div>
              <div className="alert-kpi-sub">clôturées</div>
            </div>
          </div>

          <div className="alerts-layout">
            <div className="alerts-main">
              <div className="card">
                <div className="card-head">
                  <h2>Liste des alertes</h2>
                  <span className="card-note">
                    {visibleAlerts.length} affichée{visibleAlerts.length > 1 ? "s" : ""} sur {alerts.length}
                    {activeFilterCount > 0 ? ` · ${activeFilterCount} filtre${activeFilterCount > 1 ? "s" : ""} actif${activeFilterCount > 1 ? "s" : ""}` : ""}
                  </span>
                </div>

                {/* Pastilles Sévérité/Statut (V46bis, 2026-08-28 — retour de Nicolas : "ça se
                    ressemble pas" à la maquette validée, qui montrait ces deux dimensions en
                    pastilles bien visibles plutôt que planquées derrière un clic sur l'en-tête
                    de colonne). Réutilisent le MÊME état/mécanisme que le filtre Excel
                    (`columnFilters`/`handleToggleValue`/`optionsFor`) — une pastille = une
                    valeur cochée/décochée, exactement comme une ligne de `ColumnFilterMenu` ;
                    Sévérité/Statut sortent donc de la liste des colonnes cliquables
                    (`FilterableTh`) plus bas, remplacées par ces pastilles comme SEULE façon de
                    les filtrer désormais. */}
                <div className="alert-chip-filters">
                  <div className="alert-chip-row">
                    <span className="alert-chip-row-label">Sévérité</span>
                    {["High", "Medium", "Low", "Informational"].map((v) => {
                      const count = severityChipOptions.find((o) => o.value === v)?.count || 0;
                      const selected = columnFilters.severity || null;
                      const active = count === 0 || !selected || selected.has(v);
                      // `disabled` sur une valeur à 0 alerte (2026-08-28, bug réel signalé par
                      // Nicolas : "quand j'appuie sur en cours ça me recoche les deux autres
                      // filtres") — CAUSE RACINE, pas juste l'affichage : `handleToggleValue`/
                      // `optionsFor` (mécanisme Excel existant, réutilisé tel quel par ces
                      // pastilles) supposent que toute valeur qu'on leur passe existe déjà
                      // parmi les alertes réelles — en construisant `allValues` uniquement à
                      // partir des valeurs PRÉSENTES. Cliquer une pastille à 0 alerte (ex. "En
                      // cours" tant qu'aucune alerte n'est InProgress) ajoutait une valeur
                      // FANTÔME à l'ensemble sélectionné ; son `.size` finissait par coïncider
                      // PAR HASARD avec `allValues.length`, ce qui déclenchait la clause "tout
                      // est coché → supprimer le filtre" de `handleToggleValue` et effaçait
                      // silencieusement tout filtre déjà posé sur cette colonne (d'où les deux
                      // AUTRES pastilles qui semblaient se "recocher"). Corrigé à la racine :
                      // une pastille à 0 alerte ne déclenche plus JAMAIS `handleToggleValue` —
                      // elle n'a de toute façon rien à filtrer.
                      const disabled = count === 0;
                      return (
                        <button
                          type="button"
                          key={v}
                          className={`alert-filter-chip${active ? " active" : ""}`}
                          onClick={disabled ? undefined : () => handleToggleValue("severity", v)}
                          disabled={disabled}
                        >
                          <span className="alert-filter-chip-dot" style={{ background: ALERT_SEVERITY_COLORS[v] }} />
                          {ALERT_SEVERITY_LABEL_FR[v]} <span className="alert-filter-chip-n">{count}</span>
                        </button>
                      );
                    })}
                  </div>
                  <div className="alert-chip-row">
                    <span className="alert-chip-row-label">Statut</span>
                    {["New", "InProgress", "Resolved"].map((v) => {
                      const count = statusChipOptions.find((o) => o.value === v)?.count || 0;
                      const selected = columnFilters.status || null;
                      const active = count === 0 || !selected || selected.has(v);
                      const disabled = count === 0;
                      return (
                        <button
                          type="button"
                          key={v}
                          className={`alert-filter-chip${active ? " active" : ""}`}
                          onClick={disabled ? undefined : () => handleToggleValue("status", v)}
                          disabled={disabled}
                        >
                          <span className="alert-filter-chip-dot" style={{ background: ALERT_STATUS_COLORS[v] }} />
                          {ALERT_STATUS_LABEL_FR[v]} <span className="alert-filter-chip-n">{count}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="alert-toggle-row">
                  <button
                    type="button"
                    className={`alert-toggle-chip${hideInformational ? " active" : ""}`}
                    onClick={() => setHideInformational((v) => !v)}
                    aria-pressed={hideInformational}
                  >
                    <span className="alert-toggle-sw" />
                    Masquer les informationnelles
                  </button>
                  <button
                    type="button"
                    className={`alert-toggle-chip${hideResolved ? " active" : ""}`}
                    onClick={() => setHideResolved((v) => !v)}
                    aria-pressed={hideResolved}
                  >
                    <span className="alert-toggle-sw" />
                    Masquer les résolues
                  </button>
                  <input
                    type="text"
                    className="filter-input alert-search-input"
                    placeholder="Filtrer par titre, menace ou device…"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    aria-label="Filtrer les alertes par titre, menace ou device"
                  />
                  {activeFilterCount > 0 && (
                    <button type="button" className="alert-reset-filters" onClick={resetAllFilters}>
                      Réinitialiser les filtres de colonne
                    </button>
                  )}
                </div>

                {toggleHidesEverything && (
                  <p className="alert-toggle-fallback-note">
                    Les bascules "Masquer…" ci-dessus cacheraient la totalité des{" "}
                    {columnFilteredAlerts.length} alerte{columnFilteredAlerts.length > 1 ? "s" : ""} affichée
                    {columnFilteredAlerts.length > 1 ? "s" : ""} en ce moment — désactivées pour cette vue plutôt
                    que de laisser la liste vide, décoche-les si besoin.
                  </p>
                )}

                {loading ? (
                  <p className="card-note">Chargement…</p>
                ) : visibleAlerts.length === 0 ? (
                  <p className="empty">
                    {searchQuery.trim() ? "Aucune alerte ne correspond à cette recherche." : "Aucune alerte ne correspond aux filtres actifs."}
                  </p>
                ) : (
                  <div className="cve-table-wrap alert-table-wrap" ref={tableWrapRef}>
                    <table className="cve-device-table">
                      {/* `table-layout: fixed` (styles.css, scopé à `.alert-table-wrap`) —
                          sans ça, la ligne de détail (`colSpan={8}`, `.alert-detail-grid` sur
                          deux colonnes bien plus large que 8 cellules compactes) pouvait
                          élargir TOUTE la table au-delà de son conteneur dès qu'une alerte
                          était dépliée, forçant un défilement horizontal en plus du vertical
                          (retour de Nicolas : "j'ai toujours besoin de scroll [...] dans les
                          deux sens"). Avec `fixed`, les largeurs de colonnes viennent
                          UNIQUEMENT de ce `<colgroup>`, jamais du contenu d'une cellule — la
                          ligne de détail est alors confinée à la largeur réelle de la table,
                          quel que soit son contenu. */}
                      <colgroup>
                        <col style={{ width: "9%" }} />
                        <col style={{ width: "24%" }} />
                        <col style={{ width: "9%" }} />
                        <col style={{ width: "12%" }} />
                        <col style={{ width: "12%" }} />
                        <col style={{ width: "14%" }} />
                        <col style={{ width: "12%" }} />
                        <col style={{ width: "8%" }} />
                      </colgroup>
                      <thead>
                        <tr>
                          {/* Sévérité/Statut filtrés via les pastilles ci-dessus désormais (pas
                              de dropdown Excel pour ces deux-là) — en-tête simple, pas de
                              FilterableTh. Catégorie/Device/Assigné à/Détection gardent le
                              mécanisme existant (beaucoup plus de valeurs distinctes, mieux
                              adapté à une liste à cocher cherchable qu'à des pastilles). */}
                          {Object.entries(FILTERABLE_COLUMNS).map(([key, col]) =>
                            key === "severity" || key === "status" ? (
                              <th key={key}>{col.label}</th>
                            ) : (
                              <FilterableTh
                                key={key}
                                columnKey={key}
                                label={col.label}
                                isActive={Boolean(columnFilters[key])}
                                isOpen={openColumn === key}
                                onToggleOpen={handleToggleOpen}
                                triggerRef={(el) => (thRefs.current[key] = el)}
                              />
                            )
                          )}
                          <th>Créée le</th>
                        </tr>
                      </thead>
                      <tbody>
                        {visibleAlerts.map((a) => {
                          const isOpen = expandedId === a.id;
                          return (
                            <Fragment key={a.id}>
                              <tr
                                className={`alert-row${isOpen ? " expanded" : ""}`}
                                onClick={() => handleToggleExpand(a.id)}
                                onKeyDown={(e) => {
                                  // Sans ce gestionnaire, cette ligne (dépliage du détail
                                  // d'alerte) n'était accessible qu'à la souris — incohérent
                                  // avec le reste de l'app, qui utilise de vrais <button> pour
                                  // ce même besoin (revue de code du 2026-08-18).
                                  if (e.key === "Enter" || e.key === " ") {
                                    e.preventDefault();
                                    handleToggleExpand(a.id);
                                  }
                                }}
                                tabIndex={0}
                                role="button"
                                aria-expanded={isOpen}
                              >
                                <td>
                                  <AlertSeverityCell severity={a.severity} />
                                </td>
                                <td className="cve-cell-name">
                                  <span className="alert-row-chevron" aria-hidden="true">
                                    {isOpen ? "▾" : "▸"}
                                  </span>
                                  {a.title || "—"}
                                  {threatLabel(a) && <span className="alert-threat-name">{threatLabel(a)}</span>}
                                </td>
                                <td>
                                  <AlertStatusBadge status={a.status} />
                                </td>
                                <td className="cve-small">{a.category || "—"}</td>
                                <td className="cve-small">{a.computerDnsName || "—"}</td>
                                <td className="cve-small">{a.assignedTo || "Non assigné"}</td>
                                <td className="cve-small">{a.detectionSource || "—"}</td>
                                <td className="cve-mono cve-small">{formatDateTime(a.alertCreationTime)}</td>
                              </tr>
                              {isOpen && (
                                <tr className="alert-detail-row">
                                  <td colSpan={8}>
                                    <AlertDetailPanel detail={alertDetails.cache[a.id]} severity={a.severity} />
                                  </td>
                                </tr>
                              )}
                            </Fragment>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>

            {/* Résumé (KPI + 3 camemberts) déplacé dans le rail (2026-08-20, mockup validé
                par Nicolas, même principe que Vue d'ensemble/Conformité Intune/Secure Score) :
                c'est une lecture "d'un coup d'œil" par nature, exactement ce qu'un rail doit
                porter, alors que la liste des alertes (6 colonnes filtrables + panneau de
                détail MITRE/preuves/commentaires au clic) est le contenu qui a le plus besoin
                de la largeur libérée. */}
            <aside className="alerts-rail">
              <p className="alerts-rail-title">Résumé</p>
              {/* V47 — un grand camembert `conic-gradient` par dimension, une carte chacun,
                  au lieu du trio de petits donuts SVG dans une seule carte "Répartition des
                  alertes" — voir ConicDonut/ConicDonutLegend plus haut pour le pourquoi. Les 3
                  dimensions (statut/sévérité/classification) sont toutes gardées : la maquette
                  n'en montrait que 2 (Sévérité/Statut, pas de classification), mais la demande
                  portait sur le STYLE visuel, pas sur la suppression de la classification. */}
              {loading ? (
                <div className="card">
                  <p className="card-note">Chargement…</p>
                </div>
              ) : alerts.length === 0 ? (
                <div className="card">
                  <p className="empty">Aucune alerte remontée.</p>
                </div>
              ) : (
                <>
                  <div className="card">
                    <div className="card-head">
                      <h2>Par sévérité</h2>
                    </div>
                    <div className="alert-donut-row">
                      <ConicDonut entries={severityEntries.entries} centerText={severityEntries.total} />
                      <ConicDonutLegend entries={severityEntries.entries} />
                    </div>
                  </div>
                  <div className="card">
                    <div className="card-head">
                      <h2>Par statut</h2>
                    </div>
                    <div className="alert-donut-row">
                      <ConicDonut entries={statusEntries.entries} centerText={statusEntries.total} />
                      <ConicDonutLegend entries={statusEntries.entries} />
                    </div>
                  </div>
                  <div className="card">
                    <div className="card-head">
                      <h2>Par classification</h2>
                      <span className="card-note">après qualification analyste</span>
                    </div>
                    <div className="alert-donut-row">
                      <ConicDonut entries={classificationEntries.entries} centerText={classificationEntries.total} />
                      <ConicDonutLegend entries={classificationEntries.entries} />
                    </div>
                  </div>
                </>
              )}

              {/* V46 (2026-08-28, maquette validée) — deux champs Defender jamais affichés
                  nulle part dans le dashboard avant cette refonte, agrégés côté client sans
                  appel réseau supplémentaire (voir threatCounts/detectionSourceCounts). */}
              <div className="card">
                <div className="card-head">
                  <h2>Menaces nommées</h2>
                  <span className="card-note">threatName</span>
                </div>
                {loading ? (
                  <p className="card-note">Chargement…</p>
                ) : (
                  <RankList counts={threatCounts} max={6} emptyLabel="Aucune menace nommée sur ce lot d'alertes." />
                )}
              </div>

              <div className="card">
                <div className="card-head">
                  <h2>Sources de détection</h2>
                  <span className="card-note">detectionSource</span>
                </div>
                {loading ? (
                  <p className="card-note">Chargement…</p>
                ) : (
                  <RankList counts={detectionSourceCounts} max={6} emptyLabel="Aucune source de détection renseignée." />
                )}
              </div>
            </aside>
          </div>

          {openColumn && anchorRect && (
            <ColumnFilterMenu
              anchorRect={anchorRect}
              options={optionsFor(openColumn)}
              selected={columnFilters[openColumn] || null}
              formatValue={FILTERABLE_COLUMNS[openColumn].formatValue}
              onToggleValue={(value) => handleToggleValue(openColumn, value)}
              onOnly={(value) => handleOnly(openColumn, value)}
              onClear={() => handleClear(openColumn)}
              onClose={() => {
                setOpenColumn(null);
                setAnchorRect(null);
              }}
            />
          )}
        </>
      )}
    </>
  );
}
