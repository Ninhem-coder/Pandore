import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import {
  useDeployedApps,
  useAppInstallStatus,
  useAppInstallSummary,
  useAppAssignments,
  useDiscoveredVersionDevices,
} from "../hooks/useDashboardData.js";
import SummaryCard from "../components/SummaryCard.jsx";
import { IconPackage, IconLayers, IconGauge, IconAlertTriangle, IconDownload, IconExpand } from "../components/icons.jsx";
import { GENERIC_PALETTE, COMPLIANCE_LABEL } from "../theme.js";
import { exportAppInstallStatusToExcel } from "../export.js";
import { currentLocale, localizedTable, tr } from "../i18n/core.js";

/**
 * Onglet "Application Intune" > "Application déployée" (2026-08-25, demande de Nicolas) —
 * applications DÉPLOYÉES via Intune (deviceAppManagement/mobileApps, voir
 * intune/apps.py::list_apps) : la source ici est l'affectation Intune elle-même (ce qui a été
 * PUSHÉ), pas ce qui a été détecté sur le disque des devices comme dans "Catalogue
 * d'application" (l'autre sous-catégorie) — un poste peut apparaître dans ce tableau (l'app
 * lui est assignée) sans que l'installation ait réellement abouti : voir la colonne "État
 * d'installation" du détail par device (get_app_install_status) pour distinguer les deux.
 *
 * `list_apps` est annotée `list[dict]` côté backend : une erreur y est donc encodée en
 * `[error]` (voir listPayloadError dans useDashboardData.js), pas un objet `{error:true}` nu.
 *
 * ── Redesign maître-détail (2026-08-25, même jour, suite au premier redesign en cartes) ──
 * L'accordéon en place ("cliquer une carte déplie son détail juste en dessous, repousse
 * toute la liste") posait deux problèmes remontés par Nicolas : la page reste plafonnée à
 * 1360px et centrée quel que soit l'écran ("qu'il utilise plus l'espace pas forcement full
 * centre"), et le rendu au clic était peu ergonomique — perdre sa position de scroll, un
 * tableau de devices comprimé dans une carte étroite, aucun moyen de filtrer une app à
 * beaucoup de devices. Remplacé par le même motif "colonne principale + rail latéral fixe"
 * déjà en place sur Vue d'ensemble/Conformité Intune (`.dossier--wide`, voir Dashboard.jsx) :
 * la liste reste dans une colonne dédiée (`.deployed-main`) et ne bouge plus au clic, le
 * détail par device s'affiche dans un panneau sticky à droite (`.deployed-rail` /
 * `AppDetailPanel`), avec sa propre recherche texte et ses filtres par état d'installation.
 *
 * ── Fusion avec les "discovered apps" (2026-09-02, demande de Nicolas) ──────────────────────
 * "j'aimerai bien qu'on ait les discover app + les app déployés je veux pas 600 doublons ...
 * je veux cependant voir toutes les versions" — la liste vient maintenant de
 * `get_apps_catalog` (voir intune/apps.py), qui fusionne les 173 apps déployées avec les
 * ~18894 lignes de discovered apps DÉDUPLIQUÉES en ~7479 noms distincts (toutes les versions
 * regroupées par nom plutôt qu'une ligne par version — c'était la source exacte des
 * "doublons"). Chaque entrée porte un `source` :
 * - `"deployed"` — app Intune sans correspondance détectée, comportement 100% inchangé.
 * - `"both"` — app Intune ET logiciel détecté correspondant (rapprochement approximatif par
 *   nom, voir le backend) : carte normale + badge "versions détectées" + section versions en
 *   plus dans le détail.
 * - `"discovered"` — logiciel détecté sur le parc SANS app Intune correspondante : pas d'id
 *   Intune réel, pas de statut d'installation, carte simplifiée + panneau détail dédié
 *   (`DiscoveredDetailPanel`) listant toutes les versions détectées.
 * Liste potentiellement large (~7600 entrées) : rendu paginé (`REVEAL_STEP`/"Afficher N de
 * plus", même motif que la table CVE de VulnerabilitiesTab.jsx) pour ne jamais poser des
 * milliers de cartes dans le DOM d'un coup.
 */

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(currentLocale(), { day: "2-digit", month: "2-digit", year: "numeric" });
}

function formatDateTime(iso) {
  if (!iso) return "jamais";
  const d = new Date(iso);
  // "0001-01-01T00:00:00Z" (.NET DateTime.MinValue, jamais renseigné côté Graph — même sentinel
  // que documenté ailleurs dans ce projet pour les lignes "placeholder" de compliance) parse en
  // une VRAIE date JS (pas NaN) — repéré en testant le clic "voir les devices" d'une version
  // détectée (2026-09-02) : affichait "01/01/1 00:09" au lieu de "jamais".
  if (Number.isNaN(d.getTime())) return iso;
  if (d.getFullYear() < 1970) return "jamais";
  return d.toLocaleString(currentLocale(), { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

/** Hash déterministe (djb2-like) d'une chaîne vers un entier positif — utilisé pour choisir
 * une couleur de repli stable pour une app sans icône Intune (voir AppIcon ci-dessous) : la
 * même app garde toujours la même couleur d'une session à l'autre, sans dépendance externe
 * ni état à stocker. */
function hashString(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (h * 31 + str.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

/** Icône d'application (2026-08-25, demande de Nicolas — "il y a moyen de mettre les logos
 * d'Intune ou pas à côté des applications ?"). Deux cas, voir le commentaire de `.app-icon`
 * dans styles.css :
 * - `app.largeIcon` présent (mobileApps.largeIcon, $select explicite côté backend — voir
 *   intune/apps.py::list_apps) : PNG en base64, rendu tel quel dans une <img>. La VRAIE icône
 *   fournie par Intune — pas un logo de marque redessiné à la main (aucun asset officiel
 *   disponible ici, et on évite de reproduire des logos protégés).
 * - Sinon (fréquent — beaucoup d'apps Win32/LOB n'ont pas d'icône dans Intune) : repli sur une
 *   pastille à l'initiale, teinte tirée de GENERIC_PALETTE (theme.js, même palette que les
 *   camemberts du dashboard) via un hash du nom d'app.
 */
function AppIcon({ app }) {
  const name = app.displayName || "?";
  const icon = app.largeIcon;
  // Le nom exact du champ base64 varie selon les versions de la doc Graph (`value` dans le
  // type `mimeContent`) ; `type`/`contentType` selon les mêmes variations — les deux sont
  // tolérés ici plutôt que de parier sur un seul nom.
  const base64 = icon?.value;
  const contentType = icon?.type || icon?.contentType || "image/png";

  if (base64) {
    return (
      <span className="app-icon has-icon">
        <img src={`data:${contentType};base64,${base64}`} alt="" />
      </span>
    );
  }

  const color = GENERIC_PALETTE[hashString(name) % GENERIC_PALETTE.length];
  return (
    <span className="app-icon fallback" style={{ "--icon-fg": color, "--icon-bg": `${color}26` }}>
      {name.trim().charAt(0).toUpperCase() || "?"}
    </span>
  );
}

/** Glyphe "Windows" abstrait pour le bouton "Ouvrir dans Intune" (2026-08-25, demande de
 * Nicolas — "avec comme logo le logo de Windows"). Volontairement une grille neutre à 4
 * carrés (même esprit que le glyphe stroké déjà utilisé pour "Vue d'ensemble" dans
 * Sidebar.jsx, mais en fill plein pour rester visuellement distinct) plutôt que le vrai logo
 * Microsoft (couleurs officielles, forme déposée) — même principe que AppIcon ci-dessus : on
 * évite de reproduire une marque protégée sans asset officiel disponible. */
function WindowsGlyph() {
  return (
    <svg className="win-logo" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <rect x="1.5" y="1.5" width="7.7" height="7.7" rx="0.6" />
      <rect x="10.8" y="1.5" width="7.7" height="7.7" rx="0.6" />
      <rect x="1.5" y="10.8" width="7.7" height="7.7" rx="0.6" />
      <rect x="10.8" y="10.8" width="7.7" height="7.7" rx="0.6" />
    </svg>
  );
}

/** URL de la fiche app dans l'Intune admin center (2026-08-25, demande de Nicolas — "un
 * bouton pour l'ouvrir dans Intune"). Motif `#view/Microsoft_Intune_Apps/SettingsMenu/~/0/
 * appId/{id}` — le plus courant trouvé pour ce cas d'usage, mais PAS vérifié en conditions
 * réelles depuis cette session (pas d'accès au tenant de production). À confirmer par
 * Nicolas en comparant avec l'URL affichée en ouvrant une app dans son Intune admin center ;
 * corriger ici si le motif diffère. */
function intuneAppUrl(appId) {
  return `https://intune.microsoft.com/#view/Microsoft_Intune_Apps/SettingsMenu/~/0/appId/${encodeURIComponent(appId)}`;
}

// Regroupement OS pour le filtre en pastilles (2026-08-25, demande de Nicolas — "filtrer par
// OS ... sans avoir à faire un tableau différent pour chaque OS") — même famille de clés que
// `platform` calculé côté backend (intune/apps.py::_platform_from_odata_type). "all" n'est
// pas une vraie plateforme, juste la pastille "Tous".
// `key` doubles as the translation suffix (dep.os.<key>).
const OS_FILTERS = [{ key: "all" }, { key: "windows" }, { key: "ios" }, { key: "android" }, { key: "macos" }, { key: "web" }];
const OS_BADGE_KEYS = ["windows", "ios", "android", "macos", "web"];

function osBadgeLabel(platform) {
  return tr(`dep.os.${OS_BADGE_KEYS.includes(platform) ? platform : "other"}`);
}

// Filtre "source" (2026-09-02, fusion discovered apps) — même mécanisme de pastilles que
// OS_FILTERS ci-dessus, dimension différente donc classes CSS dédiées (`.source-chip`/
// `.source-filter`, pas une réutilisation de `.os-chip`).
// `key` doubles as the translation suffix (dep.source.<key>).
const SOURCE_FILTERS = [{ key: "all" }, { key: "deployed" }, { key: "discovered" }];

// Rendu paginé (2026-09-02) — la liste fusionnée peut dépasser 7000 entrées (discovered apps
// dédupliquées), poser autant de cartes dans le DOM d'un coup ralentirait le navigateur pour
// rien. Même motif que REVEAL_STEP dans VulnerabilitiesTab.jsx.
const REVEAL_STEP = 150;

// Vocabulaire de `installState` renvoyé par get_app_install_status (2026-08-25 : bascule sur
// l'endpoint de reporting retrieveDeviceAppInstallationStatusReport, l'ancien
// managedDeviceMobileAppInstallStatuses étant déprécié côté Microsoft — voir CLAUDE.md).
// Toute valeur absente de cette table s'affiche telle quelle plutôt qu'une traduction
// inventée — utile tant que la correspondance exacte des codes numériques renvoyés par le
// nouvel endpoint n'est pas confirmée sur le tenant de production.
// `detectedOnly`: device merged from "Versions détectées sur le parc" (see `DeviceStatusExplorer`,
// `unifyVersions`, 2026-09-02) — detected on disk for the chosen version but absent from the
// Intune install report: neither "installed" nor "failed", an honest third state.
const INSTALL_STATE_LABEL = localizedTable("dep.state", [
  "installed",
  "failed",
  "notInstalled",
  "uninstallFailed",
  "pendingInstall",
  "unknown",
  "notApplicable",
  "detectedOnly",
]);

function installStateLabel(state) {
  if (!state) return tr("dep.state.unknown");
  return INSTALL_STATE_LABEL[state] || state;
}

/** Compte les devices par valeur d'un champ donné (état d'installation, département...) — calculé
 * côté client à partir de la même réponse (get_app_install_status), aucun appel réseau
 * supplémentaire. `fallback` regroupe les devices sans valeur (ex. utilisateur sans
 * `department` renseigné dans Entra ID) sous une clé dédiée plutôt que de les faire
 * disparaître silencieusement du décompte. */
function countByField(devices, field, fallback) {
  const map = {};
  for (const d of devices || []) {
    const key = d[field] || fallback;
    map[key] = (map[key] || 0) + 1;
  }
  return Object.entries(map).sort((a, b) => b[1] - a[1]);
}

/** Filtre en pastilles cliquables générique (2026-08-25, panneau détail maître-détail) —
 * remplace l'ancien récapitulatif statique (`InstallStateSummary`) : sur une app à beaucoup de
 * devices, pouvoir isoler directement les "Échec" ou un département précis d'un clic est plus
 * utile qu'un simple comptage à lire. Utilisée pour DEUX dimensions du panneau détail (état
 * d'installation ET département, voir AppDetailPanel) : même mécanisme, `field`/`fallback`/
 * `labelFor` paramétrés plutôt que deux composants quasi identiques.
 *
 * Les deux usages restaient visuellement indiscernables (même pastille ambre) tant qu'on ne
 * lisait pas le contenu — corrigé le 2026-08-25 (retour de Nicolas, "différencier les
 * filtres pour les départements et les filtres pour les états d'installation") : `groupLabel`
 * ajoute un intitulé mono au-dessus de la rangée (même motif que `.os-filter-label` sur le
 * filtre OS de la liste principale), et `variant` bascule la classe de pastille —
 * `.state-chip` (ambre, accent principal du dashboard) pour l'état d'installation,
 * `.star-chip` (bleu — même teinte que le statut "En cours" des alertes Defender,
 * ALERT_STATUS_COLORS.InProgress dans theme.js, réutilisée ici comme second accent du
 * système plutôt qu'une couleur inventée) pour le département. Une dimension "statut" et une
 * dimension "organisation" n'ont pas la même nature, la couleur doit le refléter. */
function FilterChipBar({ ariaLabel, groupLabel, variant, devices, field, fallback, active, onChange, labelFor }) {
  const counts = useMemo(() => countByField(devices, field, fallback), [devices, field, fallback]);
  if (counts.length === 0) return null;

  const chipClass = variant === "star" ? "star-chip" : "state-chip";

  return (
    <div className="filter-chip-group">
      {groupLabel && <span className="filter-chip-group-label">{groupLabel}</span>}
      <div className="state-filter" role="group" aria-label={ariaLabel}>
        <button type="button" className={`${chipClass}${active === "all" ? " active" : ""}`} onClick={() => onChange("all")}>
          {tr("dep.allChip")} <span className="chip-count">{devices.length}</span>
        </button>
        {counts.map(([value, count]) => (
          <button
            key={value}
            type="button"
            className={`${chipClass}${active === value ? " active" : ""}`}
            onClick={() => onChange(value)}
          >
            {labelFor ? labelFor(value) : value} <span className="chip-count">{count}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function AppInstallTable({ devices, emptyMessage }) {
  if (!devices || devices.length === 0) {
    return <p className="empty">{emptyMessage || tr("dep.noDevice")}</p>;
  }
  return (
    <div className="cve-table-wrap deployed-detail-table-wrap">
      <table className="cve-device-table">
        <thead>
          <tr>
            <th>{tr("dep.col.device")}</th>
            <th>{tr("dep.col.user")}</th>
            <th>{tr("dep.col.department")}</th>
            <th>{tr("dep.col.installedVersion")}</th>
            <th>{tr("dep.col.installState")}</th>
            <th>{tr("dep.col.os")}</th>
            <th>{tr("dep.col.lastSync")}</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d, i) => (
            <tr key={d.deviceId || i}>
              <td className="cve-cell-name">{d.deviceName || "—"}</td>
              <td className="cve-small">{d.userPrincipalName || "—"}</td>
              <td className="cve-small">{d.department || "—"}</td>
              <td className="cve-mono cve-small">{d.appVersion}</td>
              <td>{installStateLabel(d.installState)}</td>
              <td className="cve-small">{d.osDescription || "—"}</td>
              <td className="cve-mono cve-small">{formatDateTime(d.lastSyncDateTime)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Barre "installées/échecs/en attente" visible SANS clic, sous l'en-tête de chaque ligne de
 * la liste — demande de Nicolas ("plus d'espace") : cette info reste visible au survol de la
 * liste plutôt que cachée derrière une sélection. Alimentée par `summary.byApp[app.id]`
 * (useAppInstallSummary) — PAS un nouvel appel réseau : c'est le même agrégat par app déjà
 * calculé pour le bandeau KPI, voir intune/apps.py::get_apps_install_summary. Rien affiché si
 * cette app est absente de `byApp` (agrégat pas encore chargé, ou type d'app qui ne le
 * supporte pas) plutôt qu'une barre à zéro trompeuse. */
function InstallRateBar({ counts }) {
  if (!counts) return null;
  const installed = counts.installed || 0;
  const failed = counts.failed || 0;
  const pending = counts.pending || 0;
  const notInstalled = counts.notInstalled || 0;
  const total = installed + failed + pending + notInstalled;
  if (total === 0) return null;

  return (
    <div className="install-bar-wrap">
      <div className="install-bar">
        {installed > 0 && <span className="seg-installed" style={{ width: `${(installed / total) * 100}%` }} />}
        {failed > 0 && <span className="seg-failed" style={{ width: `${(failed / total) * 100}%` }} />}
        {pending > 0 && <span className="seg-pending" style={{ width: `${(pending / total) * 100}%` }} />}
      </div>
      <div className="install-legend">
        {installed > 0 && (
          <span className="install-legend-item">
            <span className="install-legend-dot installed" />
            {tr("dep.installed", { count: installed })}
          </span>
        )}
        {failed > 0 && (
          <span className="install-legend-item">
            <span className="install-legend-dot failed" />
            {tr("dep.failed", { count: failed })}
          </span>
        )}
        {pending > 0 && (
          <span className="install-legend-item">
            <span className="install-legend-dot pending" />
            {tr("dep.pending", { count: pending })}
          </span>
        )}
      </div>
    </div>
  );
}

/** Une ligne = une application déployée, cliquable pour la sélectionner (le détail par
 * device s'affiche à côté, dans le rail — voir AppDetailPanel/`.deployed-rail`), PAS pour la
 * déplier en place comme avant le redesign maître-détail. `.app-card.selected` porte l'accent
 * visuel de sélection (voir styles.css) à la place de l'ancien chevron animé.
 *
 * `.app-card-row` reste un `<div role="button">`, PAS un `<button>` : le bouton "Ouvrir dans
 * Intune" est un `<a>` interactif imbriqué dedans, et le HTML n'autorise pas de contenu
 * interactif à l'intérieur d'un `<button>`. Le clic sur ce lien appelle `stopPropagation()`
 * pour ne pas aussi déclencher la sélection de la ligne. */
function DeployedAppRow({ app, selected, onSelect, installCounts }) {
  function handleKeyDown(e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onSelect(app.id);
    }
  }

  const isDiscoveredOnly = app.source === "discovered";
  const deviceTotal = isDiscoveredOnly
    ? app.discovered?.totalDeviceCount ?? null
    : installCounts
    ? installCounts.installed + installCounts.failed + installCounts.pending + installCounts.notInstalled
    : null;

  return (
    <div className={`app-card${selected ? " selected" : ""}`}>
      <div
        className="app-card-row"
        role="button"
        tabIndex={0}
        aria-pressed={selected}
        onClick={() => onSelect(app.id)}
        onKeyDown={handleKeyDown}
      >
        <AppIcon app={app} />
        <div className="app-card-main">
          <div className="app-card-name-row">
            <span className="app-card-name">{app.displayName || tr("dep.unknownApp")}</span>
            <span className="os-badge">{osBadgeLabel(app.platform)}</span>
            {isDiscoveredOnly ? (
              <span className="discovered-badge discovered-only">{tr("dep.detectedOnly")}</span>
            ) : (
              <>
                {app.displayVersion && <span className="version-badge">v{app.displayVersion}</span>}
                {app.discovered && (
                  <span className="discovered-badge" title={tr("dep.versionsTitle")}>
                    {tr("dep.versionsDetected", { count: app.discovered.versionCount })}
                  </span>
                )}
                <a
                  className="intune-open-btn"
                  href={intuneAppUrl(app.id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={tr("dep.openIntuneTitle")}
                  onClick={(e) => e.stopPropagation()}
                >
                  <WindowsGlyph />
                  Intune
                </a>
              </>
            )}
          </div>
          <span className="app-card-meta">
            {isDiscoveredOnly
              ? tr("dep.detectedNoIntune")
              : tr("dep.publisherModified", { publisher: app.publisher || tr("dep.unknownPublisher"), date: formatDate(app.lastModifiedDateTime) })}
          </span>
        </div>
        <div className="app-card-devices">
          <span className="n">{deviceTotal === null ? "—" : deviceTotal}</span>
          {tr("dep.devicesWord")}
        </div>
      </div>

      {!isDiscoveredOnly && <InstallRateBar counts={installCounts} />}
    </div>
  );
}

/** Devices détectés pour UNE version précise, avec recherche + filtres (2026-09-02, demande de
 * Nicolas : d'abord "je ne vois pas QUI a l'application, seulement la version", puis "les
 * filtres comme pour app déployés") — même mécanique que le panneau "Application déployée"
 * (recherche texte + `FilterChipBar` état/département), déclinée sur les champs que
 * `get_discovered_app_devices` renvoie réellement : "état" = `complianceState` (pas
 * `installState`, ce ne sont pas des devices avec une assignation Intune) et "département" =
 * `department` (résolu côté backend comme pour `AppInstallTable`). État de filtre LOCAL,
 * remonté à zéro à chaque changement de version via `key={version}` posé par l'appelant. */
function DiscoveredVersionDeviceList({ devices }) {
  const [query, setQuery] = useState("");
  const [stateFilter, setStateFilter] = useState("all");
  const [starFilter, setStarFilter] = useState("all");

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return devices.filter((d) => {
      const matchesText =
        !needle ||
        (d.deviceName || "").toLowerCase().includes(needle) ||
        (d.userPrincipalName || "").toLowerCase().includes(needle) ||
        (d.userDisplayName || "").toLowerCase().includes(needle);
      const matchesState = stateFilter === "all" || (d.complianceState || "unknown") === stateFilter;
      const matchesStar = starFilter === "all" || (d.department || "unknown") === starFilter;
      return matchesText && matchesState && matchesStar;
    });
  }, [devices, query, stateFilter, starFilter]);

  if (!devices || devices.length === 0) {
    return <p className="empty">{tr("dep.noDeviceForVersion")}</p>;
  }

  return (
    <>
      <div className="deployed-detail-tools">
        <input
          type="text"
          className="filter-input"
          placeholder={tr("dep.filterDevices")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label={tr("dep.filterVersionDevicesAria")}
        />
        <FilterChipBar
          ariaLabel={tr("dep.filterComplianceAria")}
          groupLabel={tr("dep.stateLabel")}
          variant="state"
          devices={devices}
          field="complianceState"
          fallback="unknown"
          active={stateFilter}
          onChange={setStateFilter}
          labelFor={(value) => (value === "unknown" ? tr("dep.state.unknown") : COMPLIANCE_LABEL[value] || value)}
        />
        <FilterChipBar
          ariaLabel={tr("dep.filterDepartmentAria")}
          groupLabel={tr("dep.departmentLabel")}
          variant="star"
          devices={devices}
          field="department"
          fallback="unknown"
          active={starFilter}
          onChange={setStarFilter}
          labelFor={(value) => (value === "unknown" ? tr("department.none") : value)}
        />
      </div>
      <table className="cve-device-table">
        <thead>
          <tr>
            <th>{tr("dep.col.device")}</th>
            <th>{tr("dep.col.user")}</th>
            <th>{tr("dep.col.department")}</th>
            <th>{tr("dep.col.os")}</th>
            <th>{tr("dep.col.compliance")}</th>
            <th>{tr("dep.col.lastSync")}</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((d, i) => (
            <tr key={d.deviceId || i}>
              <td className="cve-cell-name">{d.deviceName || "—"}</td>
              <td className="cve-small">{d.userPrincipalName || d.userDisplayName || "—"}</td>
              <td className="cve-small">{d.department || "—"}</td>
              <td className="cve-small">
                {d.operatingSystem || "—"} {d.osVersion || ""}
              </td>
              <td className="cve-small">{COMPLIANCE_LABEL[d.complianceState] || d.complianceState || "—"}</td>
              <td className="cve-mono cve-small">{formatDateTime(d.lastSyncDateTime)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {filtered.length === 0 && <p className="empty">{tr("dep.noDeviceForFilter")}</p>}
    </>
  );
}

/** Table "toutes les versions détectées sur le parc" (2026-09-02, demande de Nicolas : "je
 * veux cependant voir toutes les versions") — réutilisée par `DiscoveredDetailPanel` (logiciel
 * détecté seul) ET par `AppDetailPanel` (app déployée avec correspondance détectée) : même
 * donnée (`app.discovered.versions`, déjà triée par nombre d'appareils décroissant côté
 * backend), deux points d'entrée.
 *
 * Chaque ligne "version" est cliquable quand elle porte des `ids` Graph bruts (`v.ids`,
 * `intune/apps.py::_group_discovered_apps`) — clic → dépli inline (PAS de popup, même
 * philosophie que `PolicyRow`/`AlertRow` de DeviceOverviewTab.jsx) chargeant les devices
 * réels de cette version via l'endpoint DÉJÀ existant `get_discovered_app_devices` (un appel
 * par id, fusionnés côté client dans `useDiscoveredVersionDevices` — une version peut porter
 * plusieurs ids depuis le 2e niveau de déduplication de `_group_discovered_apps`). */
function DiscoveredVersionsTable({ versions }) {
  const { state: devicesCache, ensureLoaded } = useDiscoveredVersionDevices();
  const [openVersion, setOpenVersion] = useState(null);

  if (!versions || versions.length === 0) return null;

  function toggleVersion(v) {
    const isOpen = openVersion === v.version;
    setOpenVersion(isOpen ? null : v.version);
    if (!isOpen && v.ids?.length) ensureLoaded(v.ids.join(","));
  }

  return (
    <div className="cve-table-wrap deployed-detail-table-wrap">
      <table className="cve-device-table">
        <thead>
          <tr>
            <th>{tr("dep.col.version")}</th>
            <th>{tr("dep.col.devices")}</th>
          </tr>
        </thead>
        <tbody>
          {versions.map((v, i) => {
            const clickable = Boolean(v.ids?.length);
            const isOpen = clickable && openVersion === v.version;
            const devState = clickable ? devicesCache[v.ids.join(",")] : null;
            return (
              <Fragment key={`${v.version}-${i}`}>
                <tr
                  className={clickable ? "discovered-version-row-clickable" : undefined}
                  onClick={clickable ? () => toggleVersion(v) : undefined}
                >
                  <td className="cve-mono cve-small">
                    {clickable && <span className="chev">{isOpen ? "▾" : "▸"}</span>}
                    {v.version}
                  </td>
                  <td className="cve-mono cve-small">{v.deviceCount}</td>
                </tr>
                {isOpen && (
                  <tr>
                    <td colSpan={2} className="discovered-version-detail-cell">
                      {devState?.loading && <p className="card-note">{tr("dep.loadingDevices")}</p>}
                      {devState?.error && <p className="error-note">{devState.error}</p>}
                      {!devState?.loading && !devState?.error && (
                        <DiscoveredVersionDeviceList key={v.version} devices={devState?.data?.devices || []} />
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Panneau détail d'un logiciel DÉTECTÉ sur le parc sans app Intune correspondante
 * (2026-09-02, `source: "discovered"`) — pas de statut d'installation à afficher (rien n'a été
 * poussé via Intune), juste la répartition par version. Remplace `AppDetailPanel` dans le rail
 * pour ce type d'entrée. */
function DiscoveredDetailPanel({ app, onClose }) {
  const versions = app.discovered?.versions || [];
  return (
    <div className="deployed-detail">
      <div className="deployed-detail-head">
        <AppIcon app={app} />
        <div className="deployed-detail-title">
          <div className="app-card-name-row">
            <span className="app-card-name">{app.displayName || tr("dep.unknownApp")}</span>
            <span className="os-badge">{osBadgeLabel(app.platform)}</span>
            <span className="discovered-badge discovered-only">{tr("dep.detectedOnly")}</span>
          </div>
          <span className="app-card-meta">
            {tr("dep.discoveredMeta", {
              devices: tr("dep.devicesCount", { count: app.discovered?.totalDeviceCount ?? 0 }),
              versions: tr("dep.distinctVersions", { count: versions.length }),
            })}
          </span>
        </div>
        <button type="button" className="deployed-detail-close" onClick={onClose} aria-label={tr("dep.closeDetail")}>
          <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          </svg>
        </button>
      </div>
      <p className="card-note deployed-discovered-note">
        {tr("dep.discoveredNote")}
      </p>
      <span className="filter-chip-group-label">{tr("dep.versionsDetectedLabel")}</span>
      <DiscoveredVersionsTable versions={versions} />
    </div>
  );
}

/** État + logique d'export Excel (2026-09-02, extrait de `AppDetailPanel` pour être réutilisé
 * TEL QUEL par `AppDetailModal` — même motif `useExportExcel` déjà établi dans
 * VulnerabilitiesTab.jsx, pas un composant bouton "tout-en-un" : le panneau et la popup
 * placent le bouton à des endroits différents de leur en-tête). */
function useExportExcel(app, devices) {
  const [state, setState] = useState({ status: "idle", error: null });

  // L'export porte sur TOUS les devices chargés (`devices`), pas les devices déjà filtrés à
  // l'écran — voir le commentaire de buildAppInstallExportData dans selectors.js : un export
  // doit rester complet indépendamment des filtres actifs au moment du clic.
  async function handleExport() {
    setState({ status: "exporting", error: null });
    try {
      await exportAppInstallStatusToExcel(app, devices);
      setState({ status: "idle", error: null });
    } catch (err) {
      // Génération/téléchargement entièrement local (write-excel-file/universal, voir
      // export.js), comme l'export CVE de VulnerabilitiesTab.jsx : un échec ici n'est jamais
      // un problème réseau, plutôt un environnement qui bloque les téléchargements déclenchés
      // par script — affiché tel quel plutôt que silencieusement ignoré.
      setState({ status: "idle", error: err?.message || tr("dep.exportFailed") });
    }
  }

  return { ...state, handleExport };
}

/** Corps "état d'installation par device" (2026-09-02, extrait de `AppDetailPanel`) — recherche
 * texte + filtre état + filtre département + tableau, réutilisé TEL QUEL par le panneau (rail) ET la
 * popup "agrandir" (`AppDetailModal`) : chacun en a sa PROPRE instance (état de filtre local
 * indépendant), pas un état partagé entre les deux vues. "Département" = `department` Entra ID de
 * l'utilisateur assigné au device (2026-08-25, demande de Nicolas), résolu côté backend
 * (`intune/apps.py::_department_by_upn`).
 *
 * `unifyVersions` (2026-09-02, demande de Nicolas sur la popup "agrandir" : "me permettre dans
 * le filtre de choisir la version que je veux voir plutôt que d'avoir deux tableaux") — quand
 * `true` (SEULEMENT `AppDetailModal`, jamais le rail — Nicolas n'a demandé le changement QUE
 * "quand je le mets en grand"), un filtre "Version" en pastilles remplace la section séparée
 * "Versions détectées sur le parc" (ex-`DiscoveredVersionsTable`, encore utilisée telle quelle
 * par le rail et par `DiscoveredDetailPanel`) : une seule table, dont le contenu bascule selon
 * la version choisie plutôt que deux tables toujours visibles l'une sous l'autre.
 *
 * "Toutes" reste peu coûteux (les devices suivis Intune sont déjà chargés) ; choisir UNE
 * version précise ne charge (`ensureVersionDevicesLoaded`) que LES DEVICES DÉTECTÉS DE CETTE
 * VERSION-LÀ, jamais toutes les versions d'un coup — une app à 51 versions distinctes (ex.
 * Google Chrome) ne doit jamais déclencher 51 appels au clic sur "Toutes". Les deux
 * populations (devices suivis par Intune pour cette app, devices où la version a simplement
 * été détectée sur le disque) sont fusionnées par nom de device — un device présent des DEUX
 * côtés ne compte qu'une fois (la ligne "suivie", plus riche : elle porte un vrai état
 * d'installation). Un device détecté SEUL (jamais assigné via Intune) apparaît avec l'état
 * `"detectedOnly"` plutôt qu'un état d'installation inventé. */
function DeviceStatusExplorer({ app, statusState, installCounts, unifyVersions = false }) {
  const [deviceFilter, setDeviceFilter] = useState("");
  const [stateFilter, setStateFilter] = useState("all");
  const [starFilter, setStarFilter] = useState("all");
  const [versionFilter, setVersionFilter] = useState("all");
  const { state: versionDevicesCache, ensureLoaded: ensureVersionDevicesLoaded } = useDiscoveredVersionDevices();

  const devices = statusState?.data?.devices || [];
  const discoveredVersions = app.discovered?.versions || [];

  const versionOptions = useMemo(() => {
    if (!unifyVersions) return [];
    const map = new Map();
    for (const [version, count] of countByField(devices, "appVersion", "Inconnue")) {
      map.set(version, { version, trackedCount: count, discoveredCount: 0, ids: null });
    }
    for (const v of discoveredVersions) {
      const existing = map.get(v.version);
      if (existing) {
        existing.discoveredCount = v.deviceCount;
        existing.ids = v.ids || null;
      } else {
        map.set(v.version, { version: v.version, trackedCount: 0, discoveredCount: v.deviceCount, ids: v.ids || null });
      }
    }
    return Array.from(map.values()).sort((a, b) => Math.max(b.trackedCount, b.discoveredCount) - Math.max(a.trackedCount, a.discoveredCount));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unifyVersions, devices, discoveredVersions]);

  const selectedVersionOption = versionFilter !== "all" ? versionOptions.find((o) => o.version === versionFilter) : null;
  const versionIdsKey = selectedVersionOption?.ids?.length ? selectedVersionOption.ids.join(",") : null;

  useEffect(() => {
    if (versionIdsKey) ensureVersionDevicesLoaded(versionIdsKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [versionIdsKey]);

  const versionDevicesState = versionIdsKey ? versionDevicesCache[versionIdsKey] : null;

  const scopedDevices = useMemo(() => {
    if (!unifyVersions || versionFilter === "all") return devices;
    const tracked = devices.filter((d) => (d.appVersion || "Inconnue") === versionFilter);
    const extraRaw = versionDevicesState?.data?.devices || [];
    if (extraRaw.length === 0) return tracked;
    const trackedNames = new Set(tracked.map((d) => (d.deviceName || "").toLowerCase()).filter(Boolean));
    const extra = extraRaw
      .filter((d) => !trackedNames.has((d.deviceName || "").toLowerCase()))
      .map((d) => ({
        deviceId: d.deviceId,
        deviceName: d.deviceName,
        userPrincipalName: d.userPrincipalName || d.userDisplayName,
        department: d.department,
        appVersion: versionFilter,
        installState: "detectedOnly",
        osDescription: [d.operatingSystem, d.osVersion].filter(Boolean).join(" ") || null,
        lastSyncDateTime: d.lastSyncDateTime,
      }));
    return [...tracked, ...extra];
  }, [unifyVersions, versionFilter, devices, versionDevicesState]);

  const filteredDevices = useMemo(() => {
    const needle = deviceFilter.trim().toLowerCase();
    return scopedDevices.filter((d) => {
      const matchesText =
        !needle ||
        (d.deviceName || "").toLowerCase().includes(needle) ||
        (d.userPrincipalName || "").toLowerCase().includes(needle);
      const matchesState = stateFilter === "all" || (d.installState || "unknown") === stateFilter;
      const matchesStar = starFilter === "all" || (d.department || "unknown") === starFilter;
      return matchesText && matchesState && matchesStar;
    });
  }, [scopedDevices, deviceFilter, stateFilter, starFilter]);

  return (
    <>
      <InstallRateBar counts={installCounts} />

      {statusState?.loading && <p className="card-note">{tr("dep.loadingInstallState")}</p>}
      {statusState?.error && <p className="error-note">{statusState.error}</p>}

      {!statusState?.loading && !statusState?.error && (
        <>
          {(devices.length > 0 || versionOptions.length > 0) && (
            <div className="deployed-detail-tools">
              <input
                type="text"
                className="filter-input"
                placeholder={tr("dep.filterDevices")}
                value={deviceFilter}
                onChange={(e) => setDeviceFilter(e.target.value)}
                aria-label={tr("dep.filterAppDevicesAria")}
              />
              {unifyVersions && versionOptions.length > 0 && (
                <div className="filter-chip-group">
                  <span className="filter-chip-group-label">{tr("dep.versionLabel")}</span>
                  <div className="state-filter" role="group" aria-label={tr("dep.filterVersionAria")}>
                    <button
                      type="button"
                      className={`version-chip${versionFilter === "all" ? " active" : ""}`}
                      onClick={() => setVersionFilter("all")}
                    >
                      {tr("dep.allVersions")} <span className="chip-count">{devices.length}</span>
                    </button>
                    {versionOptions.map((o) => (
                      <button
                        key={o.version}
                        type="button"
                        className={`version-chip${versionFilter === o.version ? " active" : ""}`}
                        onClick={() => setVersionFilter(o.version)}
                      >
                        {o.version} <span className="chip-count">{Math.max(o.trackedCount, o.discoveredCount)}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
              <FilterChipBar
                ariaLabel={tr("dep.filterInstallStateAria")}
                groupLabel={tr("dep.col.installState")}
                variant="state"
                devices={scopedDevices}
                field="installState"
                fallback="unknown"
                active={stateFilter}
                onChange={setStateFilter}
                labelFor={installStateLabel}
              />
              <FilterChipBar
                ariaLabel={tr("dep.filterDepartmentAria")}
                groupLabel={tr("dep.departmentLabel")}
                variant="star"
                devices={scopedDevices}
                field="department"
                fallback="unknown"
                active={starFilter}
                onChange={setStarFilter}
                labelFor={(value) => (value === "unknown" ? tr("department.none") : value)}
              />
            </div>
          )}
          {unifyVersions && versionFilter !== "all" && versionIdsKey && versionDevicesState?.loading && (
            <p className="card-note">{tr("dep.loadingVersionDevices")}</p>
          )}
          {unifyVersions && versionFilter !== "all" && versionIdsKey && versionDevicesState?.error && (
            <p className="error-note">{versionDevicesState.error}</p>
          )}
          <AppInstallTable
            devices={filteredDevices}
            emptyMessage={scopedDevices.length > 0 ? tr("dep.noDeviceMatch") : undefined}
          />
        </>
      )}

      {!unifyVersions && app.discovered && (
        <>
          <span className="filter-chip-group-label deployed-discovered-section-label">
            {tr("dep.fleetVersions", { count: app.discovered.versionCount })}
          </span>
          <p className="card-note">
            {tr("dep.matchNote", { name: app.discovered.matchedName, count: app.discovered.totalDeviceCount })}
          </p>
          <DiscoveredVersionsTable versions={app.discovered.versions} />
        </>
      )}
    </>
  );
}

/** Panneau détail (rail sticky à droite, voir `.deployed-rail` dans styles.css) — affiche le
 * détail par device de l'app sélectionnée dans la liste. Remplace l'ancien accordéon en
 * place : la liste ne bouge plus au clic, et ce panneau dispose de sa propre recherche texte
 * + filtre par état d'installation + filtre par département (voir `DeviceStatusExplorer` ci-dessus).
 *
 * `statusState`/`installCounts` viennent des mêmes hooks qu'avant (useAppInstallStatus,
 * useAppInstallSummary) — aucun changement côté chargement des données, seulement côté mise
 * en page.
 *
 * `onExpand` (2026-09-02, demande de Nicolas : "quand tu agrandis tu peux me donner la
 * possibilité d'aller dans Intune... et voir toutes les informations genre groupe require
 * available et exclude") — ouvre `AppDetailModal`, une popup PLUS GRANDE reprenant ce même
 * panneau (`DeviceStatusExplorer` réutilisé tel quel) et ajoutant les groupes d'assignation +
 * un lien direct vers Intune. Ce panneau (le rail) reste inchangé, demande explicite de
 * Nicolas ("tu gardes ce panneau"). */
function AppDetailPanel({ app, statusState, installCounts, onExpand, onClose }) {
  const devices = statusState?.data?.devices || [];
  const { status: exportStatus, error: exportError, handleExport } = useExportExcel(app, devices);

  return (
    <div className="deployed-detail">
      <div className="deployed-detail-head">
        <AppIcon app={app} />
        <div className="deployed-detail-title">
          <div className="app-card-name-row">
            <span className="app-card-name">{app.displayName || tr("dep.unknownApp")}</span>
            <span className="os-badge">{osBadgeLabel(app.platform)}</span>
            {app.displayVersion && <span className="version-badge">v{app.displayVersion}</span>}
          </div>
          <span className="app-card-meta">
            {tr("dep.publisherModified", { publisher: app.publisher || tr("dep.unknownPublisher"), date: formatDate(app.lastModifiedDateTime) })}
          </span>
        </div>
        <button
          type="button"
          className="deployed-expand-button"
          onClick={onExpand}
          aria-label={tr("dep.expandAria", { name: app.displayName || tr("dep.thisApp") })}
          title={tr("dep.expand")}
        >
          <IconExpand />
        </button>
        {devices.length > 0 && (
          <button
            type="button"
            className="deployed-export-button"
            onClick={handleExport}
            disabled={exportStatus === "exporting"}
            aria-label={tr("dep.exportAria", { name: app.displayName || tr("dep.thisApp") })}
          >
            <IconDownload />
            {exportStatus === "exporting" ? tr("vuln.exporting") : tr("vuln.exportExcel")}
          </button>
        )}
        <button type="button" className="deployed-detail-close" onClick={onClose} aria-label={tr("dep.closeDetail")}>
          <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          </svg>
        </button>
      </div>

      {exportError && <p className="error-note deployed-export-error">{exportError}</p>}

      <DeviceStatusExplorer app={app} statusState={statusState} installCounts={installCounts} />
    </div>
  );
}

/** Une catégorie d'assignation (Requises/Disponibles/Exclues) — voir `AssignmentsSection`. */
function AssignmentGroupCard({ tone, title, groups }) {
  return (
    <div className={`assign-card tone-${tone}`}>
      <div className="assign-card-head">
        <span className="assign-card-title">{title}</span>
        <span className="assign-card-count">
          {tr("dep.groups", { count: groups.length })}
        </span>
      </div>
      {groups.length === 0 ? (
        <p className="assign-empty">{tr("dep.noGroup")}</p>
      ) : (
        <div className="assign-group-list">
          {groups.map((name) => (
            <div className="assign-group-row" key={name}>
              <IconLayers />
              <span className="grp-name">{name}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Groupes d'assignation Intune (2026-09-02, demande de Nicolas — voir docstring
 * `AppDetailPanel` ci-dessus) — 3 blocs Requises/Disponibles/Exclues, `state` vient
 * d'`useAppAssignments` (chargé uniquement à l'ouverture de la popup, jamais au simple clic
 * sur une ligne de la liste). Voir intune/apps.py::get_app_assignments pour le rapprochement
 * groupId → nom et le bucketing par intent/type de cible. */
function AssignmentsSection({ state }) {
  return (
    <>
      <span className="filter-chip-group-label assign-section-label">{tr("dep.assignments")}</span>
      {state?.loading && <p className="card-note">{tr("dep.loadingAssignments")}</p>}
      {state?.error && <p className="error-note">{state.error}</p>}
      {!state?.loading && !state?.error && state?.data && (
        <div className="assign-grid">
          <AssignmentGroupCard tone="required" title={tr("dep.required")} groups={state.data.required || []} />
          <AssignmentGroupCard tone="available" title={tr("dep.available")} groups={state.data.available || []} />
          <AssignmentGroupCard tone="excluded" title={tr("dep.excluded")} groups={state.data.excluded || []} />
        </div>
      )}
    </>
  );
}

/** Popup "agrandir" (2026-09-02, demande de Nicolas : "quand tu agrandis tu peux me donner la
 * possibilité d'aller dans Intune pour le chercher... voir toutes les informations genre
 * groupe require available et exclude") — même chrome que les autres popups de ce dashboard
 * (`.wizard-overlay`/`.wizard-shell`, DeployAppWizard.jsx/EditAppTab.jsx/VulnerabilitiesTab.jsx
 * : Échap/clic en dehors copiés à l'identique). Reprend le panneau existant
 * (`DeviceStatusExplorer`, SA PROPRE instance d'état de filtre) et ajoute deux choses
 * absentes du rail : le lien "Ouvrir dans Intune" (même motif que `.intune-open-btn` déjà sur
 * chaque carte de la liste) et les groupes d'assignation (`AssignmentsSection`). */
function AppDetailModal({ app, statusState, installCounts, assignmentsState, onClose }) {
  const shellRef = useRef(null);
  const devices = statusState?.data?.devices || [];
  const { status: exportStatus, error: exportError, handleExport } = useExportExcel(app, devices);

  useEffect(() => {
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
  }, [onClose]);

  return (
    <div className="wizard-overlay">
      <div
        className="wizard-shell wizard-shell-wide"
        ref={shellRef}
        role="dialog"
        aria-modal="true"
        aria-label={app.displayName || tr("dep.appDetail")}
      >
        <div className="wizard-header">
          <AppIcon app={app} />
          <div className="wizard-header-text">
            <div className="app-card-name-row">
              <h2>{app.displayName || tr("dep.unknownApp")}</h2>
              <span className="os-badge">{osBadgeLabel(app.platform)}</span>
              {app.displayVersion && <span className="version-badge">v{app.displayVersion}</span>}
            </div>
            <span className="app-card-meta">
              {tr("dep.publisherModified", { publisher: app.publisher || tr("dep.unknownPublisher"), date: formatDate(app.lastModifiedDateTime) })}
            </span>
          </div>
          <a
            className="intune-open-btn"
            href={intuneAppUrl(app.id)}
            target="_blank"
            rel="noopener noreferrer"
            title={tr("dep.openIntuneTitle")}
          >
            <WindowsGlyph />
            {tr("dep.openInIntune")}
          </a>
          {devices.length > 0 && (
            <button
              type="button"
              className="deployed-export-button"
              onClick={handleExport}
              disabled={exportStatus === "exporting"}
              aria-label={tr("dep.exportAria", { name: app.displayName || tr("dep.thisApp") })}
            >
              <IconDownload />
              {exportStatus === "exporting" ? tr("vuln.exporting") : tr("vuln.exportExcel")}
            </button>
          )}
          <button type="button" className="deployed-detail-close" onClick={onClose} aria-label={tr("common.closeAria")}>
            <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </div>
        <div className="wizard-step-body">
          {exportError && <p className="error-note deployed-export-error">{exportError}</p>}
          <AssignmentsSection state={assignmentsState} />
          <span className="filter-chip-group-label">{tr("dep.installStateByDevice")}</span>
          <DeviceStatusExplorer app={app} statusState={statusState} installCounts={installCounts} unifyVersions />
        </div>
      </div>
    </div>
  );
}

export default function DeployedAppsTab() {
  const deployed = useDeployedApps();
  const { state: statusCache, ensureLoaded } = useAppInstallStatus();
  const { state: assignmentsCache, ensureLoaded: ensureAssignmentsLoaded } = useAppAssignments();
  const summaryState = useAppInstallSummary();
  const [selectedId, setSelectedId] = useState(null);
  // Popup "agrandir" (2026-09-02, demande de Nicolas) — état SÉPARÉ de `selectedId` : agrandir
  // n'échange pas le rail contre la popup, les deux peuvent coexister (fermer la popup laisse
  // le rail tel quel).
  const [expandedId, setExpandedId] = useState(null);
  const [filter, setFilter] = useState("");
  const [osFilter, setOsFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [visibleCount, setVisibleCount] = useState(REVEAL_STEP);

  function selectApp(id) {
    setSelectedId((current) => (current === id ? null : id));
    // Une entrée "discovered" seule n'a pas de vraie app Intune derrière son id synthétique
    // ("discovered:Nom") — appeler install-status dessus n'aurait aucun sens (pas de
    // mobileApp à interroger), voir get_apps_catalog.
    const app = deployed.apps.find((a) => a.id === id);
    if (app?.source !== "discovered") ensureLoaded(id);
  }

  function expandApp(id) {
    setExpandedId(id);
    ensureAssignmentsLoaded(id);
  }

  // Comptage par OS pour les pastilles ("Windows 31", "iOS/iPadOS 4"...) — dérivé côté client
  // de `deployed.apps` (le champ `platform` est déjà calculé côté backend, voir
  // intune/apps.py::_platform_from_odata_type), pas un appel séparé. Porte maintenant sur la
  // liste FUSIONNÉE (déployées + détectées), cohérent avec la demande de Nicolas de filtrer
  // l'ensemble sans distinction de source pour ce critère.
  const osCounts = useMemo(() => {
    const counts = { all: deployed.apps.length, windows: 0, ios: 0, android: 0, macos: 0, web: 0 };
    for (const a of deployed.apps) {
      const p = a.platform || "web";
      counts[p] = (counts[p] || 0) + 1;
    }
    return counts;
  }, [deployed.apps]);

  const sourceCounts = useMemo(() => {
    const counts = { all: deployed.apps.length, deployed: 0, discovered: 0 };
    for (const a of deployed.apps) {
      counts[a.source === "discovered" ? "discovered" : "deployed"] += 1;
    }
    return counts;
  }, [deployed.apps]);

  const filtered = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    return deployed.apps.filter((a) => {
      const matchesText =
        !needle || (a.displayName || "").toLowerCase().includes(needle) || (a.publisher || "").toLowerCase().includes(needle);
      const matchesOs = osFilter === "all" || (a.platform || "web") === osFilter;
      const matchesSource =
        sourceFilter === "all" || (sourceFilter === "discovered" ? a.source === "discovered" : a.source !== "discovered");
      return matchesText && matchesOs && matchesSource;
    });
  }, [deployed.apps, filter, osFilter, sourceFilter]);

  // Repart de REVEAL_STEP à chaque changement de filtre — même motif que
  // VulnerabilitiesTab.jsx : un "Afficher N de plus" déjà avancé n'a plus de sens sur un
  // nouveau filtrage.
  useEffect(() => {
    setVisibleCount(REVEAL_STEP);
  }, [filter, osFilter, sourceFilter]);

  const visibleApps = filtered.slice(0, visibleCount);
  const remaining = filtered.length - visibleApps.length;

  const selectedApp = useMemo(
    () => deployed.apps.find((a) => a.id === selectedId) || null,
    [deployed.apps, selectedId]
  );

  const expandedApp = useMemo(
    () => deployed.apps.find((a) => a.id === expandedId) || null,
    [deployed.apps, expandedId]
  );

  const publisherCount = useMemo(
    () => new Set(deployed.apps.filter((a) => a.source !== "discovered").map((a) => a.publisher).filter(Boolean)).size,
    [deployed.apps]
  );

  // Applications Intune "réelles" (déployées ou déployées+détectées) — exclut les entrées
  // "discovered" pures du compte "Applications déployées" (2026-09-02, fusion discovered
  // apps) : ce KPI doit continuer à répondre "combien d'apps j'ai poussées via Intune",
  // inchangé par la fusion.
  const deployedOnlyCount = useMemo(() => deployed.apps.filter((a) => a.source !== "discovered").length, [deployed.apps]);

  // Nombre de LOGICIELS distincts détectés sur le parc (2026-09-02) — dédupliqué par nom
  // (`matchedName` pour une entrée "both", `displayName` pour une entrée "discovered" pure),
  // c'est exactement le chiffre qui répond à "je veux pas 600 doublons" : avant la fusion,
  // c'était 18894 lignes brutes (une par version détectée) : ici, un vrai compte de logiciels.
  const distinctDiscoveredCount = useMemo(() => {
    const names = new Set();
    for (const a of deployed.apps) {
      if (a.discovered) names.add(a.discovered.matchedName || a.displayName);
    }
    return names.size;
  }, [deployed.apps]);

  // Formatage FR du taux d'installation (virgule décimale, ex. "94,2%") — même convention
  // que le reste du dashboard (SecureScoreTab, etc.), pas de bibliothèque dédiée pour un seul
  // nombre. `null` (aucune app avec agrégat disponible, ex. tenant sans app déployée) affiché
  // comme "—", pas "0%" (0% affirmerait un échec total plutôt qu'une absence de donnée).
  const summary = summaryState.summary;
  const installRateLabel =
    summaryState.loading || !summary || summary.installRate === null
      ? "—"
      : `${summary.installRate.toLocaleString(currentLocale(), { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`;
  const installRateTone =
    !summary || summary.installRate === null
      ? "default"
      : summary.installRate >= 90
      ? "good"
      : summary.installRate >= 75
      ? "warning"
      : "danger";
  const failedTotalLabel = summaryState.loading || !summary ? "—" : summary.failedTotal;
  const failedTotalTone = summary && summary.failedTotal > 0 ? "danger" : "good";

  if (deployed.error) {
    return (
      <div className="card">
        <div className="card-head">
          <h2>{tr("dep.title")}</h2>
        </div>
        <p className="error-note">{deployed.error}</p>
      </div>
    );
  }

  return (
    <>
      <div className="strip">
        <SummaryCard
          icon={<IconPackage />}
          title={tr("dep.kpi.deployed")}
          value={deployed.loading ? "—" : deployedOnlyCount}
          hint="deviceAppManagement/mobileApps"
        />
        <SummaryCard
          icon={<IconLayers />}
          title={tr("dep.kpi.publishers")}
          value={deployed.loading ? "—" : publisherCount}
        />
        <SummaryCard
          icon={<IconGauge />}
          title={tr("dep.kpi.installRate")}
          value={installRateLabel}
          hint={summaryState.error ? tr("dep.unavailable") : tr("dep.kpi.installRateHint")}
          tone={installRateTone}
        />
        <SummaryCard
          icon={<IconAlertTriangle />}
          title={tr("dep.kpi.failures")}
          value={failedTotalLabel}
          hint={summaryState.error ? tr("dep.unavailable") : tr("dep.kpi.failuresHint")}
          tone={failedTotalTone}
        />
        <SummaryCard
          icon={<IconLayers />}
          title={tr("dep.kpi.discovered")}
          value={deployed.loading ? "—" : distinctDiscoveredCount}
          hint={tr("dep.kpi.discoveredHint")}
        />
      </div>

      <div className="deployed-layout">
        <div className="deployed-main">
          <div className="card-head">
            <h2>{tr("dep.title")}</h2>
            <span className="card-note">list_apps · deviceAppManagement/mobileApps</span>
          </div>

          <div className="filter-bar">
            <input
              type="text"
              className="filter-input"
              placeholder={tr("dep.filterApps")}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              aria-label={tr("dep.filterAppsAria")}
            />
            <div className="os-filter" role="group" aria-label={tr("dep.filterOsAria")}>
              <span className="os-filter-label">OS</span>
              {OS_FILTERS.map((f) => (
                <button
                  key={f.key}
                  type="button"
                  className={`os-chip${osFilter === f.key ? " active" : ""}`}
                  onClick={() => setOsFilter(f.key)}
                >
                  {tr(`dep.os.${f.key}`)} <span className="chip-count">{osCounts[f.key] ?? 0}</span>
                </button>
              ))}
            </div>
            <div className="source-filter" role="group" aria-label={tr("dep.filterSourceAria")}>
              <span className="os-filter-label">{tr("dep.sourceLabel")}</span>
              {SOURCE_FILTERS.map((f) => (
                <button
                  key={f.key}
                  type="button"
                  className={`source-chip${sourceFilter === f.key ? " active" : ""}`}
                  onClick={() => setSourceFilter(f.key)}
                >
                  {tr(`dep.source.${f.key}`)} <span className="chip-count">{sourceCounts[f.key] ?? 0}</span>
                </button>
              ))}
            </div>
          </div>

          {deployed.loading && <p className="card-note">{tr("dep.loadingApps")}</p>}

          {!deployed.loading && filtered.length === 0 && (
            <p className="empty">
              {deployed.apps.length === 0
                ? tr("dep.noApps")
                : tr("dep.noAppMatch")}
            </p>
          )}

          {!deployed.loading && filtered.length > 0 && (
            <>
              <div className="app-grid">
                {visibleApps.map((app) => (
                  <DeployedAppRow
                    key={app.id}
                    app={app}
                    selected={selectedId === app.id}
                    onSelect={selectApp}
                    installCounts={summary?.byApp?.[app.id]}
                  />
                ))}
              </div>
              {remaining > 0 && (
                <button type="button" className="deployed-show-more-btn" onClick={() => setVisibleCount((c) => c + REVEAL_STEP)}>
                  {tr("dep.showMore", { step: Math.min(REVEAL_STEP, remaining), remaining })}
                </button>
              )}
            </>
          )}
        </div>

        <aside className="deployed-rail">
          {selectedApp ? (
            selectedApp.source === "discovered" ? (
              <DiscoveredDetailPanel key={selectedApp.id} app={selectedApp} onClose={() => setSelectedId(null)} />
            ) : (
              <AppDetailPanel
                key={selectedApp.id}
                app={selectedApp}
                statusState={statusCache[selectedApp.id]}
                installCounts={summary?.byApp?.[selectedApp.id]}
                onExpand={() => expandApp(selectedApp.id)}
                onClose={() => setSelectedId(null)}
              />
            )
          ) : (
            <div className="deployed-detail-empty">
              <IconPackage />
              <p>{tr("dep.selectApp")}</p>
            </div>
          )}
        </aside>
      </div>

      {expandedApp && (
        <AppDetailModal
          key={expandedApp.id}
          app={expandedApp}
          statusState={statusCache[expandedApp.id]}
          installCounts={summary?.byApp?.[expandedApp.id]}
          assignmentsState={assignmentsCache[expandedApp.id]}
          onClose={() => setExpandedId(null)}
        />
      )}
    </>
  );
}
