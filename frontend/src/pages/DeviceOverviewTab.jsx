import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { useVanitasSuspiciousEvents } from "../hooks/useDashboardData.js";
import { computeDevicePosture } from "../selectors.js";
import { SuspiciousEventDetailModal, SuspiciousEventsTable } from "./VanitasSuspiciousActivityTab.jsx";
import { CveDetailModal, SeverityBadge, SoftwareIcon } from "./VulnerabilitiesTab.jsx";
import {
  COMPLIANCE_COLORS,
  COMPLIANCE_DEFAULT_COLOR,
  COMPLIANCE_LABEL_FR,
  POLICY_STATUS_COLORS,
  policyStatusLabel,
  policyStatusSeverity,
  EXPOSURE_LEVEL_LABEL_FR,
  ALERT_SEVERITY_COLORS,
  ALERT_STATUS_COLORS,
  ALERT_STATUS_LABEL_FR,
  ALERT_CLASSIFICATION_COLORS,
  ALERT_CLASSIFICATION_LABEL_FR,
  CVE_SEVERITY_COLORS,
} from "../theme.js";
import { IconLaptop, IconShield, IconGauge, IconAlertTriangle, IconTarget, IconWrench, IconLayers, IconPackage } from "../components/icons.jsx";
import { DeviceSettingsPanel, computeSettingsState } from "../components/ComplianceOsGrid.jsx";

/**
 * Onglet "Appareil" (2026-08-18, demande de Nicolas) : vue "360°" d'un appareil précis,
 * recherché par nom — rapproche l'inventaire/la conformité Intune et l'inventaire/les
 * alertes Defender, jusqu'ici répartis sur deux onglets séparés sans aucun lien entre eux.
 * Voir backend/device_overview.py pour la logique de rapprochement (par nom, pas par ID).
 *
 * v3 (2026-09-02, maquettes "Fiche appareil" + "État de santé appareil" validées par Nicolas,
 * inspirées d'un dashboard style Wazuh/Zabbix envoyé en capture) : remplace les 2 cartes
 * Intune/Defender côte à côte (grid-2, refonte du 2026-08-19) par :
 * - `DeviceHero` (identité + posture, peu changé) + une ligne de tuiles "État de santé"
 *   CLIQUABLES (`HealthTile`) — chacune navigue vers la section correspondante (retour de
 *   Nicolas : "quand on clique sur les onglets en haut ça nous fait naviguer dans l'onglet").
 * - Une nav latérale groupée (`DeviceNav`, MATÉRIEL/SÉCURITÉ) inspirée de la capture envoyée,
 *   EN PLUS des tuiles — les deux pilotent le même état `activePane`, un seul mécanisme de
 *   navigation avec deux points d'entrée.
 * - Le contenu de chaque pane reste EXACTEMENT la logique déjà en place (PolicyRow/AlertRow/
 *   VulnRow/groupPolicies/groupVulnSoftware/AlertGroups/computeXKpi, tous inchangés) — seule
 *   la présentation (cartes séparées par thème plutôt que 2 blocs Intune/Defender monolithiques)
 *   change.
 *
 * ⚠️ Champs "nouveaux" envisagés sur la maquette mais NON retenus après vérification en direct
 * contre le tenant de production (2 appareils testés) : `deviceHealthAttestationState`
 * (BitLocker/Secure Boot/intégrité du code) et `partnerReportedThreatState` (menace MTD) sont
 * revenus `None` sur les deux — pas de service d'attestation matérielle ni de partenaire MTD
 * configuré sur ce tenant à ce jour. Ne PAS les afficher en dur : un tuile "État de santé"
 * perpétuellement vide serait pire que son absence. En revanche `deviceValue` (Defender,
 * "Criticité de l'actif") et `machineTags`/`ipAddresses`/`managementAgent` se sont confirmés
 * réels et exploitables — intégrés ci-dessous.
 *
 * Chargé UNIQUEMENT sur soumission du formulaire de recherche (même principe que
 * VulnerabilitiesTab.jsx). Un appareil trouvé dans UN SEUL des deux systèmes n'est PAS traité
 * comme une erreur — chaque pane concernée affiche son propre état "absent" plutôt qu'un
 * message d'erreur global.
 */

const POSTURE_ICON = { good: "✓", warning: "!", danger: "✕" };

// Ordre du pire au mieux — sert à choisir la teinte d'un groupe "Actives" (alertes) à partir
// de la sévérité la plus grave présente, même logique que le tri par gravité des politiques
// (policyStatusSeverity) mais pour l'échelle de sévérité Defender.
const ALERT_SEVERITY_ORDER = ["High", "Medium", "Low", "Informational", "UnSpecified"];

function fmtDate(value) {
  return value ? new Date(value).toLocaleString("fr-FR") : "—";
}

function fmtRelative(value) {
  if (!value) return null;
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return null;
  const diffMs = Date.now() - then;
  const diffH = diffMs / 3_600_000;
  if (diffH < 1) return "à l'instant";
  if (diffH < 24) return `il y a ${Math.round(diffH)} h`;
  return `il y a ${Math.round(diffH / 24)} j`;
}

/** Octets -> Go, une décimale, virgule FR — `totalStorageSpaceInBytes`/`freeStorageSpaceInBytes`/
 * `physicalMemoryInBytes` de managedDevice sont en octets, jamais présentés autrement dans
 * cette app (aucun helper existant à réutiliser, contrairement aux dates/statuts). */
function fmtBytes(bytes) {
  const n = Number(bytes);
  if (!bytes || Number.isNaN(n) || n <= 0) return "—";
  const gb = n / 1024 ** 3;
  return `${gb < 0.1 ? "< 0,1" : gb.toFixed(1).replace(".", ",")} Go`;
}

/** Oui/Non/Inconnu coloré (vert/rouge/gris) — réutilise les teintes `COMPLIANCE_COLORS`
 * (mêmes verts/rouges "bon/mauvais" que le reste du dashboard) plutôt que d'introduire une
 * nouvelle paire de couleurs juste pour ce badge. `goodWhenTrue=false` inverse le sens
 * (ex. jailbreak : "Oui" est le cas GRAVE, pas le cas sain). */
function boolBadge(value, { trueLabel = "Oui", falseLabel = "Non", goodWhenTrue = true } = {}) {
  if (value == null) return { label: "Inconnu", color: COMPLIANCE_DEFAULT_COLOR };
  const isTrue = value === true || String(value).toLowerCase() === "true";
  const isFalse = value === false || String(value).toLowerCase() === "false";
  if (!isTrue && !isFalse) return { label: String(value), color: COMPLIANCE_DEFAULT_COLOR };
  const good = isTrue === goodWhenTrue;
  return { label: isTrue ? trueLabel : falseLabel, color: good ? COMPLIANCE_COLORS.compliant : COMPLIANCE_COLORS.noncompliant };
}

function ColorBadge({ label, color }) {
  return (
    <span className="device-status-badge" style={{ color, borderColor: `${color}55` }}>
      {label}
    </span>
  );
}

/** Bandeau d'identité : nom, utilisateur assigné, posture combinée (computeDevicePosture), et
 * les deux derniers horodatages de vue par système — la synthèse qui justifie l'existence même
 * de cet onglet.
 *
 * ⚠️ `user` (2026-09-02, retour de Nicolas : "pourquoi je ne vois pas le propriétaire ?") —
 * régression réelle de la refonte v3 : `userDisplayName`/`userPrincipalName` (l'utilisateur
 * ASSIGNÉ à l'appareil) vivaient dans l'ancien `.device-byline`, disparu lors du passage aux
 * cartes/onglets, sans être réintégré nulle part. "Propriétaire" dans la carte "Matériel" est
 * un champ DIFFÉRENT (`ownerType`, Entreprise/Personnel — le type de propriété, pas la
 * personne) : les deux existaient déjà séparément avant la refonte, seul le second avait
 * survécu par erreur. */
function DeviceHero({ deviceName, user, posture, intuneSync, defenderSeen }) {
  return (
    <div className="device-hero">
      <div className="device-hero-icon" aria-hidden="true">
        <IconLaptop />
      </div>
      <div className="device-hero-body">
        <p className="device-hero-eyebrow">Fiche appareil · Intune + Defender</p>
        <h2 className="device-hero-name">{deviceName}</h2>
        <div className="device-hero-facts">
          {user && <span className="device-hero-fact">Utilisateur : {user}</span>}
          {intuneSync && <span className="device-hero-fact">Intune : vu {fmtRelative(intuneSync)}</span>}
          {defenderSeen && <span className="device-hero-fact">Defender : vu {fmtRelative(defenderSeen)}</span>}
        </div>
      </div>
      {posture && (
        <div className={`device-posture-pill device-posture-${posture.tone}`}>
          <span className="device-posture-headline">
            <span className="device-posture-icon" aria-hidden="true">
              {POSTURE_ICON[posture.tone]}
            </span>
            <span className="device-posture-label">{posture.label}</span>
          </span>
          {posture.partial && <span className="device-posture-partial">vue partielle</span>}
          {posture.reasons.length > 0 && (
            <span className="device-posture-reasons">{posture.reasons.join(" · ")}</span>
          )}
        </div>
      )}
    </div>
  );
}

/** Tuile "État de santé", cliquable — navigue vers `goto` au clic (2026-09-02, maquette
 * validée : "quand on clique sur les onglets en haut ça nous fait naviguer dans l'onglet").
 * `value=null` (système correspondant non trouvé) affiche "—" plutôt que de disparaître —
 * la tuile reste un point d'entrée valide vers sa section, qui explique elle-même l'absence. */
function HealthTile({ tone, icon, value, label, active, onClick }) {
  return (
    <button type="button" className={`device-htile tone-${tone}${active ? " active" : ""}`} onClick={onClick}>
      <span className="device-htile-icon" aria-hidden="true">
        {icon}
      </span>
      <span className="device-htile-text">
        <span className="device-htile-value">{value ?? "—"}</span>
        <span className="device-htile-label">{label}</span>
      </span>
    </button>
  );
}

/** Nav latérale groupée (2026-09-02, capture envoyée par Nicolas) — un item = une section
 * (`key`), pilote le même état `activePane` que les tuiles de santé au-dessus. */
function NavItem({ itemKey, active, icon, label, badge, onClick }) {
  return (
    <button type="button" className={`device-nav-item${active ? " active" : ""}`} onClick={() => onClick(itemKey)}>
      <span className="device-nav-icon" aria-hidden="true">
        {icon}
      </span>
      <span className="device-nav-label">{label}</span>
      {badge != null && <span className="device-nav-badge">{badge}</span>}
    </button>
  );
}

/** État "absent" d'un des deux systèmes, pour une pane donnée — remplace le contenu de la
 * section plutôt qu'un simple message d'erreur générique. */
function MissingPane({ system, icon, error }) {
  return (
    <div className="card device-missing-card">
      <div className="device-missing-body">
        <span className="device-missing-icon" aria-hidden="true">
          {icon}
        </span>
        <p>{error || `Aucun appareil ${system} trouvé avec ce nom.`}</p>
      </div>
    </div>
  );
}

/**
 * Une ligne de politique — dépliable au clic pour charger le détail par réglage (même
 * endpoint/mêmes composants que le drill-down de ComplianceOsGrid.jsx : `DeviceSettingsPanel`,
 * réutilisé tel quel plutôt que redupliqué).
 *
 * `effectiveState` (2026-09-02, demande de Nicolas : "si les paramètres sont conformes alors
 * tu la mets conforme") — même reconciliation déjà en place côté `ComplianceDeviceTable.jsx`
 * (`computeSettingsState(cached) || d.status`, page "Conformité" fleet-wide) : l'agrégat
 * Graph par politique peut afficher "notApplicable" (ou tout autre état) alors que le détail
 * par réglage, une fois chargé, dit "compliant" — écart déjà documenté ailleurs dans ce
 * dashboard (donnée agrégée périmée côté Microsoft). Avant ce correctif, seul le footnote
 * `ReconciliationNote` (dans le détail déplié) signalait l'écart ; le badge affiché sur la
 * ligne, lui, restait sur l'état brut. Ne s'applique qu'UNE FOIS le détail chargé (clic sur la
 * ligne) — pas de pré-vérification eager de toutes les politiques, même philosophie
 * "progressive" que la page Conformité fleet-wide.
 */
function PolicyRow({ status: s, deviceId }) {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState(null);
  const effectiveState = computeSettingsState(detail) || s.state;
  const color = POLICY_STATUS_COLORS[effectiveState] || POLICY_STATUS_COLORS.unknown;
  const clickable = Boolean(deviceId && s.id);

  function toggle() {
    if (!clickable) return;
    const next = !open;
    setOpen(next);
    if (next && !detail) {
      setDetail({ loading: true });
      api
        .deviceComplianceStatus(deviceId, s.id)
        .then((data) => {
          if (Array.isArray(data)) setDetail({ settings: data });
          else setDetail({ error: data?.message || "erreur inconnue" });
        })
        .catch((err) => setDetail({ error: err.message }));
    }
  }

  function handleKeyDown(e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggle();
    }
  }

  return (
    <li>
      <div
        className={`device-overview-row${clickable ? " clickable" : ""}`}
        style={{ "--row-accent": color }}
        onClick={clickable ? toggle : undefined}
        onKeyDown={clickable ? handleKeyDown : undefined}
        tabIndex={clickable ? 0 : undefined}
        role={clickable ? "button" : undefined}
        aria-expanded={clickable ? open : undefined}
      >
        <span className="device-row-accent" aria-hidden="true" />
        <span className="device-row-label">
          {s.displayName || s.id || "Politique inconnue"}
          {s.lastReportedDateTime && <span className="device-row-sublabel"> · vu {fmtDate(s.lastReportedDateTime)}</span>}
        </span>
        <ColorBadge label={policyStatusLabel(effectiveState)} color={color} />
      </div>
      {open && (
        <div className="device-overview-row-detail">
          <DeviceSettingsPanel state={detail || { loading: true }} policyStatus={s.state} policyName={s.displayName} />
        </div>
      )}
    </li>
  );
}

/** Répartit les statuts de conformité en trois groupes par PERTINENCE : "à traiter"
 * (échec/erreur/grâce/en attente — severity ≤ 3), "conforme", et "non applicable" (+ tout
 * statut imprévu/inconnu). Inchangé depuis la refonte du 2026-08-19. */
function groupPolicies(statuses) {
  const urgent = [];
  const good = [];
  const na = [];
  for (const s of statuses) {
    const sev = policyStatusSeverity(s.state);
    if (sev <= 3) urgent.push(s);
    else if (sev === 5) good.push(s);
    else na.push(s);
  }
  return { urgent, good, na };
}

function PolicyGroups({ statuses, deviceId }) {
  const { urgent, good, na } = groupPolicies(statuses);
  return (
    <>
      {urgent.length > 0 && (
        <div className="device-pgroup device-pgroup-urgent">
          <div className="device-pgroup-head">
            <span className="device-pgroup-dot" style={{ background: COMPLIANCE_COLORS.noncompliant }} />
            <span className="device-pgroup-title" style={{ color: COMPLIANCE_COLORS.noncompliant }}>
              À traiter
            </span>
            <span className="device-pgroup-count">({urgent.length})</span>
          </div>
          <ul className="device-overview-status-list">
            {urgent.map((s, i) => (
              <PolicyRow key={s.id ?? i} status={s} deviceId={deviceId} />
            ))}
          </ul>
        </div>
      )}

      <div className="device-pgroup">
        <div className="device-pgroup-head">
          <span className="device-pgroup-dot" style={{ background: COMPLIANCE_COLORS.compliant }} />
          <span className="device-pgroup-title" style={{ color: COMPLIANCE_COLORS.compliant }}>
            Conforme
          </span>
          <span className="device-pgroup-count">({good.length})</span>
        </div>
        {good.length === 0 ? (
          <p className="empty">Aucune politique conforme.</p>
        ) : (
          <ul className="device-overview-status-list">
            {good.map((s, i) => (
              <PolicyRow key={s.id ?? i} status={s} deviceId={deviceId} />
            ))}
          </ul>
        )}
      </div>

      {na.length > 0 && (
        <Disclosure
          summary={
            <>
              <strong>
                {na.length} politique{na.length > 1 ? "s" : ""} non applicable{na.length > 1 ? "s" : ""}
              </strong>{" "}
              à cet appareil (hors périmètre du check) · aucune action requise
            </>
          }
        >
          <ul className="device-overview-status-list">
            {na.map((s, i) => (
              <PolicyRow key={s.id ?? i} status={s} deviceId={deviceId} />
            ))}
          </ul>
        </Disclosure>
      )}
    </>
  );
}

/** Section repliable générique — même pattern pour les politiques "non applicables", les
 * logiciels vulnérables à faible risque et les alertes résolues. Inchangé depuis 2026-08-19. */
function Disclosure({ summary, children }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="device-pgroup">
      <button
        type="button"
        className="device-pgroup-toggle"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="chev" aria-hidden="true">
          ▸
        </span>
        <span>{summary}</span>
      </button>
      {open && <div className="device-pgroup-toggle-body">{children}</div>}
    </div>
  );
}

/** Détail complet d'une alerte (déplié au clic) — combine des champs déjà présents sur
 * l'alerte de la liste et des champs qui n'existent QUE sur `GET /api/alerts/{id}`
 * (détermination, état d'investigation, techniques MITRE ATT&CK). Inchangé. */
function AlertDetail({ alert: a, state }) {
  if (state.loading) return <p className="empty cve-small">Chargement du détail…</p>;
  if (state.error) return <p className="empty cve-small">Impossible de récupérer le détail : {state.error}</p>;
  const d = state.data || {};
  const classification = a.classification || "Non classifiée";
  const classifColor = ALERT_CLASSIFICATION_COLORS[classification] || ALERT_CLASSIFICATION_COLORS["Non classifiée"];
  const mitre = Array.isArray(d.mitreTechniques) ? d.mitreTechniques : [];

  return (
    <div className="alert-detail-meta">
      <div className="alert-detail-meta-item">
        <span className="alert-detail-meta-label">Catégorie</span>
        <span>{a.category || "—"}</span>
      </div>
      <div className="alert-detail-meta-item">
        <span className="alert-detail-meta-label">Classification</span>
        <ColorBadge label={ALERT_CLASSIFICATION_LABEL_FR[classification] || classification} color={classifColor} />
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
        <span className="alert-detail-meta-label">Famille de menace</span>
        <span>{a.threatFamilyName || "—"}</span>
      </div>
      <div className="alert-detail-meta-item">
        <span className="alert-detail-meta-label">Assigné à</span>
        <span>{a.assignedTo || "—"}</span>
      </div>
      <div className="alert-detail-meta-item">
        <span className="alert-detail-meta-label">Créée le</span>
        <span>{fmtDate(a.alertCreationTime)}</span>
      </div>
      <div className="alert-detail-meta-item">
        <span className="alert-detail-meta-label">Dernier événement</span>
        <span>{fmtDate(a.lastEventTime)}</span>
      </div>
      {mitre.length > 0 && (
        <div className="alert-detail-meta-item">
          <span className="alert-detail-meta-label">Techniques MITRE ATT&CK</span>
          <span>{mitre.map((t) => (typeof t === "string" ? t : t.techniqueId || t.technique || "?")).join(", ")}</span>
        </div>
      )}
    </div>
  );
}

/** Une ligne d'alerte — même principe de dépli que PolicyRow. Inchangé. */
function AlertRow({ alert: a }) {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState(null);
  const sevColor = ALERT_SEVERITY_COLORS[a.severity] || ALERT_SEVERITY_COLORS.Informational;
  const statusColor = ALERT_STATUS_COLORS[a.status] || ALERT_STATUS_COLORS.Unknown;
  const clickable = Boolean(a.id);

  function toggle() {
    if (!clickable) return;
    const next = !open;
    setOpen(next);
    if (next && !detail) {
      setDetail({ loading: true });
      api
        .defenderAlertDetail(a.id)
        .then((data) => {
          if (data?.error) setDetail({ error: data.message });
          else setDetail({ data });
        })
        .catch((err) => setDetail({ error: err.message }));
    }
  }

  function handleKeyDown(e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggle();
    }
  }

  return (
    <li>
      <div
        className={`device-overview-row${clickable ? " clickable" : ""}`}
        style={{ "--row-accent": sevColor }}
        onClick={clickable ? toggle : undefined}
        onKeyDown={clickable ? handleKeyDown : undefined}
        tabIndex={clickable ? 0 : undefined}
        role={clickable ? "button" : undefined}
        aria-expanded={clickable ? open : undefined}
      >
        <span className="device-row-accent" aria-hidden="true" />
        <span className="device-row-label">
          {a.title || "Alerte sans titre"}
          {a.category && <span className="device-row-sublabel"> · {a.category}</span>}
        </span>
        <span className="device-overview-alert-badges">
          <ColorBadge label={a.severity || "?"} color={sevColor} />
          <ColorBadge label={ALERT_STATUS_LABEL_FR[a.status] || a.status || "?"} color={statusColor} />
        </span>
      </div>
      {open && (
        <div className="device-overview-row-detail">
          <AlertDetail alert={a} state={detail || { loading: true }} />
        </div>
      )}
    </li>
  );
}

/** Pire sévérité présente dans une liste d'alertes — sert à teinter le groupe "Actives".
 * Inchangé depuis 2026-08-19. */
function worstAlertSeverity(alerts) {
  for (const sev of ALERT_SEVERITY_ORDER) {
    if (alerts.some((a) => a.severity === sev)) return sev;
  }
  return "Informational";
}

// Ordre de gravité (pire en premier) pour le tri par défaut de la table ci-dessous — même
// vocabulaire que CVE_SEVERITY_COLORS/SeverityBadge (VulnerabilitiesTab.jsx).
const DEVICE_VULN_SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };
const DEVICE_VULN_SEVERITY_LABEL_FR = { Critical: "Critique", High: "Élevée", Medium: "Moyenne", Low: "Faible" };
const DEVICE_VULN_SEVERITIES = ["Critical", "High", "Medium", "Low"];

/** Bandeau KPI par criticité (2026-09-02, maquette validée — "avec des couleurs et la
 * criticité en plus") — liseré haut coloré, même idiom que les autres bandeaux KPI du
 * dashboard (Alertes Defender, Vulnérabilités). Calculé côté client sur `vulns` (déjà chargé
 * en entier), aucun nouvel appel réseau. */
function DeviceVulnKpiStrip({ vulns }) {
  const counts = useMemo(() => {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const v of vulns) {
      if (c[v.severity] !== undefined) c[v.severity] += 1;
    }
    return c;
  }, [vulns]);

  return (
    <div className="device-vuln-kpi-strip">
      {DEVICE_VULN_SEVERITIES.map((sev) => (
        <div key={sev} className="device-vuln-kpi-card" style={{ "--kpi-accent": CVE_SEVERITY_COLORS[sev] }}>
          <span className="device-vuln-kpi-label">{DEVICE_VULN_SEVERITY_LABEL_FR[sev]}</span>
          <span className="device-vuln-kpi-value">{counts[sev]}</span>
        </div>
      ))}
    </div>
  );
}

/** Table CVE scrollable de l'onglet "Vulnérabilités" (2026-09-02, demande de Nicolas : "je les
 * veux toutes dans un tableau scrollable avec la cve le logiciel concernée et autre
 * information ... et le fait que je peux cliquer dessus comme dans les vuln normal", puis
 * "le tableau est pas beau... des couleurs et la criticité en plus" — maquette validée) —
 * remplace l'ancien groupement par LOGICIEL (VulnRow/groupVulnSoftware, cve_count agrégé, pas
 * cliquable) : une ligne = une CVE, réutilise `.cve-table-wrap`/`.cve-device-table`
 * (génériques, déjà utilisées par VulnerabilitiesTab.jsx). Bandeau KPI par criticité + filtre
 * par sévérité en pastilles + liseré coloré/pastille de sévérité par ligne (`SeverityBadge`,
 * `CVE_SEVERITY_COLORS` — EXPORTÉS de VulnerabilitiesTab.jsx/theme.js, pas une redérivation).
 * Triée par sévérité décroissante par défaut (`v.severity`, colonne directe de
 * `DeviceTvmSoftwareVulnerabilities`, ajoutée gratuitement côté backend le même jour). Clic
 * sur une ligne → `onSelectCve`, qui ouvre `CveDetailModal` (EXPORTÉE, même popup que la page
 * "Vulnérabilités" normale). Recherche texte côté client, aucun nouvel appel réseau. */
function DeviceVulnTable({ vulns, onSelectCve }) {
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  const severityCounts = useMemo(() => {
    const c = { all: vulns.length, Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const v of vulns) {
      if (c[v.severity] !== undefined) c[v.severity] += 1;
    }
    return c;
  }, [vulns]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    let list = vulns;
    if (needle) {
      list = list.filter(
        (v) =>
          (v.cve_code || "").toLowerCase().includes(needle) ||
          (v.software_name || "").toLowerCase().includes(needle) ||
          (v.software_vendor || "").toLowerCase().includes(needle)
      );
    }
    if (severityFilter !== "all") {
      list = list.filter((v) => v.severity === severityFilter);
    }
    return [...list].sort((a, b) => {
      const diff = (DEVICE_VULN_SEVERITY_ORDER[a.severity] ?? 5) - (DEVICE_VULN_SEVERITY_ORDER[b.severity] ?? 5);
      return diff !== 0 ? diff : (a.cve_code || "").localeCompare(b.cve_code || "");
    });
  }, [vulns, query, severityFilter]);

  return (
    <>
      <DeviceVulnKpiStrip vulns={vulns} />
      <div className="filter-bar" style={{ marginBottom: 12 }}>
        <input
          type="text"
          className="filter-input"
          placeholder="Filtrer par CVE, éditeur ou logiciel…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filtrer les vulnérabilités de cet appareil"
        />
        <div className="device-vuln-sev-filter" role="group" aria-label="Filtrer par sévérité">
          <button
            type="button"
            className={`device-vuln-sev-chip all${severityFilter === "all" ? " active" : ""}`}
            onClick={() => setSeverityFilter("all")}
          >
            Toutes <span className="chip-count">{severityCounts.all}</span>
          </button>
          {DEVICE_VULN_SEVERITIES.map((sev) => (
            <button
              key={sev}
              type="button"
              className={`device-vuln-sev-chip${severityFilter === sev ? " active" : ""}`}
              style={{ "--sev-accent": CVE_SEVERITY_COLORS[sev] }}
              onClick={() => setSeverityFilter(sev)}
            >
              <span className="dot" />
              {DEVICE_VULN_SEVERITY_LABEL_FR[sev]} <span className="chip-count">{severityCounts[sev]}</span>
            </button>
          ))}
        </div>
        <span className="card-note">
          {filtered.length} / {vulns.length} CVE
        </span>
      </div>
      <div className="cve-table-wrap">
        <table className="cve-device-table">
          <thead>
            <tr>
              <th>Sévérité</th>
              <th>CVE</th>
              <th>Logiciel</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((v) => (
              <tr
                key={v.cve_code}
                className="device-vuln-row-clickable"
                style={{ borderLeftColor: CVE_SEVERITY_COLORS[v.severity] || CVE_SEVERITY_COLORS.Unknown }}
                onClick={() => onSelectCve(v)}
              >
                <td>
                  <SeverityBadge severity={v.severity} />
                </td>
                <td className="cve-mono cve-cell-name">{v.cve_code}</td>
                <td className="cve-small">
                  <div className="device-vuln-sw-cell">
                    <SoftwareIcon name={v.software_name} />
                    <div>
                      <div className="device-vuln-sw-name">{v.software_name || "—"}</div>
                      {v.software_vendor && <div className="device-vuln-sw-vendor">{v.software_vendor}</div>}
                    </div>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && <p className="empty">Aucune CVE ne correspond à ce filtre.</p>}
      </div>
    </>
  );
}

function AlertGroups({ alerts }) {
  const active = alerts.filter((a) => a.status === "New" || a.status === "InProgress");
  const resolved = alerts.filter((a) => !(a.status === "New" || a.status === "InProgress"));
  const worst = active.length > 0 ? worstAlertSeverity(active) : null;
  const worstColor = worst ? ALERT_SEVERITY_COLORS[worst] || ALERT_SEVERITY_COLORS.Informational : null;

  return (
    <>
      {active.length > 0 && (
        <div className="device-pgroup device-pgroup-urgent">
          <div className="device-pgroup-head">
            <span className="device-pgroup-dot" style={{ background: worstColor }} />
            <span className="device-pgroup-title" style={{ color: worstColor }}>
              Actives
            </span>
            <span className="device-pgroup-count">({active.length})</span>
          </div>
          <ul className="device-overview-status-list">
            {active.map((a) => (
              <AlertRow key={a.id} alert={a} />
            ))}
          </ul>
        </div>
      )}

      {resolved.length > 0 && (
        <Disclosure
          summary={
            <>
              <strong>
                {resolved.length} alerte{resolved.length > 1 ? "s" : ""} résolue{resolved.length > 1 ? "s" : ""}
              </strong>{" "}
              · pour mémoire, aucune action requise
            </>
          }
        >
          <ul className="device-overview-status-list">
            {resolved.slice(0, 15).map((a) => (
              <AlertRow key={a.id} alert={a} />
            ))}
          </ul>
          {resolved.length > 15 && <p className="card-note">+{resolved.length - 15} autre(s) alerte(s) résolue(s) non affichée(s).</p>}
        </Disclosure>
      )}
    </>
  );
}

/** Alertes non erronées d'un appareil Defender, filtrées une seule fois. Inchangé. */
function cleanAlerts(defender) {
  return Array.isArray(defender?.alerts) ? defender.alerts.filter((a) => !a?.error) : [];
}

/** CVE d'un appareil Defender, débarrassées du contrat d'erreur — une ligne par CVE
 * (2026-09-02, `defender.vulnerabilities`, voir defender/vulnerabilities.py::
 * get_device_vulnerabilities) : remplace l'ancien `vulnerableSoftware` groupé par logiciel. */
function cleanVulnerabilities(defender) {
  const raw = Array.isArray(defender?.vulnerabilities) ? defender.vulnerabilities : [];
  if (raw.length === 1 && raw[0]?.error) return { list: [], error: raw[0].message };
  return { list: raw.filter((v) => !v?.error), error: null };
}

/** KPI "Conformité" — teinte + libellé de `d.complianceState`. Inchangé. */
function computeConformiteKpi(intune) {
  if (!intune?.found) return null;
  const state = intune.device?.complianceState;
  const tone = state === "compliant" ? "ok" : state === "noncompliant" ? "bad" : state === "inGracePeriod" ? "warn" : "warn";
  const statuses = Array.isArray(intune.complianceStatuses) ? intune.complianceStatuses : [];
  const failing = statuses.filter((s) => policyStatusSeverity(s.state) <= 3).length;
  return {
    tone,
    label: COMPLIANCE_LABEL_FR[state] || state || "Inconnu",
    sub:
      statuses.length > 0
        ? `${statuses.length} politique${statuses.length > 1 ? "s" : ""}${failing > 0 ? `, ${failing} en échec` : ""}`
        : "aucune politique",
  };
}

/** KPI "Exposition" — teinte + libellé de `m.exposureLevel`. Inchangé. */
function computeExpositionKpi(defender) {
  if (!defender?.found) return null;
  const level = defender.machine?.exposureLevel;
  const tone = level === "Low" ? "ok" : level === "High" ? "bad" : level === "Medium" ? "warn" : "warn";
  return { tone, label: EXPOSURE_LEVEL_LABEL_FR[level] || level || "Inconnue", sub: "Defender for Endpoint" };
}

/** KPI "Alertes actives" — compte des alertes New/InProgress, teinté par la pire sévérité. */
function computeAlertesKpi(defender) {
  if (!defender?.found) return null;
  const alerts = cleanAlerts(defender);
  const active = alerts.filter((a) => a.status === "New" || a.status === "InProgress");
  const worst = active.length > 0 ? worstAlertSeverity(active) : null;
  const tone = worst === "High" ? "bad" : active.length > 0 ? "warn" : "ok";
  let sub;
  if (active.length === 0) sub = "aucune alerte active";
  else if (worst === "High") sub = `dont ${active.filter((a) => a.severity === "High").length} de sévérité élevée`;
  else sub = "sévérité moyenne ou informationnelle";
  return { tone, value: active.length, sub };
}

/** KPI "Logiciels vulnérables" — compte de logiciels distincts touchés par au moins une CVE
 * (2026-09-02, adapté à `defender.vulnerabilities` — une ligne par CVE, plus par logiciel :
 * le compte de logiciels distincts et le nombre de CVE "critiques" — >10 CVE pour CE logiciel
 * précis — sont donc recalculés ici plutôt que lus directement). */
function computeVulnKpi(defender) {
  if (!defender?.found) return null;
  const { list } = cleanVulnerabilities(defender);
  const bySoftware = new Map();
  for (const v of list) {
    const key = `${v.software_vendor || ""}::${v.software_name || "?"}`;
    bySoftware.set(key, (bySoftware.get(key) || 0) + 1);
  }
  const critical = Array.from(bySoftware.values()).filter((n) => n > 10).length;
  const tone = critical > 0 ? "bad" : list.length > 0 ? "warn" : "ok";
  const sub =
    list.length === 0
      ? "aucun logiciel vulnérable détecté"
      : `${list.length} CVE au total${critical > 0 ? `, ${critical} logiciel${critical > 1 ? "s" : ""} critique${critical > 1 ? "s" : ""}` : ", aucun logiciel critique"}`;
  return { tone, value: bySoftware.size, sub };
}

/** KPI "Criticité de l'actif" (2026-09-02, nouveau — `deviceValue` Defender, confirmé réel
 * ("Normal") en direct contre le tenant de production, contrairement à
 * `deviceHealthAttestationState`/`partnerReportedThreatState`, restés `None` sur les 2
 * appareils testés et donc volontairement absents de cette page). */
function computeCriticiteKpi(defender) {
  if (!defender?.found) return null;
  const value = defender.machine?.deviceValue;
  const tone = value === "High" ? "warn" : value === "Low" ? "ok" : "ok";
  const label = { High: "Élevée", Low: "Faible", Normal: "Normale" }[value] || value || "Inconnue";
  return { tone, label, sub: "Defender for Endpoint" };
}

/** Adresse IP "principale" d'un appareil Defender (2026-09-02) — `ipAddresses` (confirmé réel
 * en direct : liste riche avec type/statut par interface) contient souvent plusieurs
 * interfaces link-local (169.254.x.x, désactivées) en plus de la ou des interfaces réellement
 * actives : on préfère la première interface `operationalStatus === "Up"` à `lastIpAddress`
 * seul, qui ne donne qu'une adresse sans dire si elle est encore d'actualité. Retombe sur
 * `lastIpAddress` si `ipAddresses` est absent/vide (champ pas garanti peuplé partout). */
function primaryIpAddress(machine) {
  const list = Array.isArray(machine?.ipAddresses) ? machine.ipAddresses : [];
  const up = list.find((ip) => ip.operationalStatus === "Up" && ip.ipAddress && !ip.ipAddress.startsWith("169.254."));
  // `lastExternalIpAddress` (2026-09-02, retour de Nicolas sur un appareil Android réel dont
  // l'IP n'apparaissait pas) : `lastIpAddress` revient `null` sur certains appareils mobiles —
  // confirmé en direct (cecilia_cester_Android : lastIpAddress=null, mais
  // lastExternalIpAddress="92.184.141.104", exactement l'adresse visible dans le portail
  // Defender). Dernier repli, après les deux tentatives déjà en place.
  return up?.ipAddress || machine?.lastIpAddress || machine?.lastExternalIpAddress || null;
}

/** Onglet "Applications" (2026-09-02, demande de Nicolas : "on peut rajouter pour tous les
 * devices un onglet avec les applications ?") — liste les applications DÉTECTÉES sur le
 * disque de l'appareil (`intune.detectedApps`, `get_device_detected_apps` côté backend),
 * PAS le statut de déploiement Intune par app : `retrieveDeviceAppInstallationStatusReport`
 * (utilisé par "Application déployée") ne peut être filtré que par `ApplicationId`, jamais
 * par device — vérifié en direct (400 Bad Request), il n'existe donc pas de vue symétrique
 * "statut d'installation par app" pour un appareil pris seul. Recherche texte simple, côté
 * client — un appareil normal en a des dizaines (87 sur DEMO-WKS-106 en conditions réelles),
 * pas besoin de pagination serveur.
 *
 * `packageId` (2026-09-02, retour de Nicolas sur "fr.paylib.paylib" affiché brut : "on aurait
 * pas une bibliothèque sur laquelle on peut se baser pour afficher le nom display de l'app ?")
 * — présent UNIQUEMENT quand `intune.app_names.resolve_android_app_names` a remplacé le nom
 * brut Android par le nom Google Play Store ; affiché en petite sous-ligne technique sous le
 * nom convivial (jamais caché) et inclus dans la recherche pour rester trouvable par les deux
 * (un technicien qui connaît "com.android.chrome" par cœur doit pouvoir taper ça). */
function AppsPane({ apps }) {
  const [query, setQuery] = useState("");
  if (!Array.isArray(apps) || apps.length === 0) {
    return <p className="empty">Aucune application détectée sur cet appareil.</p>;
  }
  const needle = query.trim().toLowerCase();
  const filtered = needle
    ? apps.filter(
        (a) => a.displayName.toLowerCase().includes(needle) || (a.packageId || "").toLowerCase().includes(needle)
      )
    : apps;
  return (
    <>
      <div className="filter-bar" style={{ marginBottom: 12 }}>
        <input
          type="text"
          className="filter-input"
          placeholder="Filtrer par nom d'application…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filtrer les applications"
        />
        <span className="card-note">
          {filtered.length} / {apps.length} application{apps.length > 1 ? "s" : ""}
        </span>
      </div>
      <div className="cve-table-wrap">
        <table className="cve-device-table">
          <thead>
            <tr>
              <th>Application</th>
              <th>Version</th>
              <th>Plateforme</th>
              <th>Taille</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => (
              <tr key={a.id}>
                <td className="cve-cell-name">
                  {a.displayName}
                  {a.packageId && <div className="cve-mono cve-small">{a.packageId}</div>}
                </td>
                <td className="cve-mono cve-small">{a.version}</td>
                <td className="cve-small">{a.platform}</td>
                <td className="cve-mono cve-small">{fmtBytes(a.sizeInByte)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && <p className="empty">Aucune application ne correspond à « {query} ».</p>}
      </div>
    </>
  );
}

const MAX_RECENT = 5;

const NAV_SECTIONS = [
  { key: "overview", label: "Vue d'ensemble", icon: <IconGauge /> },
  {
    group: "Matériel",
    items: [
      { key: "os", label: "Système d'exploitation", icon: <IconLaptop /> },
      { key: "hw", label: "Matériel", icon: <IconWrench /> },
      { key: "identity", label: "Identité & réseau", icon: <IconLayers /> },
      { key: "apps", label: "Applications", icon: <IconPackage /> },
    ],
  },
  {
    group: "Sécurité",
    items: [
      { key: "compliance", label: "Conformité", icon: <IconShield /> },
      { key: "vulns", label: "Vulnérabilités", icon: <IconTarget /> },
      { key: "alerts", label: "Alertes", icon: <IconAlertTriangle /> },
    ],
  },
];

export default function DeviceOverviewTab({ initialQuery }) {
  const [query, setQuery] = useState("");
  const [state, setState] = useState({ loading: false, error: null, result: null });
  const [recentSearches, setRecentSearches] = useState([]);
  const [activePane, setActivePane] = useState("overview");
  // Popup CVE (2026-09-02, demande de Nicolas : "cliquer dessus comme dans les vuln normal")
  // — même popup que la page "Vulnérabilités" normale (CveDetailModal, exportée de
  // VulnerabilitiesTab.jsx), ouverte au clic sur une ligne de DeviceVulnTable.
  const [selectedCve, setSelectedCve] = useState(null);
  // Enrichissement du pane "Alertes" avec les événements suspects Vanitas du même poste
  // (jalon "détection d'activités suspectes sur les postes", 2026-09-14) — voir
  // `device_overview.py::get_device_overview` pour la jointure Intune/Defender par NOM ; côté
  // Vanitas il n'existe pas encore de résolution hostname↔agent_id exposée ici, donc filtrage
  // par `hostname` CÔTÉ CLIENT sur le journal fleet-wide (échelle "quelques postes", même
  // raisonnement que les autres agrégats fleet-wide de ce dashboard) plutôt qu'un nouvel appel
  // dédié. Un compte Pandore sans AUCUN profil Vanitas assigné verra cet appel échouer (403) —
  // dégradé SILENCIEUSEMENT (voir plus bas) : ce bloc est un plus, pas le cœur de cette page.
  const vanitasSuspiciousEvents = useVanitasSuspiciousEvents({});
  const [selectedSuspiciousEvent, setSelectedSuspiciousEvent] = useState(null);

  // Recherche globale (2026-08-20) : un nom d'appareil tapé dans le masthead atterrit ici via
  // `initialQuery`. Clé sur `initialQuery?.token` (pas `initialQuery?.query`).
  useEffect(() => {
    if (!initialQuery?.query) return;
    setQuery(initialQuery.query);
    runSearch(initialQuery.query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery?.token]);

  function runSearch(name) {
    setState({ loading: true, error: null, result: null });
    setActivePane("overview");
    // Revue de bugs du 2026-09-02 : sans ce reset, ouvrir la popup CVE sur l'appareil A puis
    // chercher l'appareil B SANS fermer la popup laissait `selectedCve` (la CVE cliquée sous
    // A) ouvert alors que `deviceScope` (dérivé de `result?.deviceName`) bascule sur B —
    // `CveDetailModal` se remettait alors à filtrer les chemins de CETTE CVE pour B, résultat
    // silencieusement faux (ou trompeur) plutôt qu'une popup fermée proprement.
    setSelectedCve(null);
    api
      .deviceOverview(name)
      .then((payload) => {
        if (payload?.error) {
          setState({ loading: false, error: payload.message, result: null });
        } else {
          setState({ loading: false, error: null, result: payload });
          setRecentSearches((prev) => [name, ...prev.filter((n) => n !== name)].slice(0, MAX_RECENT));
        }
      })
      .catch((err) => setState({ loading: false, error: err.message, result: null }));
  }

  function handleSubmit(event) {
    event.preventDefault();
    const name = query.trim();
    if (!name) return;
    runSearch(name);
  }

  function handleChipClick(name) {
    setQuery(name);
    runSearch(name);
  }

  const result = state.result;
  const bothMissing = result && !result.intune.found && !result.defender.found;
  const posture = result && !bothMissing ? computeDevicePosture(result) : null;

  const conformiteKpi = result && !bothMissing ? computeConformiteKpi(result.intune) : null;
  const expositionKpi = result && !bothMissing ? computeExpositionKpi(result.defender) : null;
  const alertesKpi = result && !bothMissing ? computeAlertesKpi(result.defender) : null;
  const vulnKpi = result && !bothMissing ? computeVulnKpi(result.defender) : null;
  const criticiteKpi = result && !bothMissing ? computeCriticiteKpi(result.defender) : null;

  const intune = result?.intune;
  const defender = result?.defender;
  const d = intune?.found ? intune.device : null;
  const m = defender?.found ? defender.machine : null;

  const deviceSuspiciousEvents = useMemo(() => {
    const name = (result?.deviceName || "").trim().toLowerCase();
    if (!name) return [];
    return (vanitasSuspiciousEvents.state.data ?? []).filter((e) => (e.hostname || "").trim().toLowerCase() === name);
  }, [vanitasSuspiciousEvents.state.data, result?.deviceName]);

  return (
    <>
      <div className="card">
        <div className="card-head">
          <span className="device-card-icon device-card-icon-amber">
            <IconGauge />
          </span>
          <h2>Rechercher un appareil</h2>
          <span className="card-note device-card-headline-note">
            nom Intune (deviceName) ou nom DNS Defender (computerDnsName)
          </span>
        </div>
        <form className="vuln-search-form" onSubmit={handleSubmit}>
          <input
            type="text"
            className="vuln-search-input"
            placeholder="Nom de l'appareil (ex. DEMO-WKS-107)…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Nom de l'appareil"
          />
          <button type="submit" className="vuln-search-button" disabled={state.loading || !query.trim()}>
            {state.loading ? "Recherche…" : "Rechercher"}
          </button>
        </form>
        <p className="card-note vuln-search-hint">
          Un appareil absent de l'un des deux systèmes n'est pas une erreur — la section correspondante l'indique
          simplement, le reste de la fiche reste disponible.
        </p>
        {recentSearches.length > 0 && (
          <div className="device-recent-chips">
            <span className="device-recent-label">Récent :</span>
            {recentSearches.map((name) => (
              <button key={name} type="button" className="device-recent-chip" onClick={() => handleChipClick(name)}>
                {name}
              </button>
            ))}
          </div>
        )}
      </div>

      {state.error && <p className="error-note">{state.error}</p>}

      {!state.loading && !state.error && !result && (
        <div className="card">
          <div className="vuln-idle-note">
            <IconAlertTriangle />
            <p>Tape le nom d'un appareil ci-dessus pour voir sa fiche combinée Intune + Defender.</p>
          </div>
        </div>
      )}

      {bothMissing && (
        <div className="card device-missing-card device-missing-card-full">
          <div className="device-missing-body">
            <span className="device-missing-icon" aria-hidden="true">
              <IconAlertTriangle />
            </span>
            <p>
              Aucun appareil nommé « {result.deviceName} » trouvé, ni dans Intune ni dans Defender. Vérifie
              l'orthographe exacte du nom (deviceName Intune / computerDnsName Defender peuvent différer d'un
              suffixe de domaine).
            </p>
          </div>
        </div>
      )}

      {result && !bothMissing && (
        <>
          <DeviceHero
            deviceName={result.deviceName}
            user={d?.userDisplayName || d?.userPrincipalName || null}
            posture={posture}
            intuneSync={intune.found ? d?.lastSyncDateTime : null}
            defenderSeen={defender.found ? m?.lastSeen : null}
          />

          <div className="device-health-strip">
            <HealthTile
              tone={conformiteKpi?.tone || "neutral"}
              icon={<IconShield />}
              value={conformiteKpi?.label}
              label="Conformité (Intune)"
              active={activePane === "compliance"}
              onClick={() => setActivePane("compliance")}
            />
            <HealthTile
              tone={vulnKpi?.tone || "neutral"}
              icon={<IconTarget />}
              value={vulnKpi ? vulnKpi.value : null}
              label="Logiciels vulnérables"
              active={activePane === "vulns"}
              onClick={() => setActivePane("vulns")}
            />
            <HealthTile
              tone={alertesKpi?.tone || "neutral"}
              icon={<IconAlertTriangle />}
              value={alertesKpi ? alertesKpi.value : null}
              label="Alertes actives"
              active={activePane === "alerts"}
              onClick={() => setActivePane("alerts")}
            />
            <HealthTile
              tone={expositionKpi?.tone || "neutral"}
              icon={<IconGauge />}
              value={expositionKpi?.label}
              label="Exposition (Defender)"
              active={activePane === "identity"}
              onClick={() => setActivePane("identity")}
            />
            <HealthTile
              tone={criticiteKpi?.tone || "neutral"}
              icon={<IconShield />}
              value={criticiteKpi?.label}
              label="Criticité de l'actif"
              active={activePane === "identity"}
              onClick={() => setActivePane("identity")}
            />
          </div>

          <div className="device-pane-layout">
            <nav className="device-nav">
              {NAV_SECTIONS.map((section) =>
                section.group ? (
                  <div key={section.group} className="device-nav-group">
                    <p className="device-nav-group-title">{section.group}</p>
                    <div className="device-nav-sub">
                      {section.items.map((item) => (
                        <NavItem
                          key={item.key}
                          itemKey={item.key}
                          active={activePane === item.key}
                          icon={item.icon}
                          label={item.label}
                          onClick={setActivePane}
                        />
                      ))}
                    </div>
                  </div>
                ) : (
                  <NavItem
                    key={section.key}
                    itemKey={section.key}
                    active={activePane === section.key}
                    icon={section.icon}
                    label={section.label}
                    onClick={setActivePane}
                  />
                )
              )}
            </nav>

            <div className="device-pane-content">
              {activePane === "overview" && (
                <div className="device-spec-grid">
                  <OsCard intune={intune} defender={defender} />
                  <HwCard intune={intune} />
                  <IdentityCard intune={intune} defender={defender} />
                </div>
              )}

              {activePane === "os" && (
                <div className="device-spec-grid solo">
                  <OsCard intune={intune} defender={defender} />
                </div>
              )}

              {activePane === "hw" && (
                <div className="device-spec-grid solo">
                  <HwCard intune={intune} />
                </div>
              )}

              {activePane === "identity" && (
                <div className="device-spec-grid solo">
                  <IdentityCard intune={intune} defender={defender} />
                </div>
              )}

              {activePane === "compliance" &&
                (!intune.found ? (
                  <MissingPane system="Intune" icon={<IconLaptop />} error={intune.error} />
                ) : (
                  <div className="card device-content-card">
                    <div className="card-head">
                      <h2>Statuts par politique</h2>
                      <span className="card-note">
                        {Array.isArray(intune.complianceStatuses) ? intune.complianceStatuses.length : 0} politique(s)
                      </span>
                    </div>
                    {!Array.isArray(intune.complianceStatuses) || intune.complianceStatuses.length === 0 ? (
                      <p className="empty">Aucun statut de conformité par politique disponible pour cet appareil.</p>
                    ) : (
                      <>
                        <PolicyGroups statuses={intune.complianceStatuses} deviceId={d?.id} />
                        <p className="card-note vuln-search-hint">Clique une ligne pour voir le détail par réglage.</p>
                      </>
                    )}
                  </div>
                ))}

              {activePane === "vulns" &&
                (!defender.found ? (
                  <MissingPane system="Defender" icon={<IconShield />} error={defender.error} />
                ) : (
                  <div className="card device-content-card">
                    <div className="card-head">
                      <h2>Vulnérabilités</h2>
                    </div>
                    {(() => {
                      const { list, error } = cleanVulnerabilities(defender);
                      if (error) return <p className="error-note">{error}</p>;
                      if (list.length === 0) return <p className="empty">Aucune CVE détectée sur cet appareil.</p>;
                      return <DeviceVulnTable vulns={list} onSelectCve={setSelectedCve} />;
                    })()}
                  </div>
                ))}

              {activePane === "alerts" &&
                (!defender.found ? (
                  <MissingPane system="Defender" icon={<IconShield />} error={defender.error} />
                ) : (
                  <>
                    <div className="card device-content-card">
                      <div className="card-head">
                        <h2>Alertes</h2>
                      </div>
                      {(() => {
                        const alerts = cleanAlerts(defender);
                        if (alerts.length === 0) return <p className="empty">Aucune alerte sur cette machine.</p>;
                        return (
                          <>
                            <AlertGroups alerts={alerts} />
                            <p className="card-note vuln-search-hint">Clique une alerte pour voir le détail complet.</p>
                          </>
                        );
                      })()}
                    </div>

                    {/* Événements suspects Vanitas (jalon "détection d'activités suspectes sur
                        les postes", 2026-09-14) — dégradé silencieusement si le compte connecté
                        n'a aucun profil Vanitas donnant accès au module "activites_suspectes"
                        (403), ce bloc reste un complément, pas le cœur de la page "Appareil". */}
                    {!vanitasSuspiciousEvents.state.error && (
                      <div className="card device-content-card" style={{ marginTop: "16px" }}>
                        <div className="card-head">
                          <h2>Événements suspects (Vanitas)</h2>
                          <span className="card-note">
                            Télémétrie comportementale de l'agent Vanitas pour ce poste, si enrôlé
                          </span>
                        </div>
                        {vanitasSuspiciousEvents.state.status === "loading" ? (
                          <p className="empty">Chargement…</p>
                        ) : deviceSuspiciousEvents.length === 0 ? (
                          <p className="empty">
                            Aucun événement suspect Vanitas pour ce poste (ou poste non enrôlé Vanitas).
                          </p>
                        ) : (
                          <SuspiciousEventsTable
                            events={deviceSuspiciousEvents}
                            onSelect={setSelectedSuspiciousEvent}
                            showHost={false}
                          />
                        )}
                      </div>
                    )}
                  </>
                ))}

              {activePane === "apps" &&
                (!intune.found ? (
                  <MissingPane system="Intune" icon={<IconLaptop />} error={intune.error} />
                ) : (
                  <div className="card device-content-card">
                    <div className="card-head">
                      <h2>Applications détectées</h2>
                      <span className="card-note">Inventaire logiciel de l'appareil, pas le statut de déploiement par app</span>
                    </div>
                    <AppsPane apps={intune.detectedApps} />
                  </div>
                ))}
            </div>
          </div>
        </>
      )}

      {selectedCve && (
        <CveDetailModal
          row={selectedCve}
          onClose={() => setSelectedCve(null)}
          anssiState={undefined}
          deviceScope={result?.deviceName}
        />
      )}

      {selectedSuspiciousEvent && (
        <SuspiciousEventDetailModal
          event={selectedSuspiciousEvent}
          onClose={() => setSelectedSuspiciousEvent(null)}
          onUpdated={(updated) => {
            setSelectedSuspiciousEvent(updated);
            vanitasSuspiciousEvents.refresh();
          }}
        />
      )}
    </>
  );
}

/** Carte "Système d'exploitation" — combine Intune (`operatingSystem`/`osVersion`) et Defender
 * (`osBuild`/`osArchitecture`), champs déjà chargés des deux côtés (aucun nouvel appel). */
function OsCard({ intune, defender }) {
  if (!intune.found && !defender.found) return null;
  const d = intune.found ? intune.device : null;
  const m = defender.found ? defender.machine : null;
  return (
    <div className="device-spec-card">
      <div className="device-spec-card-head">
        <span className="device-spec-icon tone-star">
          <IconLaptop />
        </span>
        <span className="device-spec-card-title">Système d'exploitation</span>
      </div>
      <div className="device-spec-mini-grid">
        <div className="device-spec-mini">
          <span className="k">Famille</span>
          <span className="v">{d?.operatingSystem || m?.osPlatform || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Version</span>
          <span className="v">{d?.osVersion || m?.osVersion || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Build</span>
          <span className="v mono">{m?.osBuild || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Architecture</span>
          <span className="v">{m?.osArchitecture || "—"}</span>
        </div>
      </div>
      {!intune.found && <p className="card-note" style={{ marginTop: 10 }}>Intune non trouvé pour cet appareil — champs Defender uniquement.</p>}
      {!defender.found && <p className="card-note" style={{ marginTop: 10 }}>Defender non trouvé pour cet appareil — champs Intune uniquement.</p>}
    </div>
  );
}

/** Carte "Matériel" — modèle/série/stockage/mémoire/chiffrement, uniquement des champs Intune
 * (déjà fetchés par `get_device` sans `$select`, jamais de nouvel appel). */
function HwCard({ intune }) {
  if (!intune.found) return <MissingPane system="Intune" icon={<IconLaptop />} error={intune.error} />;
  const d = intune.device;
  const encrypted = boolBadge(d.isEncrypted);
  const jailbroken = boolBadge(d.jailBroken, { trueLabel: "Oui (root/jailbreak détecté)", goodWhenTrue: false });
  const ownerLabel = { company: "Entreprise", personal: "Personnel" }[d.ownerType] || d.ownerType || "—";
  const hasStorage = Boolean(d.totalStorageSpaceInBytes);
  const usedPct = hasStorage
    ? Math.max(0, Math.min(100, Math.round(((d.totalStorageSpaceInBytes - (d.freeStorageSpaceInBytes || 0)) / d.totalStorageSpaceInBytes) * 100)))
    : 0;

  return (
    <div className="device-spec-card">
      <div className="device-spec-card-head">
        <span className="device-spec-icon tone-neutral">
          <IconLaptop />
        </span>
        <span className="device-spec-card-title">Matériel</span>
      </div>
      <div className="device-spec-mini-grid">
        <div className="device-spec-mini">
          <span className="k">Modèle</span>
          <span className="v">{[d.manufacturer, d.model].filter(Boolean).join(" ") || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">N° série</span>
          <span className="v mono">{d.serialNumber || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Mémoire</span>
          <span className="v">{fmtBytes(d.physicalMemoryInBytes)}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Type de propriété</span>
          <span className="v">{ownerLabel}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Chiffrement</span>
          <span className="v" style={{ color: encrypted.color }}>{encrypted.label}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Root / jailbreak</span>
          <span className="v" style={{ color: jailbroken.color }}>{jailbroken.label}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Inscrit le</span>
          <span className="v mono" style={{ fontSize: 12 }}>{fmtDate(d.enrolledDateTime)}</span>
        </div>
        {hasStorage && (
          <div className="device-spec-mini full">
            <span className="k">Stockage</span>
            <div className="device-bar-track">
              <div className="device-bar-fill" style={{ width: `${usedPct}%` }} />
            </div>
            <div className="device-bar-caption">
              <span>{fmtBytes(d.totalStorageSpaceInBytes - (d.freeStorageSpaceInBytes || 0))} utilisés</span>
              <span>{fmtBytes(d.freeStorageSpaceInBytes)} libres / {fmtBytes(d.totalStorageSpaceInBytes)}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/** Carte "Identité & réseau" — sync/RBAC/jonction Entra/IP/tags/criticité, combine Intune et
 * Defender. `ipAddresses`/`machineTags`/`deviceValue`/`managementAgent` confirmés réels en
 * direct contre le tenant de production le 2026-09-02 (voir docstring de fichier). */
function IdentityCard({ intune, defender }) {
  if (!intune.found && !defender.found) return null;
  const d = intune.found ? intune.device : null;
  const m = defender.found ? defender.machine : null;
  const isAadJoined = m ? boolBadge(m.isAadJoined) : null;
  const ip = m ? primaryIpAddress(m) : null;
  const tags = Array.isArray(m?.machineTags) ? m.machineTags : [];

  return (
    <div className="device-spec-card">
      <div className="device-spec-card-head">
        <span className="device-spec-icon tone-low">
          <IconGauge />
        </span>
        <span className="device-spec-card-title">Identité &amp; réseau</span>
      </div>
      <div className="device-spec-mini-grid">
        <div className="device-spec-mini">
          <span className="k">Sync. Intune</span>
          <span className="v">{d?.lastSyncDateTime ? fmtRelative(d.lastSyncDateTime) : "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Contact Defender</span>
          <span className="v">{m?.lastSeen ? fmtRelative(m.lastSeen) : "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Adresse IP</span>
          <span className="v mono">{ip || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Groupe RBAC</span>
          <span className="v">{m?.rbacGroupName || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Jonction Entra</span>
          <span className="v" style={isAadJoined ? { color: isAadJoined.color } : undefined}>{isAadJoined?.label || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Gestion</span>
          <span className="v">{d?.managementAgent || d?.managementState || m?.managedBy || "—"}</span>
        </div>
        {/* Santé capteur/Onboarding/Niveau de risque/Identifiant AAD (2026-09-02, retour de
            Nicolas sur un appareil Android — "c'est différent en termes de champs... déjà
            dans defender il le voit pas alors que je le vois") : champs Defender déjà chargés
            (_format_machine_detail) mais jamais affichés nulle part depuis la refonte v3 — pour
            un appareil Defender-seul (Intune non trouvé), c'était la SEULE info manquante entre
            "Exposition"/"Criticité" (déjà en tuile) et rien du tout. */}
        <div className="device-spec-mini">
          <span className="k">Santé capteur</span>
          <span className="v">{m?.healthStatus || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Onboarding</span>
          <span className="v">{m?.onboardingStatus || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Niveau de risque</span>
          <span className="v">{m?.riskScore || "—"}</span>
        </div>
        <div className="device-spec-mini">
          <span className="k">Identifiant AAD</span>
          <span className="v mono" style={{ fontSize: 11 }}>{m?.aadDeviceId || d?.azureADDeviceId || "—"}</span>
        </div>
        {tags.length > 0 && (
          <div className="device-spec-mini full">
            <span className="k">Tags Defender</span>
            <div className="device-tag-row">
              {tags.map((t) => (
                <span key={t} className="device-tag">{t}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
