import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { useAuth } from "../AuthContext.jsx";
import { isErrorPayload, useVanitasAgentPackages, useVanitasSuspiciousEvents } from "../hooks/useDashboardData.js";
import { useShellSession } from "../hooks/useShellSession.js";
import { SuspiciousEventDetailModal, SuspiciousEventsTable } from "./VanitasSuspiciousActivityTab.jsx";
import VanitasEventLogPane from "./VanitasEventLogPane.jsx";
import { CveDetailModal } from "./VanitasVulnerabilitiesTab.jsx";
import {
  CERT_VALIDITY_DAYS,
  CommandForm,
  COMMAND_LABELS,
  ConfirmButton,
  compareVersions,
  daysUntil,
  fmtBytes,
  fmtDate,
  fmtDateTime,
  fmtRelative,
  hasVanitasAccess,
  isOnline,
  LATEST_AGENT_VERSION,
  latestCommandOf,
  latestCommandResult,
  severityLabelFr,
  severityTone,
  summarizeGroupRules,
  VanitasWizardShell,
} from "./vanitasShared.jsx";
import { currentLocale, localizedTable, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

const TONE_VAR = { low: "var(--low)", medium: "var(--amber)", high: "var(--high)", star: "var(--star)" };

// Garde-fou de rendu : certains produits très communs (navigateurs, Adobe Acrobat...) peuvent
// remonter des dizaines de milliers de CVE historiques (le rapprochement du jalon 2 ne filtre
// pas par date/version à l'affichage, voir cve_matching.py) — jamais poser ça d'un coup dans le
// DOM, même motif "Afficher N de plus" déjà établi ailleurs dans ce dashboard
// (VulnerabilitiesTab.jsx::REVEAL_STEP).
const VULN_REVEAL_STEP = 100;

// Ordre d'affichage des pastilles de filtre (2026-09-11, "un truc cliquable sur la vuln comme
// dans l'onglet vuln de base") — même ordre que `SEVERITY_ORDER` de
// `VanitasVulnerabilitiesTab.jsx` (dupliqué plutôt qu'importé : c'est une constante locale non
// exportée là-bas, pas une fonction partagée).
const VULN_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function certTone(days) {
  if (days === null) return null;
  if (days < 0) return "high";
  if (days < 30) return "medium";
  return "low";
}

const CERT_STATE_LABEL = localizedTable("vdd.cert", ["high", "medium", "low"]);

function certStateLabel(days) {
  return CERT_STATE_LABEL[certTone(days)] ?? tr("common.unknown");
}

// "Historique des commandes" (2026-09-11, "mettre la commande puis quand on clique mettre
// l'affichage de celui-ci") — `success === false` prime sur `status` : le serveur peut encore
// marquer une commande `completed` alors que l'agent a rapporté un échec métier (ex. installeur
// introuvable), jamais "Terminée" dans ce cas.
function commandTone(c) {
  if (c.status === "pending" || c.status === "running") return "medium";
  if (c.status === "failed" || c.success === false) return "high";
  return "low";
}

const COMMAND_STATE_LABEL = localizedTable("vdd.cmd", ["medium", "high", "low"]);

function commandStateLabel(c) {
  return COMMAND_STATE_LABEL[commandTone(c)];
}

// "Conformité" (2026-09-11, "revoir la page Conformité") — `compliant` est tri-état
// (`ComplianceResult.compliant`, nullable) : `null` = erreur d'exécution du script, jamais
// confondu avec `false` (contrôle qui a tourné et trouvé un problème).
function complianceRuleTone(r) {
  if (r.compliant === true) return "low";
  if (r.compliant === false) return "high";
  return "medium";
}

const COMPLIANCE_RULE_LABEL = localizedTable("vdd.rule", ["low", "high", "medium"]);

function complianceRuleLabel(r) {
  return COMPLIANCE_RULE_LABEL[complianceRuleTone(r)];
}

// Le résultat/les paramètres d'une commande sont du JSON brut pour la plupart des types
// (system_diagnostic/check_windows_updates/hardware_inventory, voir CommandExecutor.cs), mais
// une phrase en clair pour d'autres (ex. uninstall_agent) — jamais supposer un format unique,
// tenter le parsing et retomber sur le texte brut sans planter sinon.
function prettyCommandText(raw) {
  if (!raw) return null;
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

function diskTone(pct) {
  if (pct === null) return null;
  if (pct >= 90) return "high";
  if (pct >= 75) return "medium";
  return "low";
}

// Panneau "Matériel" (2026-09-11, retour de Nicolas — "possible d'avoir plus d'information ?")
// — `Win32_DiskDrive.MediaType` ne distingue PAS SSD/HDD de façon fiable (vérifié en direct
// contre le vrai poste : un SSD NVMe réel ET un vrai disque mécanique renvoient tous les deux
// "Fixed hard disk media") — traduction du libellé WMI brut, jamais un badge SSD/HDD inventé.
// Une valeur WMI absente de cette table s'affiche telle quelle plutôt que masquée.
const DISK_MEDIA_LABEL = localizedTable("vdd.disk", ["Fixed hard disk media", "Removable Media", "External hard disk media"]);

function diskMediaLabel(mediaType) {
  if (!mediaType) return null;
  return DISK_MEDIA_LABEL[mediaType] ?? mediaType;
}

// Périphériques PCI — `Status` WMI (2026-09-11) : "OK" = fonctionne normalement, toute autre
// valeur ("Error"/"Degraded"/"Unknown"...) affichée telle quelle avec un badge rouge, même
// esprit que le triangle jaune du Gestionnaire de périphériques Windows.
function pciStatusTone(status) {
  if (!status) return null;
  return status === "OK" ? "low" : "high";
}

// "suspicious": même journal que l'onglet transverse, filtré sur cet agent (2026-09-14).
// "event-log": recherche PONCTUELLE à la demande (2026-09-16), voir VanitasEventLogPane.jsx.
// Labels and group names are getters, read in the current interface language.
const NAV_ITEMS = [
  {
    key: "overview",
    get label() {
      return tr("vdd.nav.overview");
    },
  },
  {
    get group() {
      return tr("vdd.nav.system");
    },
    items: [
      {
        key: "os",
        get label() {
          return tr("vdd.nav.os");
        },
      },
      {
        key: "hardware",
        get label() {
          return tr("vdd.nav.hardware");
        },
      },
      {
        key: "network",
        get label() {
          return tr("vdd.nav.network");
        },
      },
    ],
  },
  {
    get group() {
      return tr("vdd.nav.security");
    },
    items: [
      {
        key: "cert",
        get label() {
          return tr("vdd.nav.cert");
        },
      },
      {
        key: "vulns",
        get label() {
          return tr("vdd.nav.vulns");
        },
      },
      {
        key: "compliance",
        get label() {
          return tr("vdd.nav.compliance");
        },
      },
      {
        key: "suspicious",
        get label() {
          return tr("vdd.nav.suspicious");
        },
      },
      {
        key: "event-log",
        get label() {
          return tr("vdd.nav.event-log");
        },
      },
    ],
  },
  {
    get group() {
      return tr("vdd.nav.inventory");
    },
    items: [
      {
        key: "apps",
        get label() {
          return tr("vdd.nav.apps");
        },
      },
    ],
  },
  {
    get group() {
      return tr("vdd.nav.administration");
    },
    items: [
      {
        key: "commands",
        get label() {
          return tr("vdd.nav.commands");
        },
      },
      {
        key: "terminal",
        get label() {
          return tr("vdd.nav.terminal");
        },
      },
    ],
  },
];

/**
 * Popup de détail d'une commande (2026-09-11, "mettre la commande puis quand on clique mettre
 * l'affichage de celui-ci") — même chrome `VanitasWizardShell` que `CveDetailModal`
 * (VanitasVulnerabilitiesTab.jsx). `result`/`parameters` mis en forme en JSON indenté quand ça
 * parse, sinon affichés tels quels (voir `prettyCommandText`) — certains types de commande
 * renvoient une phrase en clair, pas du JSON.
 */
function CommandDetailModal({ command, hostname, onClose }) {
  const tone = commandTone(command);
  const prettyResult = prettyCommandText(command.result);
  const prettyParams = prettyCommandText(command.parameters);
  return (
    <VanitasWizardShell onClose={onClose}>
      <div className="vanitas-wiz-header">
        <div className="vanitas-wiz-header-icon">
          <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6">
            <rect x="3" y="4" width="14" height="10" rx="1.5" />
            <path d="M7 17h6M10 14v3" strokeLinecap="round" />
          </svg>
        </div>
        <div className="vanitas-wiz-header-text">
          <h2>{COMMAND_LABELS[command.command_type] ?? command.command_type}</h2>
          <p>Vanitas · {hostname}</p>
        </div>
      </div>

      <div className="vanitas-wiz-body">
        <div className="vanitas-cmd-detail-meta">
          <span className={`vanitas-cmd-detail-status-pill ${tone}`}>{commandStateLabel(command)}</span>
          <span className="vanitas-cmd-detail-meta-item">
            {trRich("vdd.launchedBy", { who: <b>{command.actor ?? tr("vdd.unknownActor")}</b> })}
          </span>
          <span className="vanitas-cmd-detail-meta-item">
            {trRich("vdd.launchedOn", { date: <b>{fmtDateTime(command.created_at)}</b> })}
          </span>
          {command.completed_at && (
            <span className="vanitas-cmd-detail-meta-item">
              {trRich("vdd.completedOn", { date: <b>{fmtDateTime(command.completed_at)}</b> })}
            </span>
          )}
        </div>

        {prettyParams && (
          <>
            <p className="vanitas-cmd-detail-section-title">{tr("vdd.parameters")}</p>
            <pre className="vanitas-cmd-detail-pre">{prettyParams}</pre>
          </>
        )}

        <p className="vanitas-cmd-detail-section-title">{tr("vdd.result")}</p>
        {prettyResult ? (
          <pre className="vanitas-cmd-detail-pre">{prettyResult}</pre>
        ) : (
          <p className="vanitas-hud-empty-note" style={{ padding: "8px 0" }}>
            {tr("vdd.noResult")}
          </p>
        )}
      </div>
    </VanitasWizardShell>
  );
}

/**
 * Fiche poste Vanitas (jalon 6) — remplace l'ancien rail étroit par une vraie page de détail,
 * même esprit que DeviceOverviewTab.jsx côté Intune (hero + bandeau de santé cliquable + nav
 * latérale groupée + panneaux). Reçoit `inv`/`vulns`/`commands` déjà chargés par le parent
 * (VanitasDevicesTab.jsx, via les hooks `useKeyedFetch` mis en cache) — ce composant ne fait
 * aucun appel réseau lui-même, seulement de la présentation + un état LOCAL `activePane`.
 *
 * "Matériel"/"Identité & réseau" consomment le résultat de la commande "hardware_inventory"
 * (jalon 6, `HardwareInventoryCollector.cs` côté agent) — jamais de donnée fabriquée : tant
 * que cette commande n'a pas encore tourné sur le poste, l'état vide honnête reste affiché
 * (même motif que "Diagnostic système"/"Windows Update" avant elle).
 */
export default function VanitasDeviceDetail({
  agent,
  inv,
  vulns,
  compliance,
  commands,
  groups,
  onGroupChanged,
  onQueued,
  onBack,
  onRemoved,
}) {
  // Terminal PowerShell interactif + "Retirer de l'inventaire" gouvernés par les profils
  // Vanitas (2026-09-10, remplace l'ancien blanket `isAdmin` du 2026-09-07) — l'application
  // RÉELLE de la règle reste côté serveur (`require_vanitas_write("terminal"/"postes")`,
  // api_server.py), ce masquage/ces gardes ici ne sont qu'un confort d'UI. L'UI du terminal
  // n'a qu'un mode interactif (ouvrir/piloter une session) — aucune vue "lecture seule" n'existe
  // encore, donc un profil "terminal: lecture" seul ne voit pas cet onglet non plus (même
  // condition que l'écriture) ; le module distingue déjà lecture/écriture côté serveur pour un
  // futur historique de sessions en lecture seule.
  const { user } = useAuth();
  const canWriteTerminal = hasVanitasAccess(user, "terminal", "write");
  const canWritePostes = hasVanitasAccess(user, "postes", "write");
  // Mise à jour de l'agent (2026-09-11, revu le même jour — "je veux que le bouton quand je
  // vais dans un poste") — même module que `install_application` côté serveur
  // (`require_vanitas_write("applications")`), pas de module Vanitas "agent" dédié.
  const canWriteApplications = hasVanitasAccess(user, "applications", "write");
  const [activePane, setActivePane] = useState("overview");
  const [appsFilter, setAppsFilter] = useState("");
  const [vulnVisibleCount, setVulnVisibleCount] = useState(VULN_REVEAL_STEP);
  const [vulnQuery, setVulnQuery] = useState("");
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState("all");
  const [selectedVulnCveId, setSelectedVulnCveId] = useState(null);
  const [selectedCommandId, setSelectedCommandId] = useState(null);
  const [selectedSuspiciousEvent, setSelectedSuspiciousEvent] = useState(null);
  const [lifecycleBusy, setLifecycleBusy] = useState(false);
  const [lifecycleError, setLifecycleError] = useState(null);
  // Groupes (2026-09-08) — état local uniquement pour l'erreur de cette action précise, jamais
  // mêlé à `lifecycleError` (désinstaller/retirer) qui déclenche une navigation différente.
  const [groupBusy, setGroupBusy] = useState(false);
  const [groupError, setGroupError] = useState(null);

  // Mise à jour de l'agent (2026-09-11, revu — la page dédiée "Mise à jour de l'agent" a été
  // retirée : le catalogue d'upload vit désormais dans "Applications"
  // (VanitasInstallersTab.jsx), le déclenchement se fait ICI, sur la fiche du poste concerné.
  // Chargé par CE composant lui-même (pas passé en prop par le parent) — même précédent déjà
  // en place sur `VanitasGroupDetail.jsx` pour le même catalogue, cache partagé donc aucun
  // coût réseau supplémentaire si l'admin a déjà visité "Applications" avant.
  const agentPackages = useVanitasAgentPackages();
  const [updateBusy, setUpdateBusy] = useState(false);
  const [updateError, setUpdateError] = useState(null);
  const [updateQueued, setUpdateQueued] = useState(false);

  useEffect(() => {
    agentPackages.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Pane "Activités suspectes" (jalon "détection d'activités suspectes sur les postes",
  // 2026-09-14) — même hook que l'onglet transverse, filtré ici sur CET agent. Chargé par ce
  // composant lui-même (même précédent que `agentPackages` juste au-dessus), volontairement
  // sans le cache partagé de 2h (voir `useVanitasSuspiciousEvents`) : un journal de triage doit
  // rester frais à chaque ouverture de la fiche poste.
  const suspiciousEvents = useVanitasSuspiciousEvents(useMemo(() => ({ agentId: agent.id }), [agent.id]));

  const latestAgentPackage = agentPackages.state.data[0] ?? null;
  const agentVersionCmp = latestAgentPackage ? compareVersions(agent.agent_version, latestAgentPackage.version) : null;
  const agentIsOutdated = agentVersionCmp !== null && agentVersionCmp < 0;
  // Statut affiché sur la tuile "Agent" (2026-09-11, retour de Nicolas) — comparé au CODE
  // SOURCE (`LATEST_AGENT_VERSION`), pas au catalogue de paquets uploadés : Nicolas ne pousse
  // pas systématiquement un paquet dans "Applications" à chaque changement, ce sont surtout des
  // modifications faites côté code. Le catalogue (`latestAgentPackage`/`agentIsOutdated`
  // ci-dessus) reste la seule chose qui pilote le bouton "Mettre à jour maintenant" — un push
  // réel a toujours besoin d'un binaire réellement uploadé, cette comparaison-ci est purement
  // informative.
  const sourceVersionCmp = compareVersions(agent.agent_version, LATEST_AGENT_VERSION);
  const agentBehindSource = sourceVersionCmp !== null && sourceVersionCmp < 0;

  async function handleUpdateAgent() {
    if (!latestAgentPackage || updateBusy) return;
    setUpdateBusy(true);
    setUpdateError(null);
    try {
      const payload = await api.vanitas.queueCommand(agent.id, "update_agent", null, latestAgentPackage.id);
      if (isErrorPayload(payload)) {
        setUpdateError(payload.message);
      } else {
        setUpdateQueued(true);
        onQueued();
      }
    } catch (err) {
      setUpdateError(err.message);
    } finally {
      setUpdateBusy(false);
    }
  }

  // Terminal PowerShell interactif (jalon 9) — `shellQueuedAt` marque le moment où
  // "start_shell_session" a été mise en file (le dashboard ne connaît pas encore l'id de
  // session à cet instant, l'agent ne la crée réellement qu'à sa prochaine récupération de
  // commande, jusqu'à ~5 min plus tard, même délai que les 6 autres commandes). `shellSessionId`
  // reste `null` tant qu'une session plus récente que `shellQueuedAt` n'a pas été découverte via
  // `latestShellSession` — voir l'effet ci-dessous.
  const [shellQueuedAt, setShellQueuedAt] = useState(null);
  const [shellSessionId, setShellSessionId] = useState(null);
  const [shellStartError, setShellStartError] = useState(null);
  const [terminalInput, setTerminalInput] = useState("");
  const shell = useShellSession(shellSessionId);
  // Garde-fou anti-double-soumission : un `ref` plutôt qu'un `useState`, exprès — il se met à
  // jour de façon SYNCHRONE (contrairement à un état React, dont le nouveau rendu — donc le
  // bouton désactivé — n'est commis qu'au prochain repaint). Sans lecture ni écriture d'aucun
  // état pour l'aiguiller, un double Entrée/double clic assez rapproché pour tomber DANS cette
  // fenêtre (avant que React n'ait eu le temps de désactiver le bouton) enverrait sinon deux
  // fois la même ligne — signalé par Nicolas ("double soumission des commandes").
  const shellSendingRef = useRef(false);

  async function handleTerminalSubmit(e) {
    e.preventDefault();
    const line = terminalInput.trim();
    if (!line || shellSendingRef.current) return;
    shellSendingRef.current = true;
    setTerminalInput("");
    try {
      await shell.sendLine(line);
    } finally {
      shellSendingRef.current = false;
    }
  }

  useEffect(() => {
    if (!shellQueuedAt || shellSessionId) return undefined;
    let cancelled = false;

    async function poll() {
      const payload = await api.vanitas.latestShellSession(agent.id);
      if (cancelled || isErrorPayload(payload) || !payload) return;
      if (new Date(payload.started_at) >= shellQueuedAt && payload.status === "active") {
        setShellSessionId(payload.id);
      }
    }

    poll();
    const interval = setInterval(poll, 3000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [shellQueuedAt, shellSessionId, agent.id]);

  const appsList = inv?.data?.apps ?? [];
  const vulnList = vulns?.data ?? [];
  const commandList = commands.data ?? [];
  const complianceList = compliance?.data?.results ?? [];
  const selectedCommand = selectedCommandId ? commandList.find((c) => c.id === selectedCommandId) ?? null : null;

  const diagnostic = useMemo(() => latestCommandResult(commandList, "system_diagnostic"), [commandList]);
  const diagnosticCommand = useMemo(() => latestCommandOf(commandList, "system_diagnostic"), [commandList]);
  const windowsUpdate = useMemo(() => latestCommandResult(commandList, "check_windows_updates"), [commandList]);
  const windowsUpdateCommand = useMemo(() => latestCommandOf(commandList, "check_windows_updates"), [commandList]);
  const hardware = useMemo(() => latestCommandResult(commandList, "hardware_inventory"), [commandList]);
  const hardwareCommand = useMemo(() => latestCommandOf(commandList, "hardware_inventory"), [commandList]);

  const pciByCategory = useMemo(() => {
    const groups = new Map();
    for (const d of hardware?.pci_devices ?? []) {
      const key = d.category ?? tr("vdd.otherCategory");
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(d);
    }
    return Array.from(groups.entries());
  }, [hardware]);

  const diskPct =
    diagnostic?.disk_total_bytes && diagnostic?.disk_free_bytes != null
      ? Math.round((1 - diagnostic.disk_free_bytes / diagnostic.disk_total_bytes) * 100)
      : null;

  const online = isOnline(agent);
  const certDays = daysUntil(agent.cert_not_after);
  const worstVulnTone = vulnList.some((v) => severityTone(v.severity) === "high")
    ? "high"
    : vulnList.length > 0
      ? "medium"
      : "low";
  const commandsLast7d = commandList.filter(
    (c) => (Date.now() - new Date(c.created_at).getTime()) / 86_400_000 <= 7
  ).length;

  // Groupes (2026-09-08) — `groupById` pour résoudre `agent.group_ids` en badges nommés,
  // `staticGroups` pour la liste des groupes affectables (jamais un groupe DYNAMIQUE).
  const groupById = useMemo(() => {
    const map = new Map();
    for (const g of groups ?? []) map.set(g.id, g);
    return map;
  }, [groups]);
  const staticGroups = useMemo(() => (groups ?? []).filter((g) => !g.rules), [groups]);
  const agentGroupIds = agent.group_ids ?? [];

  const filteredApps = useMemo(() => {
    const q = appsFilter.trim().toLowerCase();
    if (!q) return appsList;
    return appsList.filter((a) => a.name?.toLowerCase().includes(q) || a.publisher?.toLowerCase().includes(q));
  }, [appsList, appsFilter]);

  // Pastille cliquable sur une vuln, comme sur l'onglet "Vulnérabilités" fleet-wide (2026-09-11)
  // — `vulnGroups` regroupe les entrées de CE poste par CVE (une CVE peut toucher plusieurs
  // produits installés), dans la même forme que `CveDetailModal` (VanitasVulnerabilitiesTab.jsx)
  // attend déjà pour la vue fleet-wide. `deviceScope` (passé au rendu, voir plus bas) masque la
  // section "Appareils exposés" de la popup — redondante ici, le lecteur est déjà sur ce poste.
  const vulnGroups = useMemo(() => {
    const byCve = new Map();
    for (const v of vulnList) {
      if (!v.cve_id) continue;
      let g = byCve.get(v.cve_id);
      if (!g) {
        g = {
          cve_id: v.cve_id,
          cvss_score: v.cvss_score,
          severity: v.severity,
          published: v.published,
          products: [],
          productKeys: new Set(),
          devices: [],
        };
        byCve.set(v.cve_id, g);
      }
      const productKey = `${v.product_name}::${v.installed_version || ""}`;
      if (!g.productKeys.has(productKey)) {
        g.productKeys.add(productKey);
        g.products.push({ name: v.product_name, version: v.installed_version });
      }
      g.devices.push({
        agentId: agent.id,
        hostname: agent.hostname,
        product_name: v.product_name,
        installed_version: v.installed_version,
        version_affected: v.version_affected,
      });
    }
    return byCve;
  }, [vulnList, agent.id, agent.hostname]);

  const selectedVulnGroup = selectedVulnCveId ? vulnGroups.get(selectedVulnCveId) ?? null : null;

  const vulnSeverityCounts = useMemo(() => {
    const counts = { all: vulnList.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const v of vulnList) {
      const s = (v.severity || "").toUpperCase();
      if (counts[s] !== undefined) counts[s]++;
    }
    return counts;
  }, [vulnList]);

  const filteredVulnList = useMemo(() => {
    const q = vulnQuery.trim().toLowerCase();
    return vulnList.filter((v) => {
      if (vulnSeverityFilter !== "all" && (v.severity || "").toUpperCase() !== vulnSeverityFilter) return false;
      if (!q) return true;
      return v.cve_id.toLowerCase().includes(q) || v.product_name?.toLowerCase().includes(q);
    });
  }, [vulnList, vulnQuery, vulnSeverityFilter]);

  function goto(pane) {
    setActivePane(pane);
  }

  async function handleUninstall() {
    setLifecycleBusy(true);
    setLifecycleError(null);
    try {
      const payload = await api.vanitas.queueCommand(agent.id, "uninstall_agent");
      if (isErrorPayload(payload)) {
        setLifecycleError(payload.message);
      } else {
        onQueued();
        goto("commands");
      }
    } catch (err) {
      setLifecycleError(err.message);
    } finally {
      setLifecycleBusy(false);
    }
  }

  async function handleStartShell() {
    setShellStartError(null);
    try {
      const payload = await api.vanitas.queueCommand(agent.id, "start_shell_session");
      if (isErrorPayload(payload)) {
        setShellStartError(payload.message);
        return;
      }
      setShellSessionId(null);
      setShellQueuedAt(new Date());
      onQueued();
    } catch (err) {
      // Filet de sécurité — ex. un compte viewer atteignant ce bouton malgré le masquage
      // ci-dessous (session redevenue viewer entre-temps) : postJSON lève sur un 403,
      // jamais rattrapé par isErrorPayload (réservé au contrat {error:true,...} en HTTP 200).
      setShellStartError(err.message);
    }
  }

// Groupes (2026-09-08, many-to-many) — un poste peut appartenir à PLUSIEURS groupes STATIQUES
  // à la fois ; les groupes DYNAMIQUES (motif) n'ont jamais d'affectation manuelle possible.
  async function handleAddToGroup(groupId) {
    if (!groupId) return;
    setGroupBusy(true);
    setGroupError(null);
    try {
      const payload = await api.vanitas.addAgentToGroup(agent.id, groupId);
      if (isErrorPayload(payload)) {
        setGroupError(payload.message);
      } else {
        onGroupChanged();
      }
    } catch (err) {
      setGroupError(err.message);
    } finally {
      setGroupBusy(false);
    }
  }

  async function handleRemoveFromGroup(groupId) {
    setGroupBusy(true);
    setGroupError(null);
    try {
      const payload = await api.vanitas.removeAgentFromGroup(agent.id, groupId);
      if (isErrorPayload(payload)) {
        setGroupError(payload.message);
      } else {
        onGroupChanged();
      }
    } catch (err) {
      setGroupError(err.message);
    } finally {
      setGroupBusy(false);
    }
  }

  async function handleRemoveFromInventory() {
    setLifecycleBusy(true);
    setLifecycleError(null);
    try {
      const payload = await api.vanitas.removeAgent(agent.id);
      if (isErrorPayload(payload)) {
        setLifecycleError(payload.message);
        setLifecycleBusy(false);
      } else {
        onRemoved();
      }
    } catch (err) {
      setLifecycleError(err.message);
      setLifecycleBusy(false);
    }
  }

  return (
    <div>
      <button type="button" className="vanitas-detail-back" onClick={onBack}>
        {tr("vdd.back")}
      </button>

      <div className="vanitas-detail-hero">
        <div className="vanitas-detail-identity">
          <div className={`vanitas-detail-dot${online ? "" : " offline"}`} />
          <div>
            <p className="vanitas-detail-name">{agent.hostname}</p>
            <div className="vanitas-detail-hero-sub">
              <span>{trRich("vdd.seen", { status: tr(online ? "vdd.online" : "vdd.silent"), when: <b>{fmtRelative(agent.last_seen)}</b> })}</span>
              <span>{trRich("vdd.enrolledOn", { date: <b>{fmtDate(agent.enrolled_at)}</b> })}</span>
              <span>{trRich("vdd.appsCount", { n: <b>{agent.apps_count}</b> })}</span>
            </div>
          </div>
        </div>
        <div className="vanitas-detail-hero-actions">
          <ConfirmButton
            label={tr("vdd.uninstall")}
            confirmLabel={tr("vdd.uninstallConfirm")}
            className="vanitas-danger-btn"
            disabled={lifecycleBusy}
            onConfirm={handleUninstall}
          />
          {/* Masqué pour un compte sans "postes" en écriture (revue de sécurité du 2026-09-07,
              généralisée aux profils Vanitas le 2026-09-10) — `DELETE /api/vanitas/agents/{id}`
              exige cette permission côté serveur (`require_vanitas_write("postes")`,
              api_server.py), ce bouton laissait sinon confirmer un retrait qui échouait ensuite
              en 403, une action sans issue plutôt qu'une simple absence. */}
          {canWritePostes && (
            <ConfirmButton
              label={tr("vdd.removeInventory")}
              confirmLabel={tr("vdd.removeConfirm")}
              className="vanitas-danger-btn"
              disabled={lifecycleBusy}
              onConfirm={handleRemoveFromInventory}
              title={tr("vdd.removeTitle")}
            />
          )}
        </div>
      </div>
      {lifecycleError && <p className="error-note" style={{ marginTop: "-8px", marginBottom: "16px" }}>{lifecycleError}</p>}

      <div className="vanitas-health-strip">
        <button
          type="button"
          className={`vanitas-health-tile${activePane === "cert" ? " active" : ""}`}
          style={{ "--tile-accent": TONE_VAR[certTone(certDays) ?? "star"] }}
          onClick={() => goto("cert")}
        >
          <div className="vanitas-health-label">{tr("vdd.tile.cert")}</div>
          <div className={`vanitas-health-value ${certTone(certDays) ?? "star"}`}>
            {certDays === null ? "—" : tr("vdd.days", { n: Math.max(0, Math.round(certDays)) })}
          </div>
        </button>
        <button
          type="button"
          className={`vanitas-health-tile${activePane === "vulns" ? " active" : ""}`}
          style={{ "--tile-accent": TONE_VAR[worstVulnTone] }}
          onClick={() => goto("vulns")}
        >
          <div className="vanitas-health-label">{tr("vdd.tile.vulns")}</div>
          <div className={`vanitas-health-value ${worstVulnTone}`}>{vulnList.length.toLocaleString(currentLocale())}</div>
        </button>
        <button
          type="button"
          className={`vanitas-health-tile${activePane === "hardware" ? " active" : ""}`}
          style={{ "--tile-accent": TONE_VAR[diskTone(diskPct) ?? "star"] }}
          onClick={() => goto("hardware")}
        >
          <div className="vanitas-health-label">{tr("vdd.tile.disk")}</div>
          <div className={`vanitas-health-value ${diskTone(diskPct) ?? "star"}`}>
            {diskPct === null ? "—" : `${diskPct} %`}
          </div>
        </button>
        <button
          type="button"
          className={`vanitas-health-tile${activePane === "apps" ? " active" : ""}`}
          style={{ "--tile-accent": TONE_VAR.star }}
          onClick={() => goto("apps")}
        >
          <div className="vanitas-health-label">{tr("vdd.tile.apps")}</div>
          <div className="vanitas-health-value star">{appsList.length}</div>
        </button>
        <button
          type="button"
          className={`vanitas-health-tile${activePane === "commands" ? " active" : ""}`}
          style={{ "--tile-accent": TONE_VAR.star }}
          onClick={() => goto("commands")}
        >
          <div className="vanitas-health-label">{tr("vdd.tile.commands")}</div>
          <div className="vanitas-health-value star">{commandsLast7d}</div>
        </button>
      </div>

      <div className="vanitas-detail-layout">
        <nav className="vanitas-detail-nav">
          <button
            type="button"
            className={`vanitas-detail-nav-item${activePane === "overview" ? " active" : ""}`}
            onClick={() => goto("overview")}
          >
            {tr("vdd.nav.overview")}
          </button>
          {NAV_ITEMS.slice(1).map((group) => (
            <div key={group.group}>
              <div className="vanitas-detail-nav-group-label">{group.group}</div>
              {group.items.filter((item) => canWriteTerminal || item.key !== "terminal").map((item) => (
                <button
                  key={item.key}
                  type="button"
                  className={`vanitas-detail-nav-item${activePane === item.key ? " active" : ""}`}
                  onClick={() => goto(item.key)}
                >
                  {item.label}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="vanitas-detail-content">
          {activePane === "overview" && (
            <div className="vanitas-ov-grid">
              <div className="vanitas-ov-tile span-2" style={{ "--tile-accent": "var(--star)" }}>
                <div className="vanitas-ov-tile-head">
                  <div className="vanitas-ov-tile-icon">◆</div>
                  <div className="vanitas-ov-tile-title">{tr("vdd.identity")}</div>
                </div>
                <div className="vanitas-ov-tile-main" style={{ fontSize: "16px" }}>{agent.hostname}</div>
                <div className="vanitas-ov-tile-sub">
                  {diagnostic?.os_version ?? tr("vdd.unknownSystem")}
                  <br />
                  {trRich("vdd.enrolledId", {
                    date: <b>{fmtDate(agent.enrolled_at)}</b>,
                    id: <span style={{ fontFamily: "var(--mono)" }}>{agent.id.slice(0, 8)}…</span>,
                  })}
                </div>
                {/* Groupes (2026-09-08, many-to-many) — point d'entrée principal pour
                    affecter/retirer ce poste de PLUSIEURS groupes STATIQUES à la fois, voir
                    VanitasGroupsTab.jsx pour la vue agrégée par groupe. Les groupes DYNAMIQUES
                    (règle, 2026-09-10) apparaissent en badge distinct, non retirables —
                    "automatique". ⚠️ Limite connue (imbrication, 2026-09-10) : un groupe
                    STATIQUE qui contient ce poste uniquement via un SOUS-GROUPE imbriqué (pas
                    une adhésion directe) affiche quand même un "×" retirable ici, qui n'aurait
                    aucun effet visible (rien à supprimer dans `AgentGroupMembership` pour cette
                    paire) — `group_ids` ne distingue pas encore adhésion directe/héritée. Rare
                    à l'échelle actuelle du parc, pas corrigé dans ce jalon. */}
                <div style={{ marginTop: "10px", display: "flex", flexWrap: "wrap", alignItems: "center", gap: "8px" }}>
                  <span className="vanitas-kv-label" style={{ fontSize: "11px" }}>{tr("vdd.groups")}</span>
                  {agentGroupIds.length === 0 && (
                    <span className="cve-small" style={{ color: "var(--ink-faint)" }}>{tr("vdd.none")}</span>
                  )}
                  {agentGroupIds.map((gid) => {
                    const g = groupById.get(gid);
                    if (!g) return null;
                    const isDynamic = !!g.rules;
                    return (
                      <span
                        key={gid}
                        className="badge"
                        style={{
                          background: isDynamic ? "rgba(231,163,60,0.12)" : "rgba(76,159,224,0.12)",
                          color: isDynamic ? "var(--amber)" : "var(--star)",
                          border: `1px solid ${isDynamic ? "var(--amber-dim)" : "rgba(76,159,224,0.35)"}`,
                          display: "inline-flex",
                          alignItems: "center",
                          gap: "6px",
                        }}
                        title={isDynamic ? tr("vd.dynamicMember", { rule: summarizeGroupRules(g.rules) }) : g.name}
                      >
                        {g.name}
                        {!isDynamic && (
                          <span
                            style={{ cursor: "pointer", opacity: 0.7 }}
                            onClick={() => handleRemoveFromGroup(gid)}
                          >
                            ×
                          </span>
                        )}
                      </span>
                    );
                  })}
                  {staticGroups.filter((g) => !agentGroupIds.includes(g.id)).length > 0 && (
                    <select
                      className="filter-input"
                      style={{ flex: "none", width: "170px" }}
                      value=""
                      onChange={(e) => handleAddToGroup(e.target.value)}
                      disabled={groupBusy}
                    >
                      <option value="">{tr("vdd.addToGroup")}</option>
                      {staticGroups
                        .filter((g) => !agentGroupIds.includes(g.id))
                        .map((g) => (
                          <option key={g.id} value={g.id}>
                            {g.name}
                          </option>
                        ))}
                    </select>
                  )}
                  {groupError && <span className="error-note" style={{ margin: 0 }}>{groupError}</span>}
                </div>
              </div>

              <div className="vanitas-ov-tile" style={{ "--tile-accent": online ? "var(--low)" : "var(--ink-faint)" }}>
                <div className="vanitas-ov-tile-head">
                  <div className="vanitas-ov-tile-icon">●</div>
                  <div className="vanitas-ov-tile-title">{tr("vdd.availability")}</div>
                </div>
                <div className="vanitas-ov-tile-main" style={{ color: online ? "var(--low)" : "var(--ink-faint)" }}>
                  {tr(online ? "vdd.online" : "vdd.silent")}
                </div>
                <div className="vanitas-ov-tile-sub">
                  {trRich("vdd.seenShort", { when: <b>{fmtRelative(agent.last_seen)}</b> })}
                  {diagnostic?.uptime && trRich("vdd.uptimeShort", { uptime: <b>{diagnostic.uptime.split(".")[0]}</b> })}
                </div>
              </div>

              <div className="vanitas-ov-tile" style={{ "--tile-accent": TONE_VAR[certTone(certDays) ?? "star"] }}>
                <div className="vanitas-ov-tile-head">
                  <div className="vanitas-ov-tile-icon">🛡</div>
                  <div className="vanitas-ov-tile-title">{tr("vdd.tile.cert")}</div>
                </div>
                <div className="vanitas-ov-tile-main">
                  {certDays === null ? "—" : Math.max(0, Math.round(certDays))}{" "}
                  <span className="unit">{tr("vdd.daysLeftUnit")}</span>
                </div>
                {certDays !== null && (
                  <div className="vanitas-cert-bar-track" style={{ marginBottom: 0 }}>
                    <div
                      className="vanitas-cert-bar-fill"
                      style={{
                        width: `${Math.max(0, Math.min(100, (certDays / 90) * 100))}%`,
                        background: TONE_VAR[certTone(certDays)],
                      }}
                    />
                  </div>
                )}
                <button type="button" className="vanitas-ov-tile-link" onClick={() => goto("cert")}>
                  {tr("vdd.seeCert")}
                </button>
              </div>

              <div className="vanitas-ov-tile" style={{ "--tile-accent": TONE_VAR[diskTone(diskPct) ?? "star"] }}>
                <div className="vanitas-ov-tile-head">
                  <div className="vanitas-ov-tile-icon">▥</div>
                  <div className="vanitas-ov-tile-title">{tr("vdd.tile.disk")}</div>
                </div>
                <div className="vanitas-ov-tile-main">{diskPct === null ? "—" : `${diskPct} %`}</div>
                <div className="vanitas-ov-tile-sub">
                  {diagnostic
                    ? tr("vdd.freeOf", { free: fmtBytes(diagnostic.disk_free_bytes), total: fmtBytes(diagnostic.disk_total_bytes) })
                    : tr("vdd.noDataDiag")}
                </div>
                <button type="button" className="vanitas-ov-tile-link" onClick={() => goto("hardware")}>
                  {tr("vdd.seeHardware")}
                </button>
              </div>

              <div className="vanitas-ov-tile span-2" style={{ "--tile-accent": TONE_VAR[worstVulnTone] }}>
                <div className="vanitas-ov-tile-head">
                  <div className="vanitas-ov-tile-icon">⚠</div>
                  <div className="vanitas-ov-tile-title">{tr("vdd.tile.vulns")}</div>
                </div>
                <div className="vanitas-ov-tile-main">
                  {vulnList.length.toLocaleString(currentLocale())}{" "}
                  <span className="unit">{tr("vdd.cveOnSoftware", { count: new Set(vulnList.map((v) => v.product_name)).size })}</span>
                </div>
                {vulnList.length === 0 ? (
                  <div className="vanitas-ov-tile-sub">{tr("vdd.noCveMatchShort")}</div>
                ) : (
                  <div className="vanitas-ov-mini-list">
                    {vulnList.slice(0, 3).map((v, i) => (
                      <div className="vanitas-ov-mini-row" key={`${v.cve_id}-${i}`}>
                        <span className="vanitas-ov-mini-dot" style={{ background: TONE_VAR[severityTone(v.severity)] ?? "var(--ink-faint)" }} />
                        <span className="vanitas-ov-mini-name">{v.cve_id} — {v.product_name}</span>
                        <span className="vanitas-ov-mini-meta">{severityLabelFr(v.severity)}</span>
                      </div>
                    ))}
                  </div>
                )}
                <button type="button" className="vanitas-ov-tile-link" onClick={() => goto("vulns")}>
                  {vulnList.length > 0 ? tr("vdd.seeCves", { count: vulnList.length }) : tr("vdd.seeDetail")}
                </button>
              </div>

              <div className="vanitas-ov-tile" style={{ "--tile-accent": "var(--amber)" }}>
                <div className="vanitas-ov-tile-head">
                  <div className="vanitas-ov-tile-icon">⟳</div>
                  <div className="vanitas-ov-tile-title">Windows Update</div>
                </div>
                <div className="vanitas-ov-tile-main">
                  {windowsUpdate ? windowsUpdate.pending_count : "—"} <span className="unit">{tr("vdd.pendingUnit")}</span>
                </div>
                <div className="vanitas-ov-tile-sub">
                  {windowsUpdateCommand ? tr("vdd.checkedAgo", { when: fmtRelative(windowsUpdateCommand.created_at) }) : tr("vdd.neverChecked")}
                </div>
                <button type="button" className="vanitas-ov-tile-link" onClick={() => goto("os")}>
                  {tr("vdd.seeDetail")}
                </button>
              </div>

              <div className="vanitas-ov-tile" style={{ "--tile-accent": "var(--star)" }}>
                <div className="vanitas-ov-tile-head">
                  <div className="vanitas-ov-tile-icon">▦</div>
                  <div className="vanitas-ov-tile-title">{tr("vdd.tile.apps")}</div>
                </div>
                <div className="vanitas-ov-tile-main">{appsList.length} <span className="unit">{tr("vdd.installedUnit")}</span></div>
                <div className="vanitas-ov-tile-sub">
                  {inv?.data?.collected_at ? tr("vdd.inventoryUpToDate", { when: fmtRelative(inv.data.collected_at) }) : tr("vdd.noInventory")}
                </div>
                <button type="button" className="vanitas-ov-tile-link" onClick={() => goto("apps")}>
                  {tr("vdd.seeList")}
                </button>
              </div>

              <div className="vanitas-ov-tile" style={{ "--tile-accent": agentBehindSource ? "var(--amber)" : "var(--low)" }}>
                <div className="vanitas-ov-tile-head">
                  <div className="vanitas-ov-tile-icon">⇪</div>
                  <div className="vanitas-ov-tile-title">{tr("vdd.agent")}</div>
                </div>
                <div className="vanitas-ov-tile-main">
                  {agent.agent_version ? `v${agent.agent_version}` : tr("vd.unknownVersion")}
                </div>
                <div className="vanitas-ov-tile-sub">
                  {sourceVersionCmp === null
                    ? tr("vdd.agentNoCompare", { version: LATEST_AGENT_VERSION })
                    : agentBehindSource
                      ? tr("vdd.agentBehind", { version: LATEST_AGENT_VERSION })
                      : tr("vdd.agentUpToDate", { version: LATEST_AGENT_VERSION })}
                </div>
                {canWriteApplications && latestAgentPackage && agentIsOutdated && (
                  <>
                    {updateQueued ? (
                      <span className="cve-small" style={{ color: "var(--low)" }}>
                        {tr("vdd.updateQueued")}
                      </span>
                    ) : (
                      <ConfirmButton
                        label={tr("vdd.updateNow")}
                        confirmLabel={tr("vdd.confirmShort")}
                        className="vanitas-ov-tile-link"
                        disabled={updateBusy}
                        onConfirm={handleUpdateAgent}
                        title={tr("vdd.updateTitle")}
                      />
                    )}
                    {updateError && <p className="error-note" style={{ marginTop: "6px" }}>{updateError}</p>}
                  </>
                )}
              </div>

              <div className="vanitas-ov-tile span-2" style={{ "--tile-accent": "var(--star)" }}>
                <div className="vanitas-ov-tile-head">
                  <div className="vanitas-ov-tile-icon">▸</div>
                  <div className="vanitas-ov-tile-title">{tr("vdd.lastCommands")}</div>
                </div>
                {commandList.length === 0 ? (
                  <div className="vanitas-ov-tile-sub">{tr("vdd.noCommandSent")}</div>
                ) : (
                  <div className="vanitas-ov-mini-list" style={{ marginTop: "2px" }}>
                    {commandList.slice(0, 3).map((c) => (
                      <div className="vanitas-ov-mini-row" key={c.id}>
                        <span
                          className="vanitas-ov-mini-dot"
                          style={{
                            background:
                              c.status === "completed" && c.success
                                ? "var(--low)"
                                : c.status === "completed"
                                  ? "var(--high)"
                                  : "var(--amber)",
                          }}
                        />
                        <span className="vanitas-ov-mini-name">
                          {COMMAND_LABELS[c.command_type] ?? c.command_type} —{" "}
                          {tr(c.status === "pending" || c.status === "running" ? "vdd.cmdInProgress" : c.success ? "vdd.cmdDone" : "vdd.cmdFailed")}
                        </span>
                        <span className="vanitas-ov-mini-meta">{fmtRelative(c.created_at)}</span>
                      </div>
                    ))}
                  </div>
                )}
                <button type="button" className="vanitas-ov-tile-link" onClick={() => goto("commands")}>
                  {tr("vdd.seeHistory")}
                </button>
              </div>
            </div>
          )}

          {activePane === "os" && (
            <>
              {/* Redesign du 2026-09-11 (retour de Nicolas — "possible d'avoir plus
                  d'information ?") : identité OS (édition/version/build/architecture en
                  badges) + fiche technique en 2 colonnes plutôt qu'un simple empilement de
                  lignes. Source PRINCIPALE = l'inventaire périodique (`inv`, `os_caption`/
                  `os_version`/`os_build_number` déjà présents depuis le jalon EOL du
                  2026-09-08 ; `os_architecture`/`os_registered_user`/`os_install_date`/
                  `os_utc_offset` nouveaux, `null` tant que l'agent n'a pas été redéployé —
                  dégradation gracieuse, jamais une case vide alarmante, un simple "—").
                  Uptime/dernier diagnostic restent dérivés de la commande "Diagnostic
                  système" (`diagnostic`/`diagnosticCommand`), une source différente.
                  Les deux cartes sont côte à côte (`.vanitas-os-panes`, retour de Nicolas —
                  "mettre les deux blocs sur la même ligne en réduisant la taille") plutôt
                  qu'empilées : padding/tailles de police resserrés, SCOPÉS à ce conteneur
                  (`.vanitas-os-panes .card`/`.cve-device-table` etc.) pour ne jamais changer
                  l'apparence de `.card`/`.cve-device-table` ailleurs sur le dashboard. */}
              <div className="vanitas-os-panes">
              <div className="card">
                <div className="card-head">
                  <h2>{tr("vdd.nav.os")}</h2>
                  <span className="card-note">{tr("vdd.osSources")}</span>
                </div>
                {inv?.data?.os_caption || inv?.data?.os_version ? (
                  <>
                    <div className="vanitas-os-hero">
                      <div className="vanitas-os-hero-icon">
                        <svg width="22" height="22" viewBox="0 0 20 20" fill="none">
                          <rect x="2" y="3" width="7" height="7" rx="1" fill="currentColor" />
                          <rect x="11" y="3" width="7" height="7" rx="1" fill="currentColor" opacity="0.55" />
                          <rect x="2" y="12" width="7" height="7" rx="1" fill="currentColor" opacity="0.55" />
                          <rect x="11" y="12" width="7" height="7" rx="1" fill="currentColor" />
                        </svg>
                      </div>
                      <div>
                        <p className="vanitas-os-hero-name">{inv.data.os_caption ?? "Windows"}</p>
                        <div className="vanitas-os-badges">
                          {inv.data.os_build_number && (
                            <span className="vanitas-os-badge">build {inv.data.os_build_number}</span>
                          )}
                          {inv.data.os_version && <span className="vanitas-os-badge">{inv.data.os_version}</span>}
                          {inv.data.os_architecture && (
                            <span className="vanitas-os-badge accent">{inv.data.os_architecture}</span>
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="vanitas-os-kv-grid">
                      <div className="vanitas-kv-row">
                        <span className="vanitas-kv-label">{tr("vdd.kv.hostname")}</span>
                        <span className="vanitas-kv-value">{agent.hostname}</span>
                      </div>
                      <div className="vanitas-kv-row">
                        <span className="vanitas-kv-label">{tr("vdd.kv.uptime")}</span>
                        <span className="vanitas-kv-value">{diagnostic?.uptime?.split(".")[0] ?? "—"}</span>
                      </div>

                      <div className="vanitas-kv-row">
                        <span className="vanitas-kv-label">{tr("vdd.kv.architecture")}</span>
                        <span className="vanitas-kv-value">{inv.data.os_architecture ?? "—"}</span>
                      </div>
                      <div className="vanitas-kv-row">
                        <span className="vanitas-kv-label">{tr("vdd.kv.lastDiagnostic")}</span>
                        <span className="vanitas-kv-value">
                          {diagnosticCommand ? fmtDateTime(diagnosticCommand.created_at) : tr("vdd.never")}
                        </span>
                      </div>

                      <div className="vanitas-kv-row">
                        <span className="vanitas-kv-label">{tr("vdd.kv.registeredUser")}</span>
                        <span className="vanitas-kv-value">{inv.data.os_registered_user ?? "—"}</span>
                      </div>
                      <div className="vanitas-kv-row">
                        <span className="vanitas-kv-label">{tr("vdd.kv.lastInventorySync")}</span>
                        <span className="vanitas-kv-value">{fmtRelative(inv.data.collected_at)}</span>
                      </div>

                      <div className="vanitas-kv-row">
                        <span className="vanitas-kv-label">{tr("vdd.kv.installDate")}</span>
                        <span className="vanitas-kv-value">{fmtDate(inv.data.os_install_date)}</span>
                      </div>
                      <div className="vanitas-kv-row">
                        <span className="vanitas-kv-label">{tr("vdd.kv.timezone")}</span>
                        <span className="vanitas-kv-value">{inv.data.os_utc_offset ?? "—"}</span>
                      </div>
                    </div>

                    {!diagnostic && (
                      <>
                        <p className="empty" style={{ marginTop: "16px" }}>
                          {tr("vdd.diagNeverRun")}
                        </p>
                        <CommandForm agentId={agent.id} onQueued={onQueued} initialType="system_diagnostic" />
                      </>
                    )}
                  </>
                ) : diagnostic ? (
                  // Repli : agent pas encore redéployé pour l'inventaire OS enrichi (2026-09-08),
                  // mais un diagnostic système existe déjà — au moins ces 3 infos restent affichées.
                  <div className="vanitas-kv-list">
                    <div className="vanitas-kv-row">
                      <span className="vanitas-kv-label">{tr("vdd.kv.version")}</span>
                      <span className="vanitas-kv-value">{diagnostic.os_version}</span>
                    </div>
                    <div className="vanitas-kv-row">
                      <span className="vanitas-kv-label">{tr("vdd.kv.uptime")}</span>
                      <span className="vanitas-kv-value">{diagnostic.uptime?.split(".")[0] ?? "—"}</span>
                    </div>
                    <div className="vanitas-kv-row">
                      <span className="vanitas-kv-label">{tr("vdd.kv.lastDiagnostic")}</span>
                      <span className="vanitas-kv-value">{fmtDateTime(diagnosticCommand?.created_at)}</span>
                    </div>
                  </div>
                ) : (
                  <>
                    <p className="empty">{tr("vdd.neverRun")}</p>
                    <CommandForm agentId={agent.id} onQueued={onQueued} initialType="system_diagnostic" />
                  </>
                )}
              </div>

              <div className="card">
                <div className="card-head">
                  <h2>{tr("vdd.windowsUpdates")}</h2>
                  <span className="card-note">{tr("vdd.viaCheckUpdates")}</span>
                </div>
                {windowsUpdate ? (
                  <>
                    <p className="card-note" style={{ marginBottom: "12px" }}>
                      <span className={`badge ${windowsUpdate.pending_count > 0 ? "medium" : "low"}`}>
                        {tr("vdd.updatesCount", { count: windowsUpdate.pending_count })}
                      </span>
                      {tr("vdd.checkedOn", { date: fmtDateTime(windowsUpdateCommand?.created_at) })}
                    </p>
                    {windowsUpdate.titles?.length > 0 && (
                      <div className="vanitas-detail-table-wrap">
                        <table className="cve-device-table">
                          <thead><tr><th>{tr("vdd.title")}</th></tr></thead>
                          <tbody>
                            {windowsUpdate.titles.map((t, i) => (
                              <tr key={i}><td>{t}</td></tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </>
                ) : (
                  <>
                    <p className="empty">{tr("vdd.neverCheckedHere")}</p>
                    <CommandForm agentId={agent.id} onQueued={onQueued} initialType="check_windows_updates" />
                  </>
                )}
              </div>
              </div>
            </>
          )}

          {activePane === "hardware" && (
            <>
              {/* Redesign v2 du 2026-09-11 (retour de Nicolas — "ça rend pas bien avec
                  beaucoup de données") : bandeau "en un coup d'œil" + Identité machine/BIOS/
                  Châssis/disques/GPU passés de colonnes de texte nu à des cartes bordées
                  (même traitement que les barrettes mémoire, déjà en place) — moins de "mur
                  de texte" à volume de données identique. */}
              {(diagnostic || hardware) && (
                <div className="vanitas-hw-stat-strip">
                  <div className="vanitas-hw-stat-tile" style={{ "--tile-accent": TONE_VAR[diskTone(diskPct) ?? "star"] }}>
                    <div className="vanitas-hw-stat-label">{tr("vdd.hw.systemDisk")}</div>
                    <div className="vanitas-hw-stat-value">{diskPct === null ? "—" : `${diskPct} %`}</div>
                  </div>
                  <div className="vanitas-hw-stat-tile" style={{ "--tile-accent": "var(--star)" }}>
                    <div className="vanitas-hw-stat-label">{tr("vdd.hw.totalMemory")}</div>
                    <div className="vanitas-hw-stat-value">
                      {hardware?.total_memory_bytes ? fmtBytes(hardware.total_memory_bytes) : "—"}
                    </div>
                  </div>
                  <div className="vanitas-hw-stat-tile" style={{ "--tile-accent": "var(--star)" }}>
                    <div className="vanitas-hw-stat-label">{tr("vdd.hw.physicalDisks")}</div>
                    <div className="vanitas-hw-stat-value">{hardware?.disks?.length ?? "—"}</div>
                  </div>
                  <div className="vanitas-hw-stat-tile" style={{ "--tile-accent": "var(--star)" }}>
                    <div className="vanitas-hw-stat-label">{tr("vdd.hw.pciDevices")}</div>
                    <div className="vanitas-hw-stat-value">{hardware?.pci_devices?.length ?? "—"}</div>
                  </div>
                </div>
              )}

            <div className="card">
              <div className="card-head">
                <h2>{tr("vdd.hardware")}</h2>
                {hardwareCommand && <span className="card-note">{tr("vdd.collectedAgo", { when: fmtRelative(hardwareCommand.created_at) })}</span>}
              </div>

              {hardware ? (
                <>
                  <div className="vanitas-hw-info-grid">
                    <div className="vanitas-hw-info-card">
                      <div className="vanitas-hw-info-card-head">
                        <div className="vanitas-hw-info-card-icon">
                          <svg width="13" height="13" viewBox="0 0 20 20" fill="none">
                            <rect x="3" y="3" width="14" height="14" rx="2" stroke="currentColor" strokeWidth="1.5" />
                          </svg>
                        </div>
                        <div className="vanitas-hw-info-card-title">{tr("vdd.hw.machineIdentity")}</div>
                      </div>
                      <div className="vanitas-kv-list">
                        <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.manufacturer")}</span><span className="vanitas-kv-value">{hardware.manufacturer ?? "—"}</span></div>
                        <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.model")}</span><span className="vanitas-kv-value">{hardware.model ?? "—"}</span></div>
                        <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.serial")}</span><span className="vanitas-kv-value">{hardware.serial_number ?? "—"}</span></div>
                        <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.uuid")}</span><span className="vanitas-kv-value">{hardware.uuid ?? "—"}</span></div>
                      </div>
                    </div>
                    <div className="vanitas-hw-info-card">
                      <div className="vanitas-hw-info-card-head">
                        <div className="vanitas-hw-info-card-icon">
                          <svg width="13" height="13" viewBox="0 0 20 20" fill="none">
                            <path d="M4 6h12M4 10h12M4 14h8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                          </svg>
                        </div>
                        <div className="vanitas-hw-info-card-title">{tr("vdd.hw.biosBoard")}</div>
                      </div>
                      <div className="vanitas-kv-list">
                        <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.biosVersion")}</span><span className="vanitas-kv-value">{hardware.bios_version ?? "—"}</span></div>
                        <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.biosDate")}</span><span className="vanitas-kv-value">{hardware.bios_release_date ?? "—"}</span></div>
                        <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.motherboard")}</span><span className="vanitas-kv-value">{hardware.motherboard_model ?? "—"}</span></div>
                        <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.motherboardSerial")}</span><span className="vanitas-kv-value">{hardware.motherboard_serial_number ?? "—"}</span></div>
                      </div>
                    </div>
                    <div className="vanitas-hw-info-card">
                      <div className="vanitas-hw-info-card-head">
                        <div className="vanitas-hw-info-card-icon">
                          <svg width="13" height="13" viewBox="0 0 20 20" fill="none">
                            <rect x="5" y="2" width="10" height="16" rx="2" stroke="currentColor" strokeWidth="1.5" />
                          </svg>
                        </div>
                        <div className="vanitas-hw-info-card-title">{tr("vdd.hw.chassis")}</div>
                      </div>
                      <div className="vanitas-kv-list">
                        <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.type")}</span><span className="vanitas-kv-value">{hardware.chassis_type ?? "—"}</span></div>
                      </div>
                    </div>
                  </div>

                  <div className="vanitas-hw-group-title" style={{ marginTop: "20px" }}>
                    {tr("vdd.memory")}
                    {hardware.total_memory_bytes ? ` — ${fmtBytes(hardware.total_memory_bytes)}` : ""}
                  </div>
                  {hardware.memory_modules?.length > 0 ? (
                    <div className="vanitas-dimm-grid">
                      {hardware.memory_modules.map((m, i) => (
                        <div className="vanitas-dimm-card" key={i}>
                          <div className="vanitas-dimm-slot">{m.slot ?? tr("vdd.dimm", { n: i + 1 })}</div>
                          <div className="vanitas-dimm-size">{fmtBytes(m.capacity_bytes)}</div>
                          <div className="vanitas-dimm-meta">
                            {m.speed_mhz ? `${m.speed_mhz} MT/s` : "—"}
                            {m.manufacturer ? ` · ${m.manufacturer}` : ""}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="empty">{tr("vdd.noDimm")}</p>
                  )}

                  <div className="vanitas-hw-group-title" style={{ marginTop: "20px" }}>{tr("vdd.hw.physicalDisks")}</div>
                  {hardware.disks?.length > 0 ? (
                    <div className="vanitas-hw-device-grid">
                      {hardware.disks.map((d, i) => (
                        <div className="vanitas-hw-device-card" key={i}>
                          <div className="vanitas-hw-device-top">
                            <div className="vanitas-hw-device-icon">
                              <svg width="14" height="14" viewBox="0 0 20 20" fill="none">
                                <rect x="3" y="6" width="14" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.5" />
                              </svg>
                            </div>
                            <div>
                              <div className="vanitas-hw-device-name">{d.model ?? tr("vdd.diskDefault")}</div>
                              <div className="vanitas-hw-device-sub">{d.interface_type ?? "—"}</div>
                            </div>
                          </div>
                          <div className="vanitas-hw-device-foot">
                            {diskMediaLabel(d.media_type) ? (
                              <span className="badge neutral">{diskMediaLabel(d.media_type)}</span>
                            ) : (
                              <span />
                            )}
                            <span className="vanitas-hw-device-size">{fmtBytes(d.size_bytes)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="empty">{tr("vdd.noDisk")}</p>
                  )}

                  <div className="vanitas-hw-group-title" style={{ marginTop: "20px" }}>{tr("vdd.gpus")}</div>
                  {hardware.graphics_cards?.length > 0 ? (
                    <div className="vanitas-hw-gpu-grid">
                      {hardware.graphics_cards.map((g, i) => (
                        <div className="vanitas-hw-gpu-card" key={i}>
                          <div className="vanitas-hw-gpu-name">{g.name ?? "GPU"}</div>
                          <div className="vanitas-hw-gpu-kv">
                            <span>{tr("vdd.driver")}</span>
                            <span>{g.driver_version ?? "—"}</span>
                          </div>
                          {g.adapter_ram_bytes != null && (
                            <div className="vanitas-hw-gpu-kv">
                              <span>{tr("vdd.vram")}</span>
                              <span>{fmtBytes(g.adapter_ram_bytes)}</span>
                            </div>
                          )}
                          {g.adapter_ram_bytes != null &&
                            g.adapter_ram_bytes >= 3.5 * 1024 ** 3 &&
                            g.adapter_ram_bytes <= 4.5 * 1024 ** 3 && (
                              <div className="vanitas-hw-gpu-note">
                                {tr("vdd.vramBug")}
                              </div>
                            )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="empty">{tr("vdd.noGpu")}</p>
                  )}

                  <div className="vanitas-hw-group-title" style={{ marginTop: "20px" }}>
                    {tr("vdd.hw.pciDevices")}
                    {hardware.pci_devices?.length ? ` — ${hardware.pci_devices.length}` : ""}
                  </div>
                  {pciByCategory.length > 0 ? (
                    pciByCategory.map(([category, items]) => (
                      <details className="vanitas-pci-group" key={category}>
                        <summary>
                          {category} <span className="vanitas-pci-count">{items.length}</span>
                          <span className="vanitas-pci-chevron">›</span>
                        </summary>
                        <div className="vanitas-pci-body">
                          <div className="vanitas-detail-table-wrap">
                            <table className="cve-device-table">
                              <thead>
                                <tr><th>{tr("vdd.pci.name")}</th><th>{tr("vdd.pci.vendor")}</th><th>{tr("vdd.pci.driver")}</th><th>{tr("vdd.pci.address")}</th><th>{tr("vdd.pci.state")}</th></tr>
                              </thead>
                              <tbody>
                                {items.map((d, i) => (
                                  <tr key={i}>
                                    <td>{d.name ?? "—"}</td>
                                    <td className="cve-small">{d.manufacturer ?? "—"}</td>
                                    <td className="cve-mono cve-small">{d.driver ?? "—"}</td>
                                    <td className="cve-mono cve-small">{d.device_id ?? "—"}</td>
                                    <td>
                                      {d.status ? (
                                        <span className={`badge ${pciStatusTone(d.status)}`}>{d.status}</span>
                                      ) : (
                                        "—"
                                      )}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      </details>
                    ))
                  ) : (
                    <p className="empty">{tr("vdd.noPci")}</p>
                  )}

                  <p className="card-note" style={{ marginTop: "18px" }}>
                    {tr("vdd.smartNote")}
                  </p>
                </>
              ) : (
                <>
                  <p className="empty" style={{ marginTop: diagnostic ? "16px" : 0 }}>
                    {tr("vdd.hwNeverRun")}
                  </p>
                  <CommandForm agentId={agent.id} onQueued={onQueued} initialType="hardware_inventory" />
                </>
              )}
            </div>
            </>
          )}

          {activePane === "network" && (
            <div className="card">
              <div className="card-head">
                <h2>{tr("vdd.identityNetwork")}</h2>
                {hardwareCommand && <span className="card-note">{tr("vdd.collectedAgo", { when: fmtRelative(hardwareCommand.created_at) })}</span>}
              </div>
              {hardware ? (
                <>
                  <div className="vanitas-net-identity-card">
                    <div className="vanitas-hw-info-card-head">
                      <div className="vanitas-hw-info-card-icon">
                        <svg width="13" height="13" viewBox="0 0 20 20" fill="none">
                          <circle cx="10" cy="7" r="3.2" stroke="currentColor" strokeWidth="1.5" />
                          <path d="M4 17c1-3.5 4-5 6-5s5 1.5 6 5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                        </svg>
                      </div>
                      <div className="vanitas-hw-info-card-title">{tr("vdd.hw.sessionIdentity")}</div>
                    </div>
                    <div className="vanitas-net-identity-kv">
                      <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.user")}</span><span className="vanitas-kv-value">{hardware.session_user || tr("vdd.notSet")}</span></div>
                      <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.domain")}</span><span className="vanitas-kv-value">{hardware.domain ?? "—"}</span></div>
                      <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.fqdn")}</span><span className="vanitas-kv-value">{hardware.dns_host_name ?? "—"}</span></div>
                    </div>
                  </div>

                  {hardware.network_adapters?.length > 0 ? (
                    <>
                      <div className="vanitas-hw-group-title">{tr("vdd.interfaces", { count: hardware.network_adapters.length })}</div>
                      <div className="vanitas-net-iface-grid">
                        {hardware.network_adapters.map((n, i) => {
                          const isPrimary = hardware.primary_ip_address &&
                            n.ip_addresses?.includes(hardware.primary_ip_address);
                          return (
                            <div className={`vanitas-net-iface-card${isPrimary ? " primary" : ""}`} key={i}>
                              <div className="vanitas-net-iface-top">
                                <div className="vanitas-net-iface-name">{n.description ?? tr("vdd.interface")}</div>
                                {isPrimary && <span className="vanitas-net-primary-badge">{tr("vdd.primary")}</span>}
                              </div>
                              <div className="vanitas-net-iface-row"><span>{tr("vdd.ip")}</span><span>{n.ip_addresses?.join(", ") || "—"}</span></div>
                              <div className="vanitas-net-iface-row"><span>{tr("vdd.mac")}</span><span>{n.mac_address ?? "—"}</span></div>
                            </div>
                          );
                        })}
                      </div>
                    </>
                  ) : (
                    <p className="empty">{tr("vdd.noInterface")}</p>
                  )}
                </>
              ) : (
                <>
                  <p className="empty">{tr("vdd.hwNeverRun")}</p>
                  <CommandForm agentId={agent.id} onQueued={onQueued} initialType="hardware_inventory" />
                </>
              )}
            </div>
          )}

          {activePane === "cert" && (() => {
            const tone = certTone(certDays);
            const pct = certDays === null ? 0 : Math.max(0, Math.min(100, (certDays / CERT_VALIDITY_DAYS) * 100));
            const validSince = agent.cert_not_after
              ? new Date(new Date(agent.cert_not_after).getTime() - CERT_VALIDITY_DAYS * 86_400_000)
              : null;
            return (
              <div className="card">
                <div className="card-head">
                  <h2>{tr("vdd.certEnrollment")}</h2>
                </div>

                <div className="vanitas-cert-hero">
                  <div className="vanitas-cert-hero-icon" style={{ "--tile-accent": TONE_VAR[tone ?? "star"] }}>
                    <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
                      <path d="M12 3l7 3v6c0 5-3.2 8.4-7 9.5C8.2 20.4 5 17 5 12V6l7-3z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
                      <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                  <div className="vanitas-cert-hero-main">
                    <div className="vanitas-cert-hero-top">
                      <span className="vanitas-cert-state-badge" style={{ "--tile-accent": TONE_VAR[tone ?? "star"] }}>
                        {certStateLabel(certDays)}
                      </span>
                      <span className="vanitas-cert-hero-days">
                        {trRich("vdd.expiresOn", {
                          date: <b>{fmtDate(agent.cert_not_after)}</b>,
                          days: <b>{certDays === null ? "—" : Math.max(0, Math.round(certDays))}</b>,
                        })}
                      </span>
                    </div>
                    <div className="vanitas-cert-bar-track">
                      <div className="vanitas-cert-bar-fill" style={{ width: `${pct}%`, background: TONE_VAR[tone ?? "star"] }} />
                    </div>
                  </div>
                </div>

                <div className="vanitas-cert-kv-grid">
                  <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.certSerial")}</span><span className="vanitas-kv-value">{agent.cert_serial ?? "—"}</span></div>
                  <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.issuedBy")}</span><span className="vanitas-kv-value">EndpointAgent Root CA</span></div>
                  <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.subject")}</span><span className="vanitas-kv-value" style={{ maxWidth: "none", whiteSpace: "normal", wordBreak: "break-all" }}>{agent.id}</span></div>
                  <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.usage")}</span><span className="vanitas-kv-value">{tr("vdd.clientAuth")}</span></div>
                  <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.enrolledOn")}</span><span className="vanitas-kv-value">{fmtDate(agent.enrolled_at)}</span></div>
                  <div className="vanitas-kv-row"><span className="vanitas-kv-label">{tr("vdd.kv.certValidSince")}</span><span className="vanitas-kv-value">{fmtDate(validSince)}</span></div>
                </div>

                <div className="vanitas-cert-note-row">
                  <svg width="15" height="15" viewBox="0 0 20 20" fill="none">
                    <path d="M10 5v6M10 14.5v.1" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
                    <circle cx="10" cy="10" r="8" stroke="currentColor" strokeWidth="1.4" />
                  </svg>
                  <p>{trRich("vdd.autoRenew", { strong: <b>{tr("vdd.lessThan30")}</b> })}</p>
                </div>
              </div>
            );
          })()}

          {activePane === "vulns" && (
            <div className="card">
              <div className="card-head">
                <h2>{tr("vdd.matchedVulns")}</h2>
                <span className="card-note">
                  {vulnList.length.toLocaleString(currentLocale())} {tr("vdd.cveOnSoftware", { count: new Set(vulnList.map((v) => v.product_name)).size })}
                </span>
              </div>
              {vulnList.length === 0 ? (
                <p className="empty">{tr("vdd.noCveMatch")}</p>
              ) : (
                <>
                  <div className="vanitas-vuln-toolbar">
                    <input
                      className="filter-input"
                      type="text"
                      placeholder={tr("vdd.vulnFilter")}
                      value={vulnQuery}
                      onChange={(e) => setVulnQuery(e.target.value)}
                      style={{ width: "300px" }}
                    />
                    <div className="chip-group">
                      <button
                        type="button"
                        className={`filter-chip${vulnSeverityFilter === "all" ? " active" : ""}`}
                        onClick={() => setVulnSeverityFilter("all")}
                      >
                        {tr("vdd.allF")} <span style={{ opacity: 0.6 }}>{vulnSeverityCounts.all}</span>
                      </button>
                      {VULN_SEVERITY_ORDER.filter((s) => vulnSeverityCounts[s] > 0).map((s) => (
                        <button
                          key={s}
                          type="button"
                          className={`filter-chip${vulnSeverityFilter === s ? " active" : ""}`}
                          onClick={() => setVulnSeverityFilter(s)}
                        >
                          <span className="dot" style={{ background: TONE_VAR[severityTone(s)] }} />
                          {severityLabelFr(s)} <span style={{ opacity: 0.6 }}>{vulnSeverityCounts[s]}</span>
                        </button>
                      ))}
                    </div>
                  </div>

                  {vulnList.length > 500 && (
                    <p className="error-note" style={{ marginBottom: "14px" }}>
                      {tr("vdd.notDateFiltered")}
                    </p>
                  )}
                  {filteredVulnList.length === 0 ? (
                    <p className="empty">{tr("vdd.noResultFilter")}</p>
                  ) : (
                    <>
                      <div className="vanitas-detail-table-wrap">
                        <table className="cve-device-table">
                          <thead>
                            <tr>
                              <th>{tr("vdd.col.severity")}</th>
                              <th>{tr("vdd.col.software")}</th>
                              <th>{tr("vdd.col.version")}</th>
                              <th>CVE</th>
                              <th>CVSS</th>
                              <th>{tr("vdd.col.published")}</th>
                              <th></th>
                            </tr>
                          </thead>
                          <tbody>
                            {filteredVulnList.slice(0, vulnVisibleCount).map((v, i) => (
                              <tr
                                key={`${v.cve_id}-${i}`}
                                className="vanitas-vuln-row-clickable"
                                tabIndex={0}
                                role="button"
                                onClick={() => setSelectedVulnCveId(v.cve_id)}
                              >
                                <td>
                                  <span className={`badge ${severityTone(v.severity)}`}>{severityLabelFr(v.severity)}</span>
                                  {v.version_affected === null && (
                                    <div className="cve-small" style={{ color: "var(--ink-faint)", marginTop: "4px" }}>
                                      {tr("vdd.indeterminate")}
                                    </div>
                                  )}
                                </td>
                                <td>{v.product_name}</td>
                                <td className="cve-mono cve-small">{v.installed_version ?? "—"}</td>
                                <td className="cve-mono cve-small">{v.cve_id}</td>
                                <td className="cve-mono cve-small">{v.cvss_score ?? "—"}</td>
                                <td className="cve-small">{fmtDate(v.published)}</td>
                                <td className="vanitas-vuln-row-chev">›</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      {vulnVisibleCount < filteredVulnList.length && (
                        <button
                          type="button"
                          className="vanitas-ov-tile-link"
                          style={{ marginTop: "14px" }}
                          onClick={() => setVulnVisibleCount((n) => n + VULN_REVEAL_STEP)}
                        >
                          {tr("vdd.showMore", {
                            step: Math.min(VULN_REVEAL_STEP, filteredVulnList.length - vulnVisibleCount),
                            remaining: (filteredVulnList.length - vulnVisibleCount).toLocaleString(currentLocale()),
                          })}
                        </button>
                      )}
                    </>
                  )}
                </>
              )}
            </div>
          )}

          {selectedVulnGroup && (
            <CveDetailModal
              group={selectedVulnGroup}
              deviceScope={agent.hostname}
              onClose={() => setSelectedVulnCveId(null)}
            />
          )}

          {activePane === "compliance" && (
            <div className="card">
              <div className="card-head">
                <h2>{tr("vdd.compliance")}</h2>
                {compliance?.data?.collected_at && (
                  <span className="card-note">{tr("vdd.lastCheck", { when: fmtRelative(compliance.data.collected_at) })}</span>
                )}
              </div>
              {compliance?.status === "loading" ? (
                <p className="empty">{tr("common.loading")}</p>
              ) : complianceList.length === 0 ? (
                <p className="empty">{tr("vdd.noComplianceResult")}</p>
              ) : (
                <>
                  <div className="vanitas-compliance-stat-strip">
                    <div className="vanitas-compliance-stat-tile" style={{ "--tile-accent": TONE_VAR.low }}>
                      <div className="vanitas-compliance-stat-label">{tr("vdd.rule.low")}</div>
                      <div className="vanitas-compliance-stat-value">
                        {complianceList.filter((r) => r.compliant === true).length}
                      </div>
                    </div>
                    <div className="vanitas-compliance-stat-tile" style={{ "--tile-accent": TONE_VAR.high }}>
                      <div className="vanitas-compliance-stat-label">{tr("vdd.rule.high")}</div>
                      <div className="vanitas-compliance-stat-value">
                        {complianceList.filter((r) => r.compliant === false).length}
                      </div>
                    </div>
                    <div className="vanitas-compliance-stat-tile" style={{ "--tile-accent": TONE_VAR.medium }}>
                      <div className="vanitas-compliance-stat-label">{tr("vdd.rule.medium")}</div>
                      <div className="vanitas-compliance-stat-value">
                        {complianceList.filter((r) => r.compliant !== true && r.compliant !== false).length}
                      </div>
                    </div>
                  </div>

                  <div className="vanitas-compliance-rule-list">
                    {complianceList.map((r) => {
                      const tone = complianceRuleTone(r);
                      return (
                        <div className={`vanitas-compliance-rule-card ${tone}`} key={r.rule_id}>
                          <div className="vanitas-compliance-rule-top">
                            <span className="vanitas-compliance-rule-name">{r.rule_name}</span>
                            <span className={`badge ${tone}`}>{complianceRuleLabel(r)}</span>
                          </div>
                          {r.detail && <pre className="vanitas-compliance-rule-detail">{r.detail}</pre>}
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </div>
          )}

          {activePane === "suspicious" && (
            <div className="card">
              <div className="card-head">
                <h2>{tr("vdd.suspicious")}</h2>
                <span className="card-note">
                  {tr("vdd.events", { count: suspiciousEvents.state.data.length })}
                </span>
              </div>
              <SuspiciousEventsTable
                events={suspiciousEvents.state.data}
                loading={suspiciousEvents.state.status === "loading"}
                error={suspiciousEvents.state.error}
                onSelect={setSelectedSuspiciousEvent}
                showHost={false}
              />
            </div>
          )}

          {activePane === "event-log" && (
            <VanitasEventLogPane
              agent={agent}
              commandList={commandList}
              onQueued={onQueued}
              canWrite={canWritePostes}
            />
          )}

          {activePane === "apps" && (
            <div className="card">
              <div className="card-head">
                <h2>{tr("vdd.installedApps")}</h2>
                <span className="card-note">
                  {tr("vdd.appsShown", { count: appsList.length, shown: appsFilter ? `${filteredApps.length} / ${appsList.length}` : appsList.length })}
                </span>
              </div>
              <input
                className="filter-input"
                type="text"
                placeholder={tr("vdd.appsFilter")}
                value={appsFilter}
                onChange={(e) => setAppsFilter(e.target.value)}
                style={{ marginBottom: "14px", width: "320px" }}
              />
              {filteredApps.length === 0 ? (
                <p className="empty">{appsList.length === 0 ? tr("vdd.noInventoryYet") : tr("vdd.noResultFilter")}</p>
              ) : (
                <div className="vanitas-detail-table-wrap">
                  <table className="cve-device-table">
                    <thead>
                      <tr>
                        <th>{tr("vdd.col.name")}</th>
                        <th>{tr("vdd.col.publisher")}</th>
                        <th>{tr("vdd.col.version")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredApps.map((a, i) => (
                        <tr key={`${a.name}-${i}`}>
                          <td>{a.name}</td>
                          <td className="cve-small">{a.publisher ?? "—"}</td>
                          <td className="cve-mono cve-small">{a.version ?? "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activePane === "commands" && (
            <div className="card">
              <div className="card-head">
                <h2>{tr("vdd.commandHistory")}</h2>
              </div>
              {commands.error && <p className="error-note">{commands.error}</p>}
              {commands.status === "loading" ? (
                <p className="empty">{tr("common.loading")}</p>
              ) : commandList.length === 0 ? (
                <p className="empty">{tr("vdd.noCommandSent")}</p>
              ) : (
                <div className="vanitas-cmd-list">
                  {commandList.map((c) => (
                    <div
                      className="vanitas-cmd-row vanitas-cmd-row-clickable"
                      key={c.id}
                      tabIndex={0}
                      role="button"
                      onClick={() => setSelectedCommandId(c.id)}
                    >
                      <div className="vanitas-cmd-row-main">
                        <span className="vanitas-cmd-name">{COMMAND_LABELS[c.command_type] ?? c.command_type}</span>
                        <span className={`vanitas-cmd-status-pill ${commandTone(c)}`}>{commandStateLabel(c)}</span>
                      </div>
                      <div className="vanitas-cmd-row-right">
                        <span className="vanitas-cmd-time">{fmtRelative(c.created_at)}</span>
                        <span className="vanitas-cmd-chev">›</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              <CommandForm agentId={agent.id} onQueued={onQueued} />
            </div>
          )}

          {selectedCommand && (
            <CommandDetailModal
              command={selectedCommand}
              hostname={agent.hostname}
              onClose={() => setSelectedCommandId(null)}
            />
          )}

          {selectedSuspiciousEvent && (
            <SuspiciousEventDetailModal
              event={selectedSuspiciousEvent}
              onClose={() => setSelectedSuspiciousEvent(null)}
              onUpdated={(updated) => {
                setSelectedSuspiciousEvent(updated);
                suspiciousEvents.refresh();
              }}
            />
          )}

          {activePane === "terminal" && (
            <div className="vanitas-hud card">
              <div className="vanitas-hud-card-head">
                <h2>{tr("vdd.terminal")}</h2>
              </div>
              {!canWriteTerminal ? (
                <p className="empty">
                  {tr("vdd.noTerminalAccess")}
                </p>
              ) : !shellQueuedAt ? (
                <>
                  <p className="vanitas-hud-terminal-warning">
                    {trRich("vdd.terminalWarning", { real: <b>{tr("vdd.realSession")}</b>, system: <b>SYSTEM</b> })}
                  </p>
                  <ConfirmButton
                    label={tr("vdd.openTerminal")}
                    confirmLabel={tr("vdd.confirmOpen")}
                    className="vanitas-danger-btn"
                    onConfirm={handleStartShell}
                    title={tr("vdd.openTitle")}
                  />
                  {shellStartError && <p className="error-note" style={{ marginTop: "10px" }}>{shellStartError}</p>}
                </>
              ) : !shellSessionId ? (
                <p className="vanitas-hud-terminal-waiting">
                  {tr("vdd.waitingAgent")}
                </p>
              ) : (
                <>
                  <div className="vanitas-hud-terminal-status-row">
                    <span className={shell.status === "stale" ? "stale" : "live"}>
                      {shell.status === "active" && tr("vdd.sessionActive")}
                      {shell.status === "stale" && tr("vdd.sessionStale")}
                      {(shell.status === "closed" || shell.status === "timed_out") && tr("vdd.sessionClosed")}
                    </span>
                    <button
                      type="button"
                      className="vanitas-hud-purge-btn"
                      onClick={shell.stop}
                      disabled={shell.status !== "active"}
                    >
                      {tr("vdd.closeSession")}
                    </button>
                  </div>
                  {shell.error && <p className="error-note" style={{ marginBottom: "10px" }}>{shell.error}</p>}
                  <div className="vanitas-hud-terminal-log">
                    {shell.events.length === 0 ? (
                      <span style={{ color: "var(--hud-ink-faint)" }}>{tr("vdd.waitingFirst")}</span>
                    ) : (
                      shell.events.map((e) => (
                        <div key={e.id} className={`vanitas-hud-terminal-line ${e.direction === "input" ? "input" : e.source}`}>
                          {e.content}
                        </div>
                      ))
                    )}
                  </div>
                  <form className="vanitas-hud-terminal-form" onSubmit={handleTerminalSubmit}>
                    <span style={{ color: "var(--hud-accent)", fontFamily: "var(--hud-mono)", alignSelf: "center" }}>&gt;</span>
                    <input
                      type="text"
                      value={terminalInput}
                      onChange={(e) => setTerminalInput(e.target.value)}
                      placeholder={tr("vdd.psPlaceholder")}
                      disabled={shell.status !== "active"}
                      autoComplete="off"
                    />
                    <button type="submit" disabled={shell.status !== "active" || !terminalInput.trim()}>
                      {tr("vdd.send")}
                    </button>
                  </form>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
