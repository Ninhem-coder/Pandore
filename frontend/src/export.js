import writeExcelFile from "write-excel-file/universal";
import {
  buildCveExportData,
  buildAppInstallExportData,
  buildPostesExportData,
  buildConformiteExportData,
  buildVulnerabilitiesExportData,
  buildEolExportData,
  buildSuspiciousEventsExportData,
  buildVanitasDeployedAppsExportData,
  buildPatchStatusExportData,
} from "./selectors.js";
import { localizedTable, tr } from "./i18n/core.js";

// Libellés des états d'installation pour les EN-TÊTES de colonnes de la feuille "Vue
// d'ensemble" (voir exportAppInstallStatusToExcel ci-dessous) — copie volontairement réduite
// de INSTALL_STATE_LABEL (DeployedAppsTab.jsx, table de référence pour l'affichage à
// l'écran) : ce fichier ne dépend d'aucun composant page (voir le commentaire d'en-tête plus
// haut sur exportCveToExcel), donc pas d'import croisé pour 5 libellés fixes.
// Exports are written in the current interface language (sheet names, headers, fixed values).
const INSTALL_STATE_COLUMN_LABEL = localizedTable("export.state", [
  "installed",
  "failed",
  "pendingInstall",
  "notInstalled",
  "notApplicable",
]);

/** Bold header cell with a translated label. */
function header(key) {
  return { value: tr(key), fontWeight: "bold" };
}

/**
 * Génère et déclenche le téléchargement d'un export Excel (.xlsx) pour UNE CVE — bouton
 * "Exporter Excel" de VulnCard (VulnerabilitiesTab.jsx), demande de Nicolas du 2026-08-21.
 *
 * `write-excel-file/universal` plutôt que `/browser` : depuis sa v4, `/browser` s'appuie sur
 * des Web Workers (voir son README) qui demandent une configuration de bundling dédiée —
 * ce projet n'en a aucune (Vite par défaut) et l'opération est de toute façon minuscule
 * (quelques dizaines de devices au plus par CVE), donc `/universal` (qui fonctionne aussi
 * bien en Node qu'au navigateur, sans Worker) évite cette dépendance pour un gain nul.
 * `/universal` ne sait renvoyer qu'un `Blob` (pas de "Save as" intégré comme `/browser`) —
 * le téléchargement est donc déclenché à la main via un lien `<a download>` temporaire,
 * exactement le mécanisme qu'utiliserait un navigateur pour tout lien de téléchargement.
 *
 * Deux onglets, même esprit que l'export Excel de référence utilisé par Nicolas (skill
 * audit-vuln-defender/Get-CveExposedDevices.ps1 : une feuille de synthèse puis une feuille
 * "Devices exposés"), mais réduits aux colonnes déjà disponibles côté dashboard — voir le
 * commentaire de `selectors.js::buildCveExportData` sur ce choix de périmètre.
 */
export async function exportCveToExcel(v) {
  const { summary, devices } = buildCveExportData(v);

  const summarySheet = {
    sheet: tr("export.sheet.summary"),
    columns: [{ width: 34 }, { width: 42 }],
    data: [
      [
        header("export.col.indicator"),
        header("export.col.value"),
      ],
      ...summary.map((row) => [{ value: row.label }, toCell(row.value)]),
    ],
  };

  const deviceSheet = {
    sheet: tr("export.sheet.exposedDevices"),
    stickyRowsCount: 1,
    columns: [{ width: 26 }, { width: 22 }, { width: 55 }, { width: 55 }],
    data: [
      [
        header("export.col.device"),
        header("export.col.rbacGroup"),
        header("export.col.diskPaths"),
        header("export.col.registryPaths"),
      ],
      ...devices.map((d) => [
        { value: safeText(d.device) },
        // "—" plutôt qu'une cellule vide quand le groupe RBAC est absent — même convention
        // d'affichage que la colonne équivalente de VulnDeviceTable à l'écran.
        { value: d.rbacGroup ? safeText(d.rbacGroup) : "—" },
        pathCell(d.diskPaths),
        pathCell(d.registryPaths),
      ]),
    ],
  };

  const blob = await writeExcelFile([summarySheet, deviceSheet]).toBlob();
  downloadBlob(blob, exportFileName(v?.cve_code));
}

/**
 * Génère et déclenche le téléchargement d'un export Excel (.xlsx) pour le détail par device
 * d'UNE app déployée — bouton "Exporter Excel" du panneau détail (AppDetailPanel,
 * DeployedAppsTab.jsx), demande de Nicolas du 2026-08-25 : "une feuille par départements et une
 * feuille de vue d'ensemble avec les comptes par département et l'appli concernée".
 *
 * Une feuille "Vue d'ensemble" (nom de l'app en titre + un décompte par département) suivie d'une
 * feuille PAR DÉPARTEMENT (liste nominative des devices) — même esprit à deux niveaux que l'export
 * CVE ci-dessus (Résumé + Devices exposés), mais avec autant de feuilles "devices" que
 * de départements représentées plutôt qu'une seule, puisque c'est la dimension explicitement
 * demandée ici. Noms de feuille tronqués à 31 caractères (limite Excel) et nettoyés des
 * caractères interdits par le format XLSX (`: \ / ? * [ ]`) — un département au nom un peu long
 * ou contenant un caractère spécial ne doit pas faire échouer tout l'export.
 */
export async function exportAppInstallStatusToExcel(app, devices) {
  const { appName, starNames, overview, byStar } = buildAppInstallExportData(app, devices);

  const overviewColumns = ["Installées", "Échecs", "En attente", "Non installées", "Non applicables", "Autres"];
  const overviewSheet = {
    sheet: tr("export.sheet.overview"),
    columns: [{ width: 28 }, { width: 12 }, ...overviewColumns.map(() => ({ width: 14 }))],
    data: [
      [{ value: tr("export.appTitle", { name: appName }), fontWeight: "bold", columnSpan: 2 + overviewColumns.length }],
      [],
      [
        header("export.col.department"),
        header("export.col.devices"),
        ...Object.keys(INSTALL_STATE_COLUMN_LABEL).map((k) => ({
          value: INSTALL_STATE_COLUMN_LABEL[k],
          fontWeight: "bold",
        })),
        header("export.col.other"),
      ],
      ...overview.map((row) => [
        { value: safeText(row.star) },
        { value: row.total, type: Number },
        ...Object.keys(INSTALL_STATE_COLUMN_LABEL).map((k) => ({ value: row[k] || 0, type: Number })),
        { value: row.other || 0, type: Number },
      ]),
    ],
  };

  const usedSheetNames = new Set([tr("export.sheet.overview")]);
  const starSheets = starNames.map((star) => {
    const sheetDevices = byStar[star] || [];
    return {
      sheet: uniqueSheetName(star, usedSheetNames),
      stickyRowsCount: 1,
      columns: [{ width: 24 }, { width: 30 }, { width: 16 }, { width: 16 }, { width: 26 }, { width: 20 }],
      data: [
        [
          header("export.col.device"),
          header("export.col.user"),
          header("export.col.installedVersion"),
          header("export.col.installState"),
          header("export.col.os"),
          header("export.col.lastSync"),
        ],
        ...sheetDevices.map((d) => [
          { value: safeText(d.deviceName) },
          { value: safeText(d.userPrincipalName) },
          { value: safeText(d.appVersion) },
          { value: INSTALL_STATE_COLUMN_LABEL[d.installState] || d.installState || tr("export.col.unknown") },
          { value: safeText(d.osDescription) },
          toCell(d.lastSyncDateTime),
        ]),
      ],
    };
  });

  const blob = await writeExcelFile([overviewSheet, ...starSheets]).toBlob();
  downloadBlob(blob, appExportFileName(appName));
}

/** Nom de feuille Excel valide et unique à partir d'un nom de département : retire les caractères
 * interdits par le format XLSX (`: \ / ? * [ ]`), tronque à la limite de 31 caractères
 * qu'Excel impose aux noms de feuille, puis désambiguïse par un suffixe numérique si la
 * troncature fait collisionner deux départements au nom proche (peu probable mais silencieusement
 * écraser une feuille serait pire qu'un nom légèrement moins lisible). */
function uniqueSheetName(rawName, used) {
  const cleaned = (rawName || tr("export.sheet.departmentFallback")).replace(/[:\\/?*[\]]/g, "-").trim() || tr("export.sheet.departmentFallback");
  let base = cleaned.slice(0, 31);
  let name = base;
  let suffix = 2;
  while (used.has(name)) {
    const suffixStr = `-${suffix}`;
    name = base.slice(0, 31 - suffixStr.length) + suffixStr;
    suffix += 1;
  }
  used.add(name);
  return name;
}

/** Neutralise l'injection de formule Excel/CSV ("CSV Injection", classe OWASP) — revue de
 * sécurité du 2026-09-02 : un nom de device (auto-enrôlement, join Autopilot) ou un UPN peut en
 * théorie commencer par `=`/`+`/`-`/`@` sans que rien dans ce dashboard ne l'empêche côté
 * source (Intune/Entra ID). Un tableur qui réinterprète une telle cellule comme une formule à
 * l'ouverture/l'import (Excel en mode compatibilité, réimport CSV, Google Sheets…) exécuterait
 * alors ce contenu. Un guillemet simple en tête force le type "texte" côté Excel sans changer
 * l'affichage visible — appliqué à toute valeur de cellule dérivée d'un device/utilisateur/
 * département réel, jamais aux libellés fixes que ce fichier écrit lui-même (états d'installation,
 * en-têtes de colonnes). */
function safeText(value) {
  const s = value === null || value === undefined ? "" : String(value);
  return /^[=+\-@]/.test(s) ? `'${s}` : s;
}

/** Cellule "valeur" de la feuille Résumé : les dates ISO (first_seen/last_seen) deviennent
 * de vraies cellules Date Excel (triables/filtrables), pas du texte — même intention que
 * l'AutoFilter du script PowerShell de référence, appliquée ici à la lecture plutôt qu'à
 * l'écriture (AutoFilter n'a guère de sens sur 8 lignes indicateur/valeur). */
function toCell(value) {
  if (value === null || value === undefined || value === "") return { value: "" };
  if (typeof value === "number") return { value, type: Number };
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) {
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) return { value: d, type: Date, format: "dd/mm/yyyy hh:mm" };
  }
  // Date SANS heure (ex. `eol_date` de vanitas/eol.py, `date.fromisoformat` — jamais de "T") —
  // 🔧 revue de sécurité/qualité du 2026-09-17 : jusqu'ici retombait dans la branche texte brut
  // ci-dessous, perdant le tri/filtre Excel natif pourtant promis par ce commentaire de
  // fonction. Format sans heure (une valeur "00:00" affichée serait trompeuse pour une date de
  // fin de support, qui n'a jamais eu d'heure réelle).
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
    const d = new Date(`${value}T00:00:00`);
    if (!Number.isNaN(d.getTime())) return { value: d, type: Date, format: "dd/mm/yyyy" };
  }
  return { value: String(value) };
}

/** Une cellule "chemins" (disque ou registre) : retour à la ligne activé pour que les
 * sauts de ligne insérés par `buildCveExportData` (un chemin par ligne, comme PathList à
 * l'écran) soient bien visibles dans Excel plutôt qu'aplatis en une seule ligne illisible. */
function pathCell(joinedPaths) {
  return { value: joinedPaths ? safeText(joinedPaths) : tr("export.noEvidence"), wrap: true, alignVertical: "top" };
}

/** "Export-CVE-2024-3400-2026-08-21.xlsx" — même convention de nom que le script PowerShell
 * de référence (Get-CveExposedDevices.ps1), pour qu'un fichier posé dans le même dossier que
 * les exports existants de Nicolas ne se distingue pas à l'œil. */
function exportFileName(cveCode) {
  const withoutPrefix = (cveCode || "cve-inconnue").replace(/^cve-/i, "");
  const safeCve = withoutPrefix.replace(/[^a-zA-Z0-9-]/g, "-");
  const date = new Date().toISOString().slice(0, 10);
  return `Export-CVE-${safeCve}-${date}.xlsx`;
}

/** "Export-Google-Chrome-2026-08-25.xlsx" — même esprit que exportFileName ci-dessus (nom
 * lisible + date du jour), adapté à un nom d'app plutôt qu'un code CVE. */
function appExportFileName(appName) {
  const safe = (appName || "application").replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  const date = new Date().toISOString().slice(0, 10);
  return `Export-${safe || "application"}-${date}.xlsx`;
}

/* ══════════════════════ Export Excel — Vanitas (2026-09-17) ══════════════════════
   7 boutons "Exporter Excel", un par page fleet-wide de Vanitas — demande de Nicolas, même
   mécanique que les 2 exports Pandore ci-dessus (write-excel-file/universal, `<a download>`
   déclenché à la main, `safeText`/`toCell` réutilisés tels quels). Nommage de fichier
   générique (`genericFileName`, ci-dessous) plutôt qu'un helper par export : contrairement à
   `exportFileName`/`appExportFileName` (un seul mot dynamique dans le nom), ces 7 exports
   partagent tous exactement la forme "Export-<Sujet>-<date>.xlsx" sans particularité propre à
   chacun. */

/** "Export-Vanitas-Postes-2026-09-17.xlsx" — voir genericFileName. */
export async function exportPostesToExcel(agents, groupById, latestCommandByAgent, isOnlineFn) {
  const rows = buildPostesExportData(agents, groupById, latestCommandByAgent, isOnlineFn);
  const sheet = {
    sheet: tr("export.sheet.endpoints"),
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 10 }, { width: 24 }, { width: 14 }, { width: 24 }, { width: 10 }, { width: 26 }, { width: 20 }, { width: 20 }],
    data: [
      [
        header("export.col.endpoint"),
        header("export.col.online"),
        header("export.col.lastSync"),
        header("export.col.agentVersion"),
        header("export.col.certificate"),
        header("export.col.applications"),
        header("export.col.groups"),
        header("export.col.lastCommand"),
        header("export.col.sentOn"),
      ],
      ...rows.map((r) => [
        { value: safeText(r.hostname) },
        { value: tr(r.online ? "export.yes" : "export.no") },
        toCell(r.lastSeen),
        { value: safeText(r.agentVersion) },
        toCell(r.certNotAfter),
        { value: r.appsCount, type: Number },
        { value: safeText(r.groups) },
        { value: safeText(r.lastCommand) },
        toCell(r.lastCommandAt),
      ]),
    ],
  };
  const blob = await writeExcelFile([sheet]).toBlob();
  downloadBlob(blob, genericFileName("Vanitas-Postes"));
}

/** "Export-Vanitas-Conformite-2026-09-17.xlsx" — deux feuilles, même esprit que l'export CVE
 * (Résumé + détail). */
export async function exportConformiteToExcel(rules) {
  const { summary, detail } = buildConformiteExportData(rules);

  const summarySheet = {
    sheet: tr("export.sheet.ruleSummary"),
    stickyRowsCount: 1,
    columns: [{ width: 30 }, { width: 12 }, { width: 10 }, { width: 10 }, { width: 20 }, { width: 12 }],
    data: [
      [
        header("export.col.rule"),
        header("export.col.enabled"),
        header("export.col.endpoints"),
        header("export.col.compliant"),
        header("export.col.nonCompliant"),
        header("export.col.unknown"),
      ],
      ...summary.map((r) => [
        { value: safeText(r.name) },
        { value: tr(r.enabled ? "export.yes" : "export.no") },
        { value: r.total, type: Number },
        { value: r.compliant, type: Number },
        { value: r.nonCompliant, type: Number },
        { value: r.unknown, type: Number },
      ]),
    ],
  };

  const detailSheet = {
    sheet: tr("export.sheet.endpointDetail"),
    stickyRowsCount: 1,
    columns: [{ width: 30 }, { width: 22 }, { width: 16 }],
    data: [
      [
        header("export.col.rule"),
        header("export.col.endpoint"),
        header("export.col.status"),
      ],
      ...detail.map((r) => [{ value: safeText(r.rule) }, { value: safeText(r.hostname) }, { value: r.status }]),
    ],
  };

  const blob = await writeExcelFile([summarySheet, detailSheet]).toBlob();
  downloadBlob(blob, genericFileName("Vanitas-Conformite"));
}

/** "Export-Vanitas-Vulnerabilites-2026-09-17.xlsx" — une ligne par (CVE × poste), sur tout
 * le parc (voir buildVulnerabilitiesExportData). */
export async function exportVulnerabilitiesToExcel(groups) {
  const rows = buildVulnerabilitiesExportData(groups);
  const sheet = {
    sheet: tr("export.sheet.cveByEndpoint"),
    stickyRowsCount: 1,
    columns: [{ width: 18 }, { width: 12 }, { width: 10 }, { width: 18 }, { width: 22 }, { width: 28 }, { width: 16 }, { width: 14 }],
    data: [
      [
        header("export.col.cve"),
        header("export.col.severity"),
        header("export.col.cvss"),
        header("export.col.published"),
        header("export.col.endpoint"),
        header("export.col.software"),
        header("export.col.installedVersion"),
        header("export.col.affectedVersion"),
      ],
      ...rows.map((r) => [
        { value: safeText(r.cveId) },
        { value: r.severity },
        r.cvssScore === null ? { value: "" } : { value: r.cvssScore, type: Number },
        toCell(r.published),
        { value: safeText(r.hostname) },
        { value: safeText(r.product) },
        { value: safeText(r.installedVersion) },
        { value: r.versionAffected },
      ]),
    ],
  };
  const blob = await writeExcelFile([sheet]).toBlob();
  downloadBlob(blob, genericFileName("Vanitas-Vulnerabilites"));
}

/** "Export-Vanitas-Logiciels-obsoletes-2026-09-17.xlsx" — une ligne par occurrence EOL,
 * `typeLabels` = TYPE_LABEL_FR de VanitasEolTab.jsx. */
export async function exportEolToExcel(rows, typeLabels) {
  const data = buildEolExportData(rows, typeLabels);
  const sheet = {
    sheet: tr("export.sheet.eol"),
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 20 }, { width: 26 }, { width: 16 }, { width: 10 }, { width: 14 }, { width: 14 }, { width: 40 }],
    data: [
      [
        header("export.col.endpoint"),
        header("export.col.type"),
        header("export.col.softwareOrOs"),
        header("export.col.version"),
        header("export.col.eol"),
        header("export.col.daysUntilEol"),
        header("export.col.eolDate"),
        header("export.col.finding"),
      ],
      ...data.map((r) => [
        { value: safeText(r.hostname) },
        { value: r.type },
        { value: safeText(r.name) },
        { value: safeText(r.version) },
        { value: tr(r.isEol ? "export.yes" : "export.soon") },
        r.daysUntilEol === null ? { value: "" } : { value: r.daysUntilEol, type: Number },
        toCell(r.eolDate),
        { value: safeText(r.message), wrap: true },
      ]),
    ],
  };
  const blob = await writeExcelFile([sheet]).toBlob();
  downloadBlob(blob, genericFileName("Vanitas-Logiciels-obsoletes"));
}

/** "Export-Vanitas-Activites-suspectes-2026-09-17.xlsx" — exporte `events` TEL QUE FILTRÉ à
 * l'écran (voir commentaire d'en-tête de buildSuspiciousEventsExportData dans selectors.js). */
export async function exportSuspiciousEventsToExcel(events, labels) {
  const rows = buildSuspiciousEventsExportData(events, labels);
  const sheet = {
    sheet: tr("export.sheet.suspicious"),
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 12 }, { width: 18 }, { width: 22 }, { width: 40 }, { width: 18 }, { width: 14 }, { width: 18 }, { width: 18 }, { width: 30 }],
    data: [
      [
        header("export.col.endpoint"),
        header("export.col.severity"),
        header("export.col.signal"),
        header("export.col.matchedRule"),
        header("export.col.summary"),
        header("export.col.occurredOn"),
        header("export.col.status"),
        header("export.col.handledBy"),
        header("export.col.handledOn"),
        header("export.col.note"),
      ],
      ...rows.map((r) => [
        { value: safeText(r.hostname) },
        { value: r.severity },
        { value: r.signalType },
        { value: safeText(r.matchedRule) },
        { value: safeText(r.summary), wrap: true },
        toCell(r.occurredAt),
        { value: r.status },
        { value: safeText(r.handledBy) },
        toCell(r.handledAt),
        { value: safeText(r.handledNote), wrap: true },
      ]),
    ],
  };
  const blob = await writeExcelFile([sheet]).toBlob();
  downloadBlob(blob, genericFileName("Vanitas-Activites-suspectes"));
}

/** "Export-Vanitas-Applications-deployees-2026-09-17.xlsx" — même découpage à deux niveaux
 * que exportAppInstallStatusToExcel, groupé par installeur (voir
 * buildVanitasDeployedAppsExportData). */
export async function exportVanitasDeployedAppsToExcel(rows) {
  const { appNames, overview, byApp } = buildVanitasDeployedAppsExportData(rows);

  const overviewSheet = {
    sheet: tr("export.sheet.overview"),
    stickyRowsCount: 1,
    columns: [{ width: 26 }, { width: 12 }, { width: 30 }, { width: 10 }, { width: 10 }, { width: 10 }, { width: 12 }],
    data: [
      [
        header("export.col.application"),
        header("export.col.version"),
        header("export.col.targets"),
        header("export.col.endpoints"),
        header("export.col.succeeded"),
        header("export.col.failed"),
        header("export.col.pending"),
      ],
      ...overview.map((r) => [
        { value: safeText(r.name) },
        { value: safeText(r.version) },
        { value: safeText(r.targets) },
        { value: r.total, type: Number },
        { value: r.ok, type: Number },
        { value: r.bad, type: Number },
        { value: r.pending, type: Number },
      ]),
    ],
  };

  const usedSheetNames = new Set([tr("export.sheet.overview")]);
  const appSheets = appNames.map((name) => ({
    sheet: uniqueSheetName(name, usedSheetNames),
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 14 }, { width: 40 }, { width: 18 }],
    data: [
      [
        header("export.col.endpoint"),
        header("export.col.status"),
        header("export.col.result"),
        header("export.col.completedOn"),
      ],
      ...(byApp[name] || []).map((d) => [
        { value: safeText(d.hostname) },
        { value: tr(`export.deploy.${d.status === "ok" || d.status === "bad" ? d.status : "pending"}`) },
        { value: safeText(d.result || "") },
        toCell(d.completed_at || d.created_at),
      ]),
    ],
  }));

  const blob = await writeExcelFile([overviewSheet, ...appSheets]).toBlob();
  downloadBlob(blob, genericFileName("Vanitas-Applications-deployees"));
}

/** "Export-Vanitas-Mises-a-jour-2026-09-17.xlsx" — une ligne par poste suivi par une
 * politique de patch (voir buildPatchStatusExportData). */
export async function exportPatchStatusToExcel(entries) {
  const rows = buildPatchStatusExportData(entries);
  const sheet = {
    sheet: tr("export.sheet.updates"),
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 20 }, { width: 18 }, { width: 12 }, { width: 10 }, { width: 14 }, { width: 12 }, { width: 20 }, { width: 20 }, { width: 20 }],
    data: [
      [
        header("export.col.endpoint"),
        header("export.col.group"),
        header("export.col.status"),
        header("export.col.available"),
        header("export.col.todo"),
        header("export.col.inProgress"),
        header("export.col.installed"),
        header("export.col.installedOn"),
        header("export.col.forcedOn"),
        header("export.col.lastCheck"),
      ],
      ...rows.map((r) => [
        { value: safeText(r.hostname) },
        { value: r.group ? safeText(r.group) : "—" },
        { value: r.status },
        { value: r.available, type: Number },
        { value: r.todo, type: Number },
        { value: r.inProgress, type: Number },
        { value: r.installed, type: Number },
        toCell(r.installedAt),
        toCell(r.forcedAt),
        toCell(r.updatedAt),
      ]),
    ],
  };
  const blob = await writeExcelFile([sheet]).toBlob();
  downloadBlob(blob, genericFileName("Vanitas-Mises-a-jour"));
}

/** "Export-<Sujet>-2026-09-17.xlsx" — généralisation de exportFileName/appExportFileName
 * pour les 7 exports Vanitas ci-dessus, qui n'ont pas de particularité de nommage propre
 * (pas de code CVE ni de nom d'app à nettoyer, juste un sujet de page fixe). */
function genericFileName(subject) {
  const date = new Date().toISOString().slice(0, 10);
  return `Export-${subject}-${date}.xlsx`;
}

function downloadBlob(blob, fileName) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
