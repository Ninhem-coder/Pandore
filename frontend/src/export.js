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

// Libellés FR des états d'installation pour les EN-TÊTES de colonnes de la feuille "Vue
// d'ensemble" (voir exportAppInstallStatusToExcel ci-dessous) — copie volontairement réduite
// de INSTALL_STATE_LABEL_FR (DeployedAppsTab.jsx, table de référence pour l'affichage à
// l'écran) : ce fichier ne dépend d'aucun composant page (voir le commentaire d'en-tête plus
// haut sur exportCveToExcel), donc pas d'import croisé pour 5 libellés fixes.
const INSTALL_STATE_COLUMN_LABEL_FR = {
  installed: "Installées",
  failed: "Échecs",
  pendingInstall: "En attente",
  notInstalled: "Non installées",
  notApplicable: "Non applicables",
};

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
    sheet: "Résumé",
    columns: [{ width: 34 }, { width: 42 }],
    data: [
      [
        { value: "Indicateur", fontWeight: "bold" },
        { value: "Valeur", fontWeight: "bold" },
      ],
      ...summary.map((row) => [{ value: row.label }, toCell(row.value)]),
    ],
  };

  const deviceSheet = {
    sheet: "Devices exposés",
    stickyRowsCount: 1,
    columns: [{ width: 26 }, { width: 22 }, { width: 55 }, { width: 55 }],
    data: [
      [
        { value: "Device", fontWeight: "bold" },
        { value: "Groupe RBAC", fontWeight: "bold" },
        { value: "Chemin(s) disque", fontWeight: "bold" },
        { value: "Chemin(s) registre", fontWeight: "bold" },
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
    sheet: "Vue d'ensemble",
    columns: [{ width: 28 }, { width: 12 }, ...overviewColumns.map(() => ({ width: 14 }))],
    data: [
      [{ value: `Application : ${appName}`, fontWeight: "bold", columnSpan: 2 + overviewColumns.length }],
      [],
      [
        { value: "Département", fontWeight: "bold" },
        { value: "Devices", fontWeight: "bold" },
        ...Object.keys(INSTALL_STATE_COLUMN_LABEL_FR).map((k) => ({
          value: INSTALL_STATE_COLUMN_LABEL_FR[k],
          fontWeight: "bold",
        })),
        { value: "Autres", fontWeight: "bold" },
      ],
      ...overview.map((row) => [
        { value: safeText(row.star) },
        { value: row.total, type: Number },
        ...Object.keys(INSTALL_STATE_COLUMN_LABEL_FR).map((k) => ({ value: row[k] || 0, type: Number })),
        { value: row.other || 0, type: Number },
      ]),
    ],
  };

  const usedSheetNames = new Set(["Vue d'ensemble"]);
  const starSheets = starNames.map((star) => {
    const sheetDevices = byStar[star] || [];
    return {
      sheet: uniqueSheetName(star, usedSheetNames),
      stickyRowsCount: 1,
      columns: [{ width: 24 }, { width: 30 }, { width: 16 }, { width: 16 }, { width: 26 }, { width: 20 }],
      data: [
        [
          { value: "Device", fontWeight: "bold" },
          { value: "Utilisateur", fontWeight: "bold" },
          { value: "Version installée", fontWeight: "bold" },
          { value: "État d'installation", fontWeight: "bold" },
          { value: "OS", fontWeight: "bold" },
          { value: "Dernière synchro", fontWeight: "bold" },
        ],
        ...sheetDevices.map((d) => [
          { value: safeText(d.deviceName) },
          { value: safeText(d.userPrincipalName) },
          { value: safeText(d.appVersion) },
          { value: INSTALL_STATE_COLUMN_LABEL_FR[d.installState] || d.installState || "Inconnu" },
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
  const cleaned = (rawName || "Département").replace(/[:\\/?*[\]]/g, "-").trim() || "Département";
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
  return { value: joinedPaths ? safeText(joinedPaths) : "Aucune évidence", wrap: true, alignVertical: "top" };
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
    sheet: "Postes",
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 10 }, { width: 24 }, { width: 14 }, { width: 24 }, { width: 10 }, { width: 26 }, { width: 20 }, { width: 20 }],
    data: [
      [
        { value: "Poste", fontWeight: "bold" },
        { value: "En ligne", fontWeight: "bold" },
        { value: "Dernière synchro", fontWeight: "bold" },
        { value: "Version agent", fontWeight: "bold" },
        { value: "Certificat (expire)", fontWeight: "bold" },
        { value: "Applications", fontWeight: "bold" },
        { value: "Groupes", fontWeight: "bold" },
        { value: "Dernière commande", fontWeight: "bold" },
        { value: "Envoyée le", fontWeight: "bold" },
      ],
      ...rows.map((r) => [
        { value: safeText(r.hostname) },
        { value: r.online ? "Oui" : "Non" },
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
    sheet: "Résumé par règle",
    stickyRowsCount: 1,
    columns: [{ width: 30 }, { width: 12 }, { width: 10 }, { width: 10 }, { width: 20 }, { width: 12 }],
    data: [
      [
        { value: "Règle", fontWeight: "bold" },
        { value: "Activée", fontWeight: "bold" },
        { value: "Postes", fontWeight: "bold" },
        { value: "Conformes", fontWeight: "bold" },
        { value: "Non conformes", fontWeight: "bold" },
        { value: "Inconnu", fontWeight: "bold" },
      ],
      ...summary.map((r) => [
        { value: safeText(r.name) },
        { value: r.enabled ? "Oui" : "Non" },
        { value: r.total, type: Number },
        { value: r.compliant, type: Number },
        { value: r.nonCompliant, type: Number },
        { value: r.unknown, type: Number },
      ]),
    ],
  };

  const detailSheet = {
    sheet: "Détail par poste",
    stickyRowsCount: 1,
    columns: [{ width: 30 }, { width: 22 }, { width: 16 }],
    data: [
      [
        { value: "Règle", fontWeight: "bold" },
        { value: "Poste", fontWeight: "bold" },
        { value: "Statut", fontWeight: "bold" },
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
    sheet: "CVE x poste",
    stickyRowsCount: 1,
    columns: [{ width: 18 }, { width: 12 }, { width: 10 }, { width: 18 }, { width: 22 }, { width: 28 }, { width: 16 }, { width: 14 }],
    data: [
      [
        { value: "CVE", fontWeight: "bold" },
        { value: "Sévérité", fontWeight: "bold" },
        { value: "CVSS", fontWeight: "bold" },
        { value: "Publiée", fontWeight: "bold" },
        { value: "Poste", fontWeight: "bold" },
        { value: "Logiciel", fontWeight: "bold" },
        { value: "Version installée", fontWeight: "bold" },
        { value: "Version affectée", fontWeight: "bold" },
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
    sheet: "Logiciels obsolètes",
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 20 }, { width: 26 }, { width: 16 }, { width: 10 }, { width: 14 }, { width: 14 }, { width: 40 }],
    data: [
      [
        { value: "Poste", fontWeight: "bold" },
        { value: "Type", fontWeight: "bold" },
        { value: "Logiciel / OS", fontWeight: "bold" },
        { value: "Version", fontWeight: "bold" },
        { value: "EOL", fontWeight: "bold" },
        { value: "Jours avant EOL", fontWeight: "bold" },
        { value: "Date de fin de support", fontWeight: "bold" },
        { value: "Constat", fontWeight: "bold" },
      ],
      ...data.map((r) => [
        { value: safeText(r.hostname) },
        { value: r.type },
        { value: safeText(r.name) },
        { value: safeText(r.version) },
        { value: r.isEol ? "Oui" : "Bientôt" },
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
    sheet: "Activités suspectes",
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 12 }, { width: 18 }, { width: 22 }, { width: 40 }, { width: 18 }, { width: 14 }, { width: 18 }, { width: 18 }, { width: 30 }],
    data: [
      [
        { value: "Poste", fontWeight: "bold" },
        { value: "Sévérité", fontWeight: "bold" },
        { value: "Signal", fontWeight: "bold" },
        { value: "Règle déclenchée", fontWeight: "bold" },
        { value: "Résumé", fontWeight: "bold" },
        { value: "Survenu le", fontWeight: "bold" },
        { value: "Statut", fontWeight: "bold" },
        { value: "Traité par", fontWeight: "bold" },
        { value: "Traité le", fontWeight: "bold" },
        { value: "Note", fontWeight: "bold" },
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
    sheet: "Vue d'ensemble",
    stickyRowsCount: 1,
    columns: [{ width: 26 }, { width: 12 }, { width: 30 }, { width: 10 }, { width: 10 }, { width: 10 }, { width: 12 }],
    data: [
      [
        { value: "Application", fontWeight: "bold" },
        { value: "Version", fontWeight: "bold" },
        { value: "Cibles", fontWeight: "bold" },
        { value: "Postes", fontWeight: "bold" },
        { value: "Réussis", fontWeight: "bold" },
        { value: "Échecs", fontWeight: "bold" },
        { value: "En attente", fontWeight: "bold" },
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

  const usedSheetNames = new Set(["Vue d'ensemble"]);
  const appSheets = appNames.map((name) => ({
    sheet: uniqueSheetName(name, usedSheetNames),
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 14 }, { width: 40 }, { width: 18 }],
    data: [
      [
        { value: "Poste", fontWeight: "bold" },
        { value: "Statut", fontWeight: "bold" },
        { value: "Résultat", fontWeight: "bold" },
        { value: "Terminé le", fontWeight: "bold" },
      ],
      ...(byApp[name] || []).map((d) => [
        { value: safeText(d.hostname) },
        { value: d.status === "ok" ? "Réussi" : d.status === "bad" ? "Échec" : "En attente" },
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
    sheet: "Mises à jour",
    stickyRowsCount: 1,
    columns: [{ width: 22 }, { width: 20 }, { width: 18 }, { width: 12 }, { width: 10 }, { width: 14 }, { width: 12 }, { width: 20 }, { width: 20 }, { width: 20 }],
    data: [
      [
        { value: "Poste", fontWeight: "bold" },
        { value: "Groupe", fontWeight: "bold" },
        { value: "Statut", fontWeight: "bold" },
        { value: "Disponibles", fontWeight: "bold" },
        { value: "À faire", fontWeight: "bold" },
        { value: "En cours", fontWeight: "bold" },
        { value: "Installées", fontWeight: "bold" },
        { value: "Installées le", fontWeight: "bold" },
        { value: "Forcé le", fontWeight: "bold" },
        { value: "Dernière vérif.", fontWeight: "bold" },
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
