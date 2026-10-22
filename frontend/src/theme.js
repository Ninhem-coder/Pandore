import { localizedTable, tr } from "./i18n/core.js";
/**
 * Design tokens purs du dashboard : seuils, couleurs, libellés FR et petites fonctions de
 * mise en forme qui n'opèrent QUE sur ces tables (bucketing d'un score dans un palier, choix
 * d'un libellé pour une clé). Rien ici ne lit une structure de données métier (machines,
 * alertes, politiques de conformité...) — c'est ce qui distingue ce fichier de
 * `selectors.js` depuis la revue d'architecture du 2026-08-17 : ce dernier concentre les
 * DÉRIVATIONS (agrégations, jointures, tris) qui transforment les réponses de l'API en
 * données affichables, et importe ici les tokens dont il a besoin (palettes, clés de
 * gravité) plutôt que de les redéfinir.
 *
 * Avant cette scission, les deux catégories cohabitaient dans un seul fichier de 787 lignes
 * — un token de couleur et une fonction de 170 lignes qui reconstruit tout l'onglet
 * "Conformité Intune" n'ont pourtant ni la même durée de vie, ni les mêmes raisons de
 * changer, ni le même profil de risque en revue de code.
 */

/**
 * Seuils et couleurs repris à l'identique de scripts/build_exposure_html.py (skill
 * audit-exposure-score) : mêmes seuils Microsoft (0-29 low / 30-69 medium / 70-100
 * high), mêmes teintes. Un seul endroit à modifier si la palette du skill change un
 * jour, plutôt que de la redéfinir en dur dans chaque composant.
 */
export const THRESHOLDS = [
  { lo: 0, hi: 29, level: "low", color: "#48C98A", glow: "rgba(72,201,138,0.55)" },
  { lo: 30, hi: 69, level: "medium", color: "#E7A33C", glow: "rgba(231,163,60,0.55)" },
  { lo: 70, hi: 100, level: "high", color: "#EA5C5C", glow: "rgba(234,92,92,0.55)" },
];

export function levelForScore(score) {
  const s = Math.max(0, Math.min(100, score));
  return THRESHOLDS.find((t) => s >= t.lo && s <= t.hi) ?? THRESHOLDS[THRESHOLDS.length - 1];
}

/**
 * Seuils du Secure Score (onglet "Secure Score", indépendant, 2026-08-10) — mêmes trois
 * teintes que THRESHOLDS ci-dessus, mais sémantique INVERSÉE : pour l'Exposure Score, un
 * score BAS est bon (peu de risque) ; pour le Secure Score, un score HAUT est bon (le
 * tenant applique davantage de mesures de sécurité). Réutiliser THRESHOLDS tel quel aurait
 * coloré un bon Secure Score en rouge — d'où ce mapping dédié, passé à MedallionGauge via
 * sa prop `colorForScore`.
 */
export const SECURE_SCORE_THRESHOLDS = [
  { lo: 0, hi: 49, level: "high", color: "#EA5C5C" },
  { lo: 50, hi: 74, level: "medium", color: "#E7A33C" },
  { lo: 75, hi: 100, level: "low", color: "#48C98A" },
];

export function secureScoreLevel(percentage) {
  const p = Math.max(0, Math.min(100, percentage ?? 0));
  return SECURE_SCORE_THRESHOLDS.find((t) => p >= t.lo && p <= t.hi) ?? SECURE_SCORE_THRESHOLDS[0];
}

// Libellé de controlCategory (Identity/Data/Device/Apps/Infrastructure), vocabulaire
// Graph /security/secureScoreControlProfiles — distinct du vocabulaire de conformité Intune.
// Label tables below are `localizedTable`s: values are read in the current interface language.
export const SECURE_SCORE_CATEGORY_LABEL = localizedTable("secureScore.category", [
  "Identity",
  "Data",
  "Device",
  "Apps",
  "Infrastructure",
]);

// Traduction FR des valeurs `threats` de secureScoreControlProfiles (Graph) — liste fermée
// aux valeurs officiellement documentées par Microsoft ; toute valeur absente de cette table
// retombe sur un "humanize" générique (camelCase -> "Camel Case") plutôt qu'une traduction
// inventée, pour ne jamais afficher un libellé FR non vérifié. Ajoutée le 2026-08-12 (demande
// de Nicolas — cybersécurité junior cherchant à comprendre CE QUE chaque contrôle protège, pas
// seulement combien de points il rapporte).
export const SECURE_SCORE_THREAT_LABEL = localizedTable("secureScore.threat", [
  "accountBreach",
  "dataExfiltration",
  "dataSpillage",
  "elevationOfPrivilege",
  "maliciousInsider",
  "malware",
  "phishing",
  "ransomware",
  "passwordSpray",
  "denialOfService",
  "unknown",
]);

/** "TitleCase" générique pour un identifiant camelCase Graph sans traduction FR connue —
 * plutôt que d'afficher la valeur brute (`elevationOfPrivilege`) ou de deviner une
 * traduction non vérifiée. */
function humanizeThreat(value) {
  if (!value) return value;
  const spaced = value.replace(/([a-z0-9])([A-Z])/g, "$1 $2");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function translateThreat(value) {
  return SECURE_SCORE_THREAT_LABEL[value] || humanizeThreat(value);
}

// Mêmes couleurs que COMPLIANCE_COLORS / COMPLIANCE_LABEL du skill
export const COMPLIANCE_COLORS = {
  compliant: "#48C98A",
  noncompliant: "#EA5C5C",
  inGracePeriod: "#E7A33C",
};
export const COMPLIANCE_DEFAULT_COLOR = "#6B6E76";

export const COMPLIANCE_LABEL = localizedTable("compliance.state", [
  "compliant",
  "noncompliant",
  "inGracePeriod",
  "unknown",
  "conflict",
  "error",
  "configManager",
  "notApplicable",
]);

/**
 * Couleurs des statuts BRUTS Graph par politique (`d.status`/`d.deviceComplianceState`,
 * ex. "nonCompliant", "conflict", "notAssigned"...) — vocabulaire plus fin que
 * `COMPLIANCE_COLORS` ci-dessus (qui ne couvre que l'état GLOBAL d'un appareil :
 * compliant/noncompliant/inGracePeriod). Utilisé par le tableau détaillé de
 * ComplianceOsGrid.jsx (badges "État (politique)"/"État (appareil)"). Centralisé ici
 * (était dupliqué en `STATUS_COLORS` local à ComplianceOsGrid.jsx) pour rester cohérent
 * avec le principe déjà affiché en tête de ce fichier : un seul endroit à modifier.
 */
export const POLICY_STATUS_COLORS = {
  nonCompliant: "#EA5C5C",
  noncompliant: "#EA5C5C",
  error: "#E08052",
  conflict: "#E08052",
  notApplicable: "#6B6E76",
  notapplicable: "#6B6E76",
  unknown: "#7C8896",
  notAssigned: "#7C8896",
  compliant: "#48C98A",
  inGracePeriod: "#E7A33C",
};

/**
 * Libellé FR pour un état BRUT Graph par politique (même vocabulaire que POLICY_STATUS_COLORS
 * ci-dessus) — centralisé ici le 2026-08-19 (était dupliqué en `STATUS_LABEL_FR` local à
 * ComplianceOsGrid.jsx) après un bug signalé par Nicolas sur la Vue Appareil 360° : cette page
 * lisait `s.status` (qui n'existe pas sur ces lignes — voir `intune/compliance.py` et
 * `intune/compliance_detail.py::_device_policy_states`, le champ Graph s'appelle `state`) ET
 * cherchait ce statut dans `COMPLIANCE_LABEL`, la table de l'état GLOBAL d'un appareil
 * (compliant/noncompliant/inGracePeriod, tout minuscule) plutôt que celle-ci — d'où le badge
 * "?" sur chaque ligne, jamais la vraie conformité par politique.
 */
export const POLICY_STATUS_LABEL = localizedTable("policyStatus", [
  "compliant",
  "nonCompliant",
  "noncompliant",
  "error",
  "conflict",
  "notApplicable",
  "notapplicable",
  "inGracePeriod",
  "unknown",
  "notAssigned",
]);

export function policyStatusLabel(state) {
  if (!state) return "—";
  return POLICY_STATUS_LABEL[state] || state;
}

/**
 * Ordre de gravité des mêmes états BRUTS Graph par politique — centralisé en même temps que
 * POLICY_STATUS_LABEL ci-dessus (était `STATUS_SEVERITY` local à ComplianceOsGrid.jsx).
 * Sert à trier une liste de statuts pour faire remonter les échecs en tête plutôt que de les
 * laisser dans un ordre d'API non significatif — voir DeviceOverviewTab.jsx et
 * ComplianceOsGrid.jsx.
 */
export const POLICY_STATUS_SEVERITY = {
  nonCompliant: 0,
  noncompliant: 0,
  error: 1,
  conflict: 1,
  inGracePeriod: 2,
  pending: 3,
  notApplicable: 4,
  notapplicable: 4,
  compliant: 5,
  unknown: 6,
  notAssigned: 6,
};

export function policyStatusSeverity(state) {
  return POLICY_STATUS_SEVERITY[(state || "").trim()] ?? 6;
}

/**
 * Couleurs par sévérité CVE (page "Vulnérabilités", sous-catégorie Defender, 2026-08-10) —
 * vocabulaire Microsoft Defender Vulnerability Management (`Critical`/`High`/`Medium`/`Low`),
 * distinct du vocabulaire de conformité Intune (`POLICY_STATUS_COLORS` ci-dessus) même si
 * certaines teintes se recoupent volontairement (rouge = grave dans les deux cas).
 */
export const CVE_SEVERITY_COLORS = {
  Critical: "#EA5C5C",
  High: "#E08052",
  Medium: "#E7A33C",
  Low: "#48C98A",
  Unknown: "#7C8896",
};

/**
 * Traduit les messages d'erreur techniques (souvent en anglais, issus de `fetch`/du
 * navigateur, ex. "Failed to fetch") en une phrase compréhensible pour Nicolas, tout en
 * gardant le message brut disponible pour le diagnostic (revue de code frontend, 💡
 * suggestion #12 — "friendlier error-message UI"). Ne masque jamais le message d'origine :
 * `raw` est toujours renvoyé, pour qu'on puisse le montrer en repli/détail technique.
 */
export function friendlyErrorMessage(raw) {
  const message = typeof raw === "string" ? raw : tr("error.unknown");
  const lower = message.toLowerCase();
  if (lower.includes("failed to fetch") || lower.includes("networkerror") || lower.includes("load failed")) {
    return { text: tr("error.serverDown"), raw: message };
  }
  if (lower.includes("econnrefused") || lower.includes("connection refused")) {
    return { text: tr("error.connectionRefused"), raw: message };
  }
  return { text: message, raw: message };
}

/**
 * Accord au pluriel des libellés d'état ("Non conforme" -> "non conformes", "Erreur" ->
 * "erreurs", "En attente" -> invariable). Centralisé ici (était dupliqué à l'identique
 * dans IntuneTab.jsx et ComplianceOsGrid.jsx) pour qu'un futur ajout de catégorie
 * (ex. un pluriel irrégulier) ne se corrige qu'à un seul endroit.
 */
export function pluralCategory(category, n) {
  const base = category.toLowerCase();
  if (n <= 1) return base;
  if (base === "erreur") return "erreurs";
  if (base === "en attente") return "en attente"; // invariable
  return `${base}s`;
}

// Palette générique pour les camemberts "libres" (onboarding, OS, santé) sans état
// sémantique compliant/noncompliant — même dégradé ambre->rouge->gris que la palette
// "échecs par politique" du skill, réutilisé ici pour rester cohérent visuellement.
export const GENERIC_PALETTE = ["#E7A33C", "#48C98A", "#EA5C5C", "#E08052", "#6B6E76", "#C98C36", "#A97431"];

// Couleurs par OS pour l'onglet "Conformité Intune" (camembert "Par OS" + liseré/pastille
// des cartes compliance-os-grid) — mêmes teintes que l'export de référence du skill.
export const OS_COLORS = {
  Windows: "#E7A33C",
  Android: "#EA5C5C",
  iOS: "#48C98A",
  macOS: "#48C98A",
  Linux: "#6B6E76",
};
export const OS_DEFAULT_COLOR = "#6B6E76";

// Couleurs par niveau d'exposition MDE (`exposureLevel` de /api/machines) — onglet
// "Widgets (test)" (2026-08-12), camembert "Répartition par niveau d'exposition"
// (équivalent du "Device exposure distribution" du dashboard natif MDVM). Même dégradé
// sémantique que CVE_SEVERITY_COLORS (rouge = grave) plutôt qu'une nouvelle palette.
export const EXPOSURE_LEVEL_COLORS = {
  High: "#EA5C5C",
  Medium: "#E7A33C",
  Low: "#48C98A",
  None: "#6B6E76",
  Unknown: "#7C8896",
};
export const EXPOSURE_LEVEL_LABEL = localizedTable("exposure", ["High", "Medium", "Low", "None", "Unknown"]);

// Couleurs de sévérité des alertes MDE (`severity` de /api/alerts) — onglet
// "Widgets (test)", tableau "Top alertes actives". Vocabulaire distinct de CVE_SEVERITY_COLORS
// (pas de "Critical" côté alertes MDE, "Informational" en plus) — palette dédiée plutôt que
// de réutiliser CVE_SEVERITY_COLORS et masquer cette différence.
export const ALERT_SEVERITY_COLORS = {
  High: "#EA5C5C",
  Medium: "#E7A33C",
  Low: "#48C98A",
  Informational: "#7C8896",
  UnSpecified: "#7C8896",
};

// Libellés FR (2026-08-28, refonte "Alertes Defender" — maquette validée par Nicolas) :
// jusqu'ici la sévérité s'affichait telle quelle en anglais (badge ET légende de camembert),
// seul champ d'alerte resté non traduit alors que statut/classification le sont déjà
// (ALERT_STATUS_LABEL/ALERT_CLASSIFICATION_LABEL ci-dessous).
export const ALERT_SEVERITY_LABEL = localizedTable("alertSeverity", ["High", "Medium", "Low", "Informational", "UnSpecified"]);

// V42 (2026-08-17, demande de Nicolas — onglet "Widgets (test)" refondu en dashboard
// "Alertes Defender") : statut d'alerte MDE (`status` de /api/alerts), valeurs confirmées
// via la doc publique Microsoft (Get alerts API, learn.microsoft.com/defender-endpoint) —
// Unknown/New/InProgress/Resolved, PAS les statuts d'incident Graph Security ("active"/
// "inProgress"/"resolved" en minuscules) qui sont un vocabulaire différent : ce dashboard
// consomme bien l'API MDE native (defender/client.py::MDE_API_BASE), pas Graph Security.
export const ALERT_STATUS_COLORS = {
  New: "#E7A33C",
  InProgress: "#4C9FE0",
  Resolved: "#48C98A",
  Unknown: "#7C8896",
};

export const ALERT_STATUS_LABEL = localizedTable("alertStatus", ["New", "InProgress", "Resolved", "Unknown"]);

// Classification d'une alerte (`classification`, nullable tant qu'un analyste ne l'a pas
// qualifiée) — "Informational, expected activity" est la valeur littérale renvoyée par
// l'API (avec la virgule), jamais réécrite côté backend : on la mappe telle quelle ici.
export const ALERT_CLASSIFICATION_COLORS = {
  TruePositive: "#EA5C5C",
  FalsePositive: "#48C98A",
  "Informational, expected activity": "#7C8896",
  "Non classifiée": "#4C4F58",
};

export const ALERT_CLASSIFICATION_LABEL = localizedTable("alertClassification", [
  "TruePositive",
  "FalsePositive",
  "Informational, expected activity",
  "Non classifiée",
]);

// Onglet "Secure Score" > "Par criticité" (2026-08-12) : les 3 blocs sont les niveaux
// d'exposition MDE qui représentent un vrai risque à traiter — "None" (aucune exposition)
// est délibérément exclu, il n'y a rien à cliquer/prioriser pour ce niveau. Ordre du plus
// au moins critique (affichage des blocs de gauche à droite).
export const CRITICALITY_LEVELS = ["High", "Medium", "Low"];

/**
 * Gravité décroissante des catégories d'état. Sert à retenir, pour un appareil vu sur
 * plusieurs politiques, sa situation la PLUS grave — un poste non conforme quelque part reste
 * non conforme, même s'il est "non applicable" ailleurs. Utilisé par
 * `selectors.js::groupComplianceDetailByOS` — token de conformité, donc défini ici.
 */
export const SEVERITY = ["Non conforme", "Erreur", "En attente", "Non applicable", "Conforme"];

/**
 * Catégories qui constituent un VRAI manquement, et qui seules alimentent les compteurs mis en
 * avant (pastille de carte OS, camembert "Par OS", total d'appareils).
 *
 * "Non applicable" et "En attente" en sont volontairement exclus : ce ne sont pas des fautes,
 * la politique n'a simplement pas été évaluée sur l'appareil. Ils restent listés dans les
 * tableaux (demande de Nicolas : les voir, différenciés par la colonne État) mais ne doivent
 * pas gonfler les chiffres — les inclure avait fait passer Android de 71 à près de 200
 * appareils du seul fait des 163 "non applicable" de la politique Defender Threat Level.
 */
export const FAILING_CATEGORIES = ["Non conforme", "Erreur"];

/**
 * The categories above are internal identifiers (French words, kept as-is in the data); this
 * returns the label to display in the current interface language.
 */
const CATEGORY_KEYS = {
  "Non conforme": "noncompliant",
  Erreur: "error",
  "En attente": "pending",
  "Non applicable": "notApplicable",
  Conforme: "compliant",
};

export function categoryLabel(category) {
  const key = CATEGORY_KEYS[category];
  return key ? tr(`complianceCategory.${key}`) : category;
}

/** "aujourd'hui" / "il y a 1j" / "il y a 6j" — même esprit que les horodatages mono du
 * reste du dashboard, mais relatif (plus lisible que la date ISO pour "il y a 7 jours"). */
export function formatRelativeDays(dateStr, now = new Date()) {
  const then = new Date(dateStr);
  if (Number.isNaN(then.getTime())) return tr("relative.unknownDate");
  const todayMidnight = new Date(now).setHours(0, 0, 0, 0);
  const thenMidnight = new Date(then).setHours(0, 0, 0, 0);
  const diffDays = Math.floor((todayMidnight - thenMidnight) / (24 * 60 * 60 * 1000));
  if (diffDays <= 0) return tr("relative.today");
  return tr("relative.daysAgo", { count: diffDays });
}
