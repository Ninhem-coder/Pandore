import { POLICY_STATUS_COLORS } from "../theme.js";

/**
 * Reste du module d'origine (port de build_compliance_devices_tab_html(), grille par OS +
 * "journal d'incidents") après la refonte "Conformité" du 2026-08-28 (maquette validée par
 * Nicolas — score de posture, file de priorité, politiques classées par impact, table de
 * postes filtrable, voir IntuneTab.jsx/ComplianceDeviceTable.jsx) : `OsCard`/`LogRow`/l'export
 * par défaut `ComplianceOsGrid` (grille par carte OS) ont été retirés, plus aucun appelant
 * après cette refonte. Les 4 exports ci-dessous restent : `DeviceSettingsPanel`,
 * `computeSettingsState` et `ReconciliationNote` sont réutilisés à l'identique par
 * `DeviceOverviewTab.jsx` (drill-down par réglage sur la Vue Appareil 360°) ET par la nouvelle
 * `ComplianceDeviceTable.jsx` — la logique de réconciliation Graph/réglages ne doit vivre qu'à
 * un seul endroit. `StateBadge` reste exportée (déjà publique) même si aucun autre fichier ne
 * l'importe directement aujourd'hui : elle est utilisée en interne par `DeviceSettingsPanel`.
 */

/**
 * Une valeur d'état rendue en pastille colorée (point + libellé au survol via `title`).
 */
export function StateBadge({ state }) {
  if (!state) return <span className="cve-small">—</span>;
  const color = POLICY_STATUS_COLORS[state] || POLICY_STATUS_COLORS.unknown;
  return (
    <span className="cve-badge" style={{ borderColor: `${color}66`, color }}>
      {state}
    </span>
  );
}

/**
 * État recalculé d'UN device pour LA politique de la ligne, d'après ses réglages individuels
 * (settingStates). Priorité : error (au moins un réglage `error`/`conflict`) > nonCompliant
 * (au moins un réglage non conforme) > compliant (tous conformes) — un seul réglage en échec
 * ou en erreur suffit à faire échouer la politique dans le portail Intune, la même règle
 * s'applique ici (pas de moyenne/majorité). `null` quand on ne sait pas encore (chargement,
 * erreur réseau, ou aucun réglage remonté par Graph pour ce couple device/politique).
 */
export function computeSettingsState(entry) {
  if (!entry || entry.loading || entry.error) return null;
  const settings = entry.settings || [];
  if (settings.length === 0) return null;
  const states = settings.map((s) => (s.state || "").toLowerCase());
  if (states.some((s) => s === "error" || s === "conflict")) return "error";
  const allCompliant = states.every((s) => s === "compliant");
  return allCompliant ? "compliant" : "nonCompliant";
}

/**
 * Note de réconciliation courte, sous le détail par réglage d'une ligne dépliée.
 */
export function ReconciliationNote({ policyStatus, settings }) {
  const allSettingsCompliant = settings.length > 0 && settings.every((s) => (s.state || "").toLowerCase() === "compliant");
  const policyStatusLower = (policyStatus || "").toLowerCase();
  if (!(allSettingsCompliant && policyStatusLower && policyStatusLower !== "compliant")) return null;
  return (
    <p className="footnote">
      Statut recalculé : <strong>conforme</strong> (réglages ci-dessus tous compliant).
      <span
        className="footnote-why"
        title={`L'agrégat Graph par politique affiche encore « ${policyStatus} » : écart connu entre l'agrégat mis en cache côté Microsoft et l'évaluation en direct des paramètres, qui fait foi ici.`}
      >
        pourquoi ↗
      </span>
    </p>
  );
}

// Traductions FR des noms de réglage bruts Graph (2026-09-02, demande de Nicolas — "tu peux me
// mettre sur les sous paramètres ces noms la ?"). Deux tables, pas une seule, parce que les
// réglages Microsoft "de base" (Device_HealthAttestation/*, ./DevDetail/*) portent un
// `settingName` UNIQUE ET STABLE quelle que soit la politique qui le référence, alors que les
// politiques "custom" du tenant ("[ORG] Windows - Check ...") réutilisent des `settingName`
// GÉNÉRIQUES/gabarits (ex. "BOOL_IsEquals_true" apparaît sur Disable NetBIOS/SMBv1/LLMNR/IPv6
// avec un sens DIFFÉRENT à chaque fois, confirmé par la liste fournie par Nicolas) — la
// traduction pour celles-ci doit donc être scopée par (nom de politique, settingName), pas par
// settingName seul, sous peine d'afficher le même libellé sur 4 réglages différents.
const _GLOBAL_SETTING_LABELS_FR = {
  "Device_HealthAttestation/SecureBootEnabled": "Secure Boot activé",
  "Device_HealthAttestation/BitLockerEnabled": "BitLocker activé",
  "./DevDetail/SwV": "Bonne version de Windows",
};

const _POLICY_SETTING_LABELS_FR = {
  "Windows - Check Disable NetBIOS": { BOOL_IsEquals_true: "NetBIOS est bien désactivé" },
  "Windows - Check isAutopilot": { Name_IsEquals_Autopilot: "Appareil bien dans Autopilot" },
  "Windows - Check Disable SMBv1 Server": { BOOL_IsEquals_true: "SMBv1 Server bien désactivé" },
  "Windows - Check Disable LLMNR": { BOOL_IsEquals_true: "LLMNR bien désactivé" },
  "Windows - Check Security Apps : MDE": {
    RealTimeProtectionEnabled_IsEquals_Yes: "Real Time Protection activé",
    EDRBlockMode_IsEquals_Yes: "Block Mode activé",
    Service_IsEquals_Yes: "Service bien activé",
    AMRunningMode_IsEquals_Yes: "Antivirus bien démarré",
    IsTamperProtected_IsEquals_Yes: "Tamper Protection activé",
    EDRCloudBlock_IsEquals_Yes: "Cloud Block activé",
    EnableNetworkProtection_IsEquals_Yes: "Network Protection activé",
  },
  "Windows - Check SID Local Account": { SID_Status_IsEquals_Compliant: "Pas de SID de compte local" },
  "Windows - Check Disable IPv6": { BOOL_IsEquals_true: "IPv6 bien désactivé" },
  "Windows - Check Hostname": { Name_IsEquals_true: "Le nom du poste est au bon format" },
  "Windows - Check isActive": { BOOL_IsEquals_True: "Appareil bien actif" },
  "Windows - Check Admin Local": { Name_IsEquals_False: "Compte Administrateur local non présent" },
  "Windows - Check Security App : SentinelOne": {
    Service_IsEquals_Yes: "Service bien activé",
    ServiceStatus_IsEquals_Running: "Le service est bien fonctionnel",
    IsInstalled_IsEquals_Yes: "SentinelOne est bien installé",
    UninstallEntry_IsEquals_Yes: "Possibilité de le désinstaller",
    SentinelLabsKey_IsEquals_Yes: "SentinelLabsKey présente",
  },
};

/** Libellé FR d'un réglage, si connu — sinon `null` (l'appelant retombe sur le nom brut
 * Graph). Le composite (politique, settingName) est vérifié EN PREMIER (plus spécifique) avant
 * le générique (settingName seul), pour ne jamais laisser un match générique masquer une
 * traduction plus précise si les deux existaient un jour pour le même settingName.
 *
 * ⚠️ `setting.setting` (≈ `instanceDisplayName`), PAS `setting.settingName`, porte la clé
 * technique complète attendue par la liste de Nicolas — repéré EN TESTANT contre le tenant
 * de production (pas deviné) : Graph renvoie par exemple `setting: "Device_HealthAttestation/
 * SecureBootEnabled"` mais `settingName: "Windows10CompliancePolicy.SecureBootEnabled"` (un
 * identifiant interne différent, jamais celui donné par Nicolas) ; de même `setting:
 * "RealTimeProtectionEnabled_IsEquals_Yes"` (le suffixe `_IsEquals_Yes` cité par Nicolas) vs
 * `settingName: "RealTimeProtectionEnabled"` (sans suffixe). Utiliser `settingName` en premier
 * (comme dans une première version de cette fonction) fait échouer TOUS les lookups en
 * silence — jamais d'erreur, juste un repli permanent sur le nom brut. */
function _settingLabelFr(policyName, setting) {
  const raw = setting.setting || setting.instanceDisplayName || setting.settingName;
  if (!raw) return null;
  // Clés de la table SANS préfixe d'organisation : "[ORG] Windows - Check X" et "Windows - Check
  // X" partagent les mêmes libellés, quel que soit le préfixe utilisé par le tenant.
  const policyKey = policyName ? policyName.replace(/^\[[^\]]+\]\s*/, "") : null;
  const composite = policyKey ? _POLICY_SETTING_LABELS_FR[policyKey]?.[raw] : null;
  return composite || _GLOBAL_SETTING_LABELS_FR[raw] || null;
}

/** `policyName` (2026-09-02, ajouté pour la traduction FR ci-dessus) : le `displayName` de LA
 * politique dont ce détail par réglage est issu — nécessaire pour le lookup composite
 * (politique, settingName) sur les politiques "custom" du tenant. `undefined` reste toléré
 * (retombe sur la table globale puis sur le nom brut Graph), pas de rupture pour un appelant
 * qui ne le fournirait pas encore. */
export function DeviceSettingsPanel({ state, policyStatus, policyName }) {
  if (state.loading) {
    return <p className="empty cve-small">Chargement du détail par paramètre…</p>;
  }
  if (state.error) {
    return <p className="empty cve-small">Impossible de récupérer le détail : {state.error}</p>;
  }
  const settings = state.settings || [];
  if (settings.length === 0) {
    return <p className="empty cve-small">Aucun paramètre remonté par Graph pour ce couple device/politique.</p>;
  }
  return (
    <div className="settings-panel">
      {settings.map((s, i) => {
        // Graph renvoie "0" (chaîne) en `errorDescription` pour un réglage SANS erreur réelle
        // (`errorCode: 0`, confirmé en direct contre le tenant de production) — pas un message
        // à afficher, juste l'écho stringifié du code. Sans ce garde-fou, chaque ligne
        // conforme affichait littéralement "0" à côté de son nom.
        const detail =
          (s.errorDescription && s.errorDescription !== "0" ? s.errorDescription : "") ||
          (s.sources?.length ? s.sources.map((src) => src.displayName).join(", ") : "");
        const label = _settingLabelFr(policyName, s) || s.instanceDisplayName || s.settingName || s.setting || "—";
        return (
          <div className="setting-row" key={`${s.setting || s.settingName || i}`}>
            <StateBadge state={s.state} />
            <span className="setting-name">{label}</span>
            {detail && <span className="setting-detail">{detail}</span>}
          </div>
        );
      })}
      <ReconciliationNote policyStatus={policyStatus} settings={settings} />
    </div>
  );
}
