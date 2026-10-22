/**
 * Demo dataset — entirely FICTIONAL, generated in the browser from a fixed seed so every launch
 * (and every screenshot) shows the same fleet. Nothing here comes from a real tenant: device
 * names use the DEMO- prefix, users the reserved `demo.example` domain, IDs are generated.
 *
 * Shapes mirror the real API responses (keys and enum values captured from the backend), so
 * the dashboard renders exactly as it does against Microsoft Graph / Defender / Vanitas.
 * Used only when the app runs with `VITE_DEMO=true` (`npm run demo`); see demo/server.js.
 */

// ── Deterministic helpers ──────────────────────────────────────────────────────────────────

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = mulberry32(20261021);
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const int = (min, max) => min + Math.floor(rand() * (max - min + 1));
const chance = (p) => rand() < p;
const weighted = (pairs) => {
  const total = pairs.reduce((s, [, w]) => s + w, 0);
  let r = rand() * total;
  for (const [v, w] of pairs) {
    r -= w;
    if (r <= 0) return v;
  }
  return pairs[pairs.length - 1][0];
};
const hex = (n) => Array.from({ length: n }, () => Math.floor(rand() * 16).toString(16)).join("");
const uuid = () => `${hex(8)}-${hex(4)}-4${hex(3)}-${pick(["8", "9", "a", "b"])}${hex(3)}-${hex(12)}`;
const pad = (n, w) => String(n).padStart(w, "0");

const NOW = Date.now();
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const iso = (ms) => new Date(ms).toISOString();
const ago = (ms) => iso(NOW - ms);
const dateOnly = (ms) => iso(ms).slice(0, 10);

export const DOMAIN = "demo.example";

// ── People ─────────────────────────────────────────────────────────────────────────────────

const FIRST = ["alice", "bruno", "chloe", "david", "emma", "felix", "gabrielle", "hugo", "ines", "jules", "karim", "lea", "marc", "nina", "oscar", "pauline", "quentin", "rose", "samuel", "tania", "ugo", "victoire", "william", "yasmine", "zoe", "adrien", "basile", "camille", "diane", "elias"];
const LAST = ["martin", "bernard", "dubois", "thomas", "robert", "richard", "petit", "durand", "leroy", "moreau", "simon", "laurent", "lefebvre", "michel", "garcia", "david", "bertin", "roux", "vincent", "fournier"];
export const DEPARTMENTS = ["Finance", "Ressources humaines", "Ventes", "Informatique", "Support client", "Marketing", "Logistique", "Direction"];

const users = [];
for (let i = 0; i < 70; i++) {
  const first = FIRST[i % FIRST.length];
  const last = LAST[(i * 7) % LAST.length];
  const upn = `${first}.${last}@${DOMAIN}`;
  if (users.some((u) => u.upn === upn)) continue;
  users.push({
    id: uuid(),
    upn,
    displayName: `${first[0].toUpperCase()}${first.slice(1)} ${last[0].toUpperCase()}${last.slice(1)}`,
    department: DEPARTMENTS[i % DEPARTMENTS.length],
  });
}
export const USERS = users;

// ── Intune devices ─────────────────────────────────────────────────────────────────────────

const WIN_VERSIONS = [
  ["10.0.26100.2033", "Windows11", 45],
  ["10.0.22631.4317", "Windows11", 40],
  ["10.0.19045.5011", "Windows10", 15],
];
const MODELS = [
  ["Dell Inc.", "Latitude 7440"],
  ["Dell Inc.", "OptiPlex 7010"],
  ["LENOVO", "ThinkPad T14 Gen 4"],
  ["HP", "EliteBook 840 G10"],
  ["Microsoft Corporation", "Surface Laptop 5"],
];

function makeDevice(name, os, idx) {
  const user = users[idx % users.length];
  let osVersion;
  let defenderPlatform = null;
  let manufacturer;
  let model;
  if (os === "Windows") {
    const v = weighted(WIN_VERSIONS.map((x) => [x, x[2]]));
    osVersion = v[0];
    defenderPlatform = v[1];
    [manufacturer, model] = pick(MODELS);
  } else if (os === "macOS") {
    osVersion = pick(["14.6.1", "15.0.1", "14.7"]);
    defenderPlatform = "macOS";
    manufacturer = "Apple";
    model = pick(["MacBook Pro (14-inch, 2023)", "MacBook Air (M2, 2022)"]);
  } else if (os === "Android") {
    osVersion = pick(["14", "13", "15"]);
    manufacturer = pick(["samsung", "Google"]);
    model = manufacturer === "Google" ? "Pixel 8" : "Galaxy A54 5G";
  } else {
    osVersion = pick(["17.6.1", "18.0.1"]);
    manufacturer = "Apple";
    model = "iPhone 14";
  }
  const complianceState = weighted([
    ["compliant", 84],
    ["noncompliant", 8],
    ["inGracePeriod", 4],
    ["unknown", 4],
  ]);
  const lastSync = NOW - int(10, 60 * 30) * 60_000; // 10 min à 30 h
  const enrolled = NOW - int(20, 700) * DAY;
  return {
    id: uuid(),
    userId: user.id,
    deviceName: name,
    managedDeviceOwnerType: "company",
    managementState: "managed",
    enrolledDateTime: iso(enrolled),
    lastSyncDateTime: iso(lastSync),
    operatingSystem: os,
    complianceState,
    jailBroken: "False",
    managementAgent: "mdm",
    osVersion,
    azureADRegistered: true,
    deviceEnrollmentType: os === "Windows" ? "windowsAzureADJoin" : "userEnrollment",
    emailAddress: user.upn,
    azureADDeviceId: uuid(),
    deviceRegistrationState: "registered",
    deviceCategoryDisplayName: os,
    isSupervised: false,
    exchangeAccessState: "none",
    exchangeAccessStateReason: "none",
    isEncrypted: complianceState === "compliant" || chance(0.5),
    userPrincipalName: user.upn,
    model,
    manufacturer,
    imei: null,
    complianceGracePeriodExpirationDateTime: complianceState === "inGracePeriod" ? iso(NOW + int(1, 5) * DAY) : "9999-12-31T23:59:59Z",
    serialNumber: `DEMO${hex(6).toUpperCase()}`,
    phoneNumber: null,
    androidSecurityPatchLevel: os === "Android" ? dateOnly(NOW - int(20, 120) * DAY) : null,
    userDisplayName: user.displayName,
    wiFiMacAddress: hex(12).toUpperCase(),
    deviceHealthAttestationState: null,
    subscriberCarrier: "",
    meid: null,
    totalStorageSpaceInBytes: pick([256, 512, 1024]) * 1_000_000_000,
    freeStorageSpaceInBytes: int(40, 300) * 1_000_000_000,
    managedDeviceName: `${user.upn.split("@")[0]}_${os}`,
    partnerReportedThreatState: "secured",
    managementCertificateExpirationDate: iso(NOW + int(200, 400) * DAY),
    ethernetMacAddress: os === "Windows" ? hex(12).toUpperCase() : "",
    physicalMemoryInBytes: pick([8, 16, 32]) * 1_073_741_824,
    enrollmentProfileName: "",
    deviceActionResults: [],
    // champs internes à la démo (jamais lus par l'UI)
    _defenderPlatform: defenderPlatform,
    _department: user.department,
    _user: user,
  };
}

const devices = [];
for (let i = 1; i <= 96; i++) devices.push(makeDevice(`DEMO-WKS-${pad(i, 3)}`, "Windows", i));
for (let i = 1; i <= 10; i++) devices.push(makeDevice(`DEMO-MAC-${pad(i, 2)}`, "macOS", i + 3));
for (let i = 1; i <= 20; i++) devices.push(makeDevice(`DEMO-MOB-${pad(i, 2)}`, "Android", i + 11));
for (let i = 1; i <= 6; i++) devices.push(makeDevice(`DEMO-IOS-${pad(i, 2)}`, "iOS", i + 29));
// Poste « vitrine » utilisé par les captures d'écran (fiche appareil) : non conforme et non
// chiffré, avec des alertes actives (voir la boucle des alertes plus bas).
export const SHOWCASE_DEVICE = devices.find((d) => d.deviceName === "DEMO-WKS-007");
SHOWCASE_DEVICE.complianceState = "noncompliant";
SHOWCASE_DEVICE.isEncrypted = false;
export const DEVICES = devices;

// ── Defender machines ──────────────────────────────────────────────────────────────────────

const machines = devices
  .filter((d) => d._defenderPlatform)
  .map((d) => {
    const exposureLevel = weighted([
      ["Low", 55],
      ["Medium", 32],
      ["High", 10],
      ["None", 3],
    ]);
    return {
      id: hex(40),
      computerDnsName: d.deviceName.toLowerCase(),
      aadDeviceId: d.azureADDeviceId,
      osPlatform: d._defenderPlatform,
      osVersion: null,
      onboardingStatus: "Onboarded",
      healthStatus: weighted([
        ["Active", 92],
        ["Inactive", 8],
      ]),
      // Quelques postes récents, pour la tuile « Nouveaux devices (7 jours) » du Dashboard.
      firstSeen: /-(00[1-5])$/.test(d.deviceName) ? ago(int(1, 6) * DAY) : iso(new Date(d.enrolledDateTime).getTime() + DAY),
      lastSeen: iso(NOW - int(5, 60 * 40) * 60_000),
      lastIpAddress: `10.20.${int(1, 40)}.${int(2, 250)}`,
      riskScore: exposureLevel === "High" ? "Medium" : weighted([["None", 70], ["Informational", 20], ["Low", 10]]),
      exposureLevel,
      machineTags: [d._department],
      rbacGroupName: "Postes de travail",
      isAadJoined: true,
      osBuild: Number(d.osVersion.split(".")[2]) || null,
      osArchitecture: "64-bit",
      agentVersion: "10.8760.26100.2033",
      deviceValue: "Normal",
      managedBy: "Intune",
      defenderAvStatus: null,
      partnerReportedThreatState: null,
      lastExternalIpAddress: "203.0.113.24",
      _device: d,
    };
  });

const NON_ONBOARDED_NAMES = ["printer-hall-01", "printer-hall-02", "nas-backup-01", "meeting-room-tv", "badge-reader-03", "ubuntu-build-01", "debian-proxy-01", "unknown-10-20-8-41", "iot-sensor-07", "voip-gw-01", "android-kiosk-02", "scanner-rh-01", "ipad-accueil", "srv-legacy-02"];
const nonOnboarded = NON_ONBOARDED_NAMES.map((name) => ({
  id: hex(40),
  computerDnsName: name,
  aadDeviceId: null,
  osPlatform: pick(["Other", "Linux", "Debian", "Ubuntu", "Windows10", "AppleiOS"]),
  osVersion: null,
  onboardingStatus: weighted([
    ["CanBeOnboarded", 70],
    ["InsufficientInfo", 30],
  ]),
  healthStatus: "Inactive",
  firstSeen: ago(int(30, 300) * DAY),
  lastSeen: ago(int(1, 20) * DAY),
  lastIpAddress: `10.20.${int(1, 40)}.${int(2, 250)}`,
  riskScore: "None",
  exposureLevel: "None",
  machineTags: [],
}));
export const MACHINES = machines;
export const NON_ONBOARDED = nonOnboarded;
export const ALL_MACHINES = [...machines, ...nonOnboarded];

// ── Compliance policies and per-device report rows ─────────────────────────────────────────

const POLICIES = [
  ["[DEMO] Windows - BitLocker obligatoire", "#microsoft.graph.windows10CompliancePolicy", "Windows"],
  ["[DEMO] Windows - Secure Boot activé", "#microsoft.graph.windows10CompliancePolicy", "Windows"],
  ["[DEMO] Windows - Antivirus Defender actif", "#microsoft.graph.windows10CompliancePolicy", "Windows"],
  ["[DEMO] Windows - Version minimale de l'OS", "#microsoft.graph.windows10CompliancePolicy", "Windows"],
  ["[DEMO] Windows - Pare-feu activé", "#microsoft.graph.windows10CompliancePolicy", "Windows"],
  ["[DEMO] macOS - FileVault obligatoire", "#microsoft.graph.macOSCompliancePolicy", "macOS"],
  ["[DEMO] macOS - Version minimale de l'OS", "#microsoft.graph.macOSCompliancePolicy", "macOS"],
  ["[DEMO] Android - Code PIN", "#microsoft.graph.androidWorkProfileCompliancePolicy", "Android"],
  ["[DEMO] Android - Version minimale de l'OS", "#microsoft.graph.androidWorkProfileCompliancePolicy", "Android"],
  ["[DEMO] Android - Niveau de menace Defender", "#microsoft.graph.androidWorkProfileCompliancePolicy", "Android"],
  ["[DEMO] iOS - Code d'accès", "#microsoft.graph.iosCompliancePolicy", "iOS"],
  ["Default Device Compliance Policy", null, null],
].map(([displayName, odataType, os]) => ({ id: uuid(), displayName, odataType, _os: os }));
export const COMPLIANCE_POLICIES = POLICIES;

// Statut par couple appareil × politique (vocabulaire complianceStatus de Graph).
const policyRows = new Map(); // policyId -> [{device, status, lastReported}]
for (const p of POLICIES) policyRows.set(p.id, []);
for (const d of devices) {
  const applicable = POLICIES.filter((p) => p._os === d.operatingSystem || p._os === null);
  const failing = new Set();
  if (d.complianceState === "noncompliant" || d.complianceState === "inGracePeriod") {
    const candidates = applicable.filter((p) => p._os);
    failing.add(pick(candidates).id);
    if (chance(0.35)) failing.add(pick(candidates).id);
  }
  for (const p of applicable) {
    let status;
    if (d.complianceState === "unknown") status = "unknown";
    else if (failing.has(p.id)) status = "nonCompliant";
    else if (p._os === null && d.complianceState === "noncompliant") status = "nonCompliant";
    else status = weighted([
      ["compliant", 99.2],
      ["notApplicable", 0.6],
      ["error", 0.2],
    ]);
    policyRows.get(p.id).push({ device: d, status, lastReported: d.lastSyncDateTime });
  }
}
export const POLICY_ROWS = policyRows;

// Réglages évalués par politique (détail par paramètre, forme de settingStates).
const SETTINGS_BY_POLICY = {
  BitLocker: [["Device_HealthAttestation/BitLockerEnabled", "Windows10CompliancePolicy.BitLockerEnabled", "Require BitLocker"]],
  "Secure Boot": [["Device_HealthAttestation/SecureBootEnabled", "Windows10CompliancePolicy.SecureBootEnabled", "Require Secure Boot to be enabled on the device"]],
  Antivirus: [
    ["DeviceStatus/Antivirus", "Windows10CompliancePolicy.AntivirusRequired", "Antivirus"],
    ["DeviceStatus/AntiSpyware", "Windows10CompliancePolicy.AntiSpywareRequired", "Antispyware"],
  ],
  "Version minimale": [["./DevDetail/SwV", "Windows10CompliancePolicy.OsMinimumVersion", "Minimum OS version"]],
  "Pare-feu": [["./Vendor/MSFT/Firewall/MdmStore/DomainProfile/EnableFirewall", "Windows10CompliancePolicy.ActiveFirewallRequired", "Firewall"]],
};
export function settingsFor(policyName, status) {
  const key = Object.keys(SETTINGS_BY_POLICY).find((k) => policyName.includes(k));
  const base = key ? SETTINGS_BY_POLICY[key] : [["DeviceCompliance/Generic", "CompliancePolicy.Setting", "Paramètre de conformité"]];
  return base.map(([setting, settingName, instanceDisplayName], i) => ({
    setting,
    settingName,
    instanceDisplayName,
    state: status === "nonCompliant" && i === 0 ? "nonCompliant" : status === "notApplicable" ? "notApplicable" : "compliant",
    errorCode: 0,
    errorDescription: status === "nonCompliant" && i === 0 ? "Valeur actuelle non conforme à la politique" : "0",
    userId: uuid(),
    userName: null,
    userEmail: null,
    userPrincipalName: null,
    currentValue: null,
    sources: [{ id: uuid(), displayName: policyName, sourceType: "deviceConfiguration" }],
  }));
}

// ── Software, vulnerabilities and CVEs ─────────────────────────────────────────────────────

const SOFTWARE = [
  ["google", "chrome", "130.0.6723.92"],
  ["mozilla", "firefox", "131.0.3"],
  ["microsoft", "edge", "130.0.2849.56"],
  ["microsoft", "windows_11", "10.0.22631"],
  ["microsoft", "windows_10", "10.0.19045"],
  ["microsoft", "office", "16.0.17928"],
  ["microsoft", ".net_framework", "4.8.1"],
  ["adobe", "acrobat_reader_dc", "24.003"],
  ["7-zip", "7-zip", "23.01"],
  ["notepad++", "notepad++", "8.6.9"],
  ["videolan", "vlc_media_player", "3.0.20"],
  ["oracle", "jre", "8.0.411"],
  ["zoom", "zoom", "6.1.11"],
  ["python", "python", "3.10.11"],
  ["putty", "putty", "0.80"],
  ["apple", "macos", "14.6.1"],
];
export const SOFTWARE_LIST = SOFTWARE;

const SEV = [
  ["Critical", 9, 10],
  ["High", 7, 8.9],
  ["Medium", 4, 6.9],
  ["Low", 1, 3.9],
];
const cves = [];
let cveSeq = 21000;
for (const [vendor, name] of SOFTWARE) {
  const count = name.startsWith("windows") ? 60 : name === "chrome" || name === "edge" ? 35 : int(4, 18);
  for (let i = 0; i < count; i++) {
    const [severity, lo, hi] = weighted([
      [SEV[0], 8],
      [SEV[1], 34],
      [SEV[2], 48],
      [SEV[3], 10],
    ]);
    cves.push({
      cve_code: `CVE-2026-${pad(cveSeq++, 5)}`,
      software_vendor: vendor,
      software_name: name,
      severity,
      cvss_score: Math.round((lo + rand() * (hi - lo)) * 10) / 10,
      exploitability_level: weighted([
        ["NoExploit", 80],
        ["ExploitIsPublic", 12],
        ["ExploitIsVerified", 6],
        ["ExploitIsInKit", 2],
      ]),
      exploit_in_wild: chance(0.05),
      epss: Math.round(rand() * 0.4 * 10000) / 10000,
      affected_count: int(1, name.startsWith("windows") || name === "chrome" ? 70 : 25),
      published: dateOnly(NOW - int(5, 300) * DAY),
    });
  }
}
export const CVES = cves;

// ── Alerts ─────────────────────────────────────────────────────────────────────────────────

const ALERT_TEMPLATES = [
  ["'Wacatac' malware was detected", "Malware", "Wacatac", "Trojan:Script/Wacatac.H!ml", "WindowsDefenderAv", "Medium"],
  ["Suspicious PowerShell command line", "Execution", null, null, "WindowsDefenderAtp", "Medium"],
  ["Potentially unwanted application was detected", "UnwantedSoftware", "Presenoker", "PUA:Win32/Presenoker", "WindowsDefenderAv", "Low"],
  ["Possible credential theft activity", "CredentialAccess", "Mimikatz", "HackTool:Win32/Mimikatz", "WindowsDefenderAtp", "High"],
  ["Connection to a malicious URL was blocked", "CommandAndControl", null, null, "WindowsDefenderSmartScreen", "Informational"],
  ["Suspicious file dropped by Office application", "InitialAccess", null, null, "WindowsDefenderAtp", "Medium"],
  ["Phishing website was blocked", "InitialAccess", "Phish", "Trojan:HTML/Phish", "WindowsDefenderSmartScreen", "Low"],
  ["Hands-on-keyboard attack via Impacket", "LateralMovement", "Impacket", "HackTool:Python/Impacket", "WindowsDefenderAtp", "High"],
  ["Suspicious remote discovery activity", "Discovery", null, null, "WindowsDefenderAtp", "Low"],
];
const alerts = [];
for (let i = 0; i < 46; i++) {
  const [title, category, family, threatName, detectionSource, baseSeverity] = pick(ALERT_TEMPLATES);
  const showcase = i < 2;
  const machine = showcase ? machines.find((m) => m._device === SHOWCASE_DEVICE) : pick(machines);
  const created = NOW - (showcase ? int(30, 300) : int(10, 30 * 24 * 60)) * 60_000;
  const status = showcase ? "New" : weighted([
    ["New", 45],
    ["InProgress", 15],
    ["Resolved", 40],
  ]);
  const user = machine._device._user;
  alerts.push({
    id: `da${hex(16)}_${int(100000000, 999999999)}`,
    incidentId: 1200 + i,
    investigationId: null,
    assignedTo: status === "New" ? null : "soc@demo.example",
    severity: showcase ? "High" : chance(0.2) ? pick(["Low", "Medium", "High"]) : baseSeverity,
    status,
    classification: status === "Resolved" ? weighted([["TruePositive", 60], ["FalsePositive", 40]]) : null,
    determination: null,
    investigationState: pick(["UnsupportedAlertType", "SuppressedAlert", "Benign"]),
    detectionSource,
    detectorId: uuid(),
    category,
    threatFamilyName: family,
    title,
    description: `${title}. Données fictives générées pour le mode démo de Pandore.`,
    alertCreationTime: iso(created),
    firstEventTime: iso(created - 4 * 60_000),
    lastEventTime: iso(created - 60_000),
    lastUpdateTime: iso(created + int(1, 600) * 60_000),
    resolvedTime: status === "Resolved" ? iso(created + int(1, 48) * HOUR) : null,
    machineId: machine.id,
    computerDnsName: machine.computerDnsName,
    rbacGroupName: "Postes de travail",
    aadTenantId: "00000000-0000-0000-0000-000000000000",
    threatName,
    mitreTechniques: category === "CredentialAccess" ? ["T1003"] : category === "Execution" ? ["T1059.001"] : [],
    relatedUser: null,
    loggedOnUsers: [{ accountName: user.upn.split("@")[0], domainName: "DEMO" }],
    comments: [],
    evidence: [],
    domains: [],
    _user: user,
  });
}
alerts.sort((a, b) => (a.alertCreationTime < b.alertCreationTime ? 1 : -1));
export const ALERTS = alerts;

// ── Applications ───────────────────────────────────────────────────────────────────────────

const APPS = [
  ["7-Zip", "Igor Pavlov", "24.08", "win32LobApp", "windows"],
  ["Google Chrome", "Google LLC", "130.0.6723.92", "win32LobApp", "windows"],
  ["Mozilla Firefox", "Mozilla", "131.0.3", "win32LobApp", "windows"],
  ["Notepad++", "Notepad++ Team", "8.7.1", "win32LobApp", "windows"],
  ["VLC media player", "VideoLAN", "3.0.21", "win32LobApp", "windows"],
  ["Adobe Acrobat Reader", "Adobe", "24.004", "win32LobApp", "windows"],
  ["Microsoft Teams", "Microsoft Corporation", "24295.605", "win32LobApp", "windows"],
  ["Zoom Workplace", "Zoom Video Communications", "6.2.5", "win32LobApp", "windows"],
  ["Company Portal", "Microsoft Corporation", "11.2.1", "macOSDmgApp", "macos"],
  ["Outil de gestion des notes de frais", "Demo Software", "3.4.0", "win32LobApp", "windows"],
].map(([displayName, publisher, version, type, platform]) => ({
  "@odata.type": `#microsoft.graph.${type}`,
  id: uuid(),
  displayName,
  publisher,
  createdDateTime: ago(int(60, 600) * DAY),
  lastModifiedDateTime: ago(int(1, 60) * DAY),
  largeIcon: null,
  platform,
  displayVersion: version,
}));
export const DEPLOYED_APPS = APPS;

const DISCOVERED_ONLY = ["PuTTY", "Python 3.10", "Java 8 Update 411", "WinSCP", "Git", "Visual Studio Code", "Paint.NET", "KeePass Password Safe"];
export const DISCOVERED_APPS = DISCOVERED_ONLY.map((displayName) => ({
  id: hex(32),
  displayName,
  publisher: null,
  platform: "windows",
  lastModifiedDateTime: null,
  displayVersion: null,
  largeIcon: null,
}));

export const APP_INSTALL = new Map(); // appId -> devices[]
for (const app of APPS) {
  const targets = devices.filter((d) => (app.platform === "macos" ? d.operatingSystem === "macOS" : d.operatingSystem === "Windows"));
  APP_INSTALL.set(
    app.id,
    targets.map((d) => ({
      deviceName: d.deviceName,
      userPrincipalName: d.userPrincipalName,
      department: d._department,
      appVersion: app.displayVersion,
      installState: weighted([
        ["installed", 90],
        ["failed", 4],
        ["pendingInstall", 6],
      ]),
      osDescription: d.operatingSystem === "Windows" ? `Windows ${d.osVersion}` : `macOS ${d.osVersion}`,
      lastSyncDateTime: d.lastSyncDateTime,
      deviceId: d.id,
    }))
  );
}

// ── Secure Score ───────────────────────────────────────────────────────────────────────────

const CONTROLS = [
  ["Identity", "MFARegistrationV2", "Ensure all users can complete multifactor authentication", 9],
  ["Identity", "BlockLegacyAuthentication", "Enable policy to block legacy authentication", 8],
  ["Identity", "PWAgePolicyNew", "Do not expire passwords", 8],
  ["Identity", "SigninRiskPolicy", "Turn on sign-in risk policy", 7],
  ["Identity", "UserRiskPolicy", "Turn on user risk policy", 7],
  ["Identity", "AdminMFAV2", "Ensure multifactor authentication is enabled for all users in administrative roles", 10],
  ["Device", "scid_2010", "Turn on Microsoft Defender Antivirus PUA protection in block mode", 6],
  ["Device", "scid_2012", "Enable 'Local Security Authority (LSA) protection'", 7],
  ["Device", "scid_2016", "Turn on Microsoft Defender Credential Guard", 8],
  ["Device", "scid_2090", "Block executable content from email client and webmail", 7],
  ["Device", "scid_2091", "Block Office applications from creating child processes", 7],
  ["Device", "scid_2025", "Disable SMBv1 client driver", 5],
  ["Device", "scid_4001", "Update Google Chrome", 4],
  ["Device", "scid_4002", "Update Microsoft Windows 10", 6],
  ["Apps", "mcas_appSecureScore", "Discover trends in shadow IT application usage", 5],
  ["Apps", "DLPEnabled", "Create a DLP policy", 5],
  ["Data", "InformationProtectionPolicy", "Ensure sensitivity labels are published", 6],
  ["Data", "IRMEnabled", "Use sensitivity labels to protect sensitive content", 4],
  ["Infrastructure", "aad_admin_accounts_separate", "Use limited administrative roles", 3],
];
export const SECURE_SCORE_CONTROLS = CONTROLS.map(([controlCategory, id, title, maxScore], rank) => {
  const scoreInPercentage = weighted([
    [100, 35],
    [0, 35],
    [int(20, 90), 30],
  ]);
  return { controlCategory, id, title, maxScore, rank: rank + 1, scoreInPercentage, score: Math.round((maxScore * scoreInPercentage) / 10) / 10 };
});

// ── Vanitas (self-hosted agents) ───────────────────────────────────────────────────────────

const agentDevices = devices.filter((d) => d.operatingSystem === "Windows").slice(0, 18);
export const VANITAS_GROUPS = [
  { name: "Postes Finance", department: "Finance", window: ["22:00", "02:00"], grace: 3 },
  { name: "Postes Informatique (pilote)", department: "Informatique", window: ["12:00", "14:00"], grace: 1 },
  { name: "Postes Ventes", department: "Ventes", window: ["21:00", "23:00"], grace: 5 },
  { name: "Tous les postes", department: null, window: ["20:00", "23:00"], grace: 5 },
].map((g, i) => ({
  id: hex(32),
  name: g.name,
  rules: g.department
    ? { combinator: "and", conditions: [{ field: "hostname", operator: "glob", value: "DEMO-WKS-*" }] }
    : { combinator: "and", conditions: [{ field: "hostname", operator: "contains", value: "DEMO" }] },
  child_group_ids: [],
  created_at: ago((90 - i * 10) * DAY),
  updated_at: ago(int(1, 20) * DAY),
  device_count: 0,
  patch_enabled: Boolean(g.window),
  patch_window_start: g.window ? g.window[0] : null,
  patch_window_end: g.window ? g.window[1] : null,
  patch_grace_days: g.grace,
  _department: g.department,
}));

export const AGENTS = agentDevices.map((d, i) => {
  const online = i !== 5 && i !== 13;
  const groups = VANITAS_GROUPS.filter((g) => g._department === d._department || g._department === null);
  return {
    id: hex(32),
    hostname: d.deviceName,
    enrolled_at: ago(int(30, 200) * DAY),
    last_seen: online ? ago(int(1, 50) * 60_000) : ago(int(3, 9) * DAY),
    apps_count: int(55, 140),
    cert_serial: hex(32),
    cert_not_after: i === 7 ? iso(NOW + 12 * DAY) : iso(NOW + int(60, 330) * DAY),
    agent_version: i === 3 || i === 11 ? "2.3.0" : "2.4.1",
    group_ids: groups.map((g) => g.id),
    network_isolated: i === 2,
    network_isolated_at: i === 2 ? ago(5 * HOUR) : null,
    network_isolated_by: i === 2 ? "admin.demo" : null,
    network_isolated_reason: i === 2 ? "Activité suspecte : connexion vers une adresse IP malveillante" : null,
    network_isolated_event_id: null,
    _device: d,
  };
});
for (const g of VANITAS_GROUPS) g.device_count = AGENTS.filter((a) => a.group_ids.includes(g.id)).length;

export const VANITAS_RULES = [
  ["BitLocker actif sur le disque système", 0.92],
  ["Pare-feu Windows : trois profils actifs", 1],
  ["Compte administrateur local désactivé", 0.83],
  ["SMBv1 désactivé", 1],
  ["LAPS configuré", 0.61],
  ["Mises à jour Windows de moins de 30 jours", 0.78],
].map(([name, rate]) => ({
  id: hex(32),
  name,
  script_content: `# Règle de démonstration\n# Code de sortie 0 = conforme, 1 = non conforme\nexit 0\n`,
  enabled: true,
  created_at: ago(int(40, 120) * DAY),
  updated_at: ago(int(1, 30) * DAY),
  _rate: rate,
}));

export const SIGNALS = [
  ["process", "high", "Processus enfant suspect : winword.exe → powershell.exe -enc", "office_child_powershell"],
  ["network", "high", "Connexion sortante vers une adresse IP signalée comme malveillante", "network_known_bad_ip"],
  ["usb", "med", "Support de stockage USB inconnu monté", "usb_unknown_storage"],
  ["event_log", "med", "Échecs d'ouverture de session répétés (événement 4625)", "eventlog_bruteforce"],
  ["event_log", "high", "Service installé depuis un répertoire temporaire (événement 7045)", "eventlog_service_from_temp"],
  ["process", "low", "rundll32.exe lancé sans argument avec activité réseau", "process_rundll32_noargs"],
  ["process", "med", "Exécution de certutil.exe pour télécharger un fichier", "process_certutil_download"],
  ["network", "low", "Connexion sortante sur un port inhabituel (4444)", "network_unusual_port"],
];

export { rand, pick, int, chance, weighted, hex, uuid, iso, ago, dateOnly, NOW, HOUR, DAY };
