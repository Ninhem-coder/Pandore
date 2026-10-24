/**
 * In-browser fake backend for demo mode (`npm run demo`, `VITE_DEMO=true`).
 *
 * `api.js` routes every request here instead of calling `fetch` when demo mode is on. Each route
 * of the real API that the dashboard reads is answered from the fictional dataset in
 * `demo/data.js`, with the same JSON shape. Writes (create, update, delete, commands) and the few
 * routes not covered return the backend's normal business-error payload (HTTP 200 contract,
 * `{error: true, ...}` or `[{error: true, ...}]`), which every page already knows how to display.
 */
import {
  ALERTS,
  ALL_MACHINES,
  AGENTS,
  APP_INSTALL,
  COMPLIANCE_POLICIES,
  CVES,
  DEPLOYED_APPS,
  DEVICES,
  DISCOVERED_APPS,
  DOMAIN,
  MACHINES,
  NON_ONBOARDED,
  POLICY_ROWS,
  SECURE_SCORE_CONTROLS,
  SIGNALS,
  SOFTWARE_LIST,
  USERS,
  VANITAS_GROUPS,
  VANITAS_RULES,
  DAY,
  HOUR,
  NOW,
  ago,
  chance,
  dateOnly,
  hex,
  int,
  iso,
  pick,
  rand,
  settingsFor,
  uuid,
  weighted,
} from "./data.js";

const DEMO_ERROR_MESSAGE = "Action non disponible en mode démo (données fictives).";
const demoError = { error: true, type: "DemoMode", message: DEMO_ERROR_MESSAGE };

const memo = new Map();
const once = (key, fn) => {
  if (!memo.has(key)) memo.set(key, fn());
  return memo.get(key);
};

// Retire les champs internes (`_xxx`) de la démo avant de répondre.
function clean(value) {
  if (Array.isArray(value)) return value.map(clean);
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) if (!k.startsWith("_")) out[k] = clean(v);
    return out;
  }
  return value;
}

const deviceByName = (name) => DEVICES.find((d) => d.deviceName.toLowerCase() === String(name).toLowerCase());
const machineByName = (name) => MACHINES.find((m) => m.computerDnsName === String(name).toLowerCase());

// ── Pandore: Intune ────────────────────────────────────────────────────────────────────────

function intuneSummary() {
  const byOperatingSystem = {};
  const byComplianceState = {};
  for (const d of DEVICES) {
    byOperatingSystem[d.operatingSystem] = (byOperatingSystem[d.operatingSystem] || 0) + 1;
    byComplianceState[d.complianceState] = (byComplianceState[d.complianceState] || 0) + 1;
  }
  const total = DEVICES.length;
  const compliant = byComplianceState.compliant || 0;
  return {
    totalDevices: total,
    compliantCount: compliant,
    nonCompliantCount: byComplianceState.noncompliant || 0,
    complianceRate: `${((compliant / total) * 100).toFixed(1)}%`,
    byOperatingSystem,
    byComplianceState,
  };
}

function policySummary() {
  return COMPLIANCE_POLICIES.map((p) => {
    const counts = { successCount: 0, failedCount: 0, errorCount: 0, notApplicableCount: 0, pendingCount: 0 };
    for (const r of POLICY_ROWS.get(p.id)) {
      if (r.status === "compliant") counts.successCount++;
      else if (r.status === "nonCompliant") counts.failedCount++;
      else if (r.status === "error") counts.errorCount++;
      else if (r.status === "notApplicable") counts.notApplicableCount++;
      else counts.pendingCount++;
    }
    return { id: p.id, displayName: p.displayName, odataType: p.odataType, ...counts, lastUpdateDateTime: ago(2 * HOUR) };
  });
}

const CATEGORY = { nonCompliant: "Non conforme", error: "Erreur", notApplicable: "Non applicable", unknown: "En attente" };
function complianceDetail() {
  const policies = [];
  let aggregate = 0;
  for (const p of COMPLIANCE_POLICIES) {
    const rows = POLICY_ROWS.get(p.id);
    const failing = rows.filter((r) => r.status === "nonCompliant" || r.status === "error").length;
    if (!failing) continue;
    aggregate += failing;
    const devices = rows
      .filter((r) => r.status !== "compliant")
      .map((r) => ({
        deviceId: r.device.id,
        deviceName: r.device.deviceName,
        userPrincipalName: r.device.userPrincipalName,
        operatingSystem: r.device.operatingSystem,
        status: r.status,
        deviceComplianceState: r.device.complianceState,
        complianceCategory: CATEGORY[r.status],
        lastReportedDateTime: r.lastReported,
        resolvedFromPlaceholder: false,
      }));
    policies.push({
      id: p.id,
      displayName: p.displayName,
      failedCount: devices.length,
      aggregateFailedCount: failing,
      placeholderRows: 0,
      resolvedFromPlaceholders: 0,
      reclassifiedByDeviceState: 0,
      platformMismatchCount: 0,
      unresolvedPlaceholderRows: 0,
      unverifiedCandidates: 0,
      devices,
    });
  }
  policies.sort((a, b) => b.failedCount - a.failedCount);
  return {
    policies,
    truncated: false,
    maxDevicesPerPolicy: null,
    unavailablePolicies: [],
    placeholderOnlyPolicies: [],
    missingPolicies: [],
    scannedPolicies: policies.length,
    totalFailedCount: policies.reduce((s, p) => s + p.failedCount, 0),
    aggregateTotalCount: aggregate,
    placeholderRows: 0,
    resolvedFromPlaceholders: 0,
    reclassifiedByDeviceState: 0,
    platformMismatchCount: 0,
    unresolvedPlaceholderRows: 0,
    unverifiedCandidates: 0,
    source: "intune-reports",
  };
}

function devicePolicyStatuses(device) {
  return COMPLIANCE_POLICIES.flatMap((p) => {
    const row = POLICY_ROWS.get(p.id).find((r) => r.device === device);
    return row ? [{ id: p.id, displayName: p.displayName, state: row.status, lastReportedDateTime: row.lastReported }] : [];
  });
}

function secureScoreHistory(days) {
  const maxScore = 412;
  // Graph renvoie l'historique du plus RÉCENT au plus ancien.
  return Array.from({ length: days }, (_, k) => {
    const i = days - 1 - k;
    const t = NOW - (days - 1 - i) * DAY;
    const current = Math.round((maxScore * (0.52 + 0.09 * (i / Math.max(days - 1, 1)) + (Math.sin(i) * 0.004))) * 100) / 100;
    return {
      id: `demo_${dateOnly(t)}`,
      azureTenantId: "00000000-0000-0000-0000-000000000000",
      activeUserCount: 64,
      createdDateTime: iso(t),
      currentScore: current,
      enabledServices: ["HasExchange", "HasSharePoint", "HasOD4B", "HasMDEP"],
      licensedUserCount: 70,
      maxScore,
      vendorInformation: { provider: "SecureScore", providerVersion: null, subProvider: null, vendor: "Microsoft" },
      averageComparativeScores: [
        { basis: "AllTenants", averageScore: 197.4, appsScore: 62, appsScoreMax: 100, dataScore: 41, dataScoreMax: 100, deviceScore: 44, deviceScoreMax: 100, identityScore: 58, identityScoreMax: 100, infrastructureScore: 30, infrastructureScoreMax: 100, SeatSizeRangeLowerValue: "", SeatSizeRangeUpperValue: "" },
        { basis: "TotalSeats", averageScore: 211.3, appsScore: 64, appsScoreMax: 100, dataScore: 45, dataScoreMax: 100, deviceScore: 49, deviceScoreMax: 100, identityScore: 61, identityScoreMax: 100, infrastructureScore: 33, infrastructureScoreMax: 100, SeatSizeRangeLowerValue: "51", SeatSizeRangeUpperValue: "100" },
      ],
      controlScores: SECURE_SCORE_CONTROLS.map((c) => ({
        controlCategory: c.controlCategory,
        controlName: c.id,
        description: c.title,
        score: c.score,
        lastSynced: ago(6 * HOUR),
        implementationStatus: "",
        on: "",
        scoreInPercentage: c.scoreInPercentage,
        count: "",
        total: "",
        state: "default",
      })),
    };
  });
}

function controlProfiles() {
  return SECURE_SCORE_CONTROLS.map((c) => ({
    id: c.id,
    azureTenantId: "00000000-0000-0000-0000-000000000000",
    actionType: "Config",
    actionUrl: "https://security.microsoft.com/securescore",
    controlCategory: c.controlCategory,
    title: c.title,
    deprecated: false,
    implementationCost: pick(["Low", "Moderate", "High"]),
    lastModifiedDateTime: null,
    maxScore: c.maxScore,
    rank: c.rank,
    remediation: `<p>${c.title}.</p><p>Étapes de remédiation fictives pour le mode démo.</p>`,
    remediationImpact: "Impact limité pour les utilisateurs.",
    service: c.controlCategory === "Identity" ? "AzureAD" : c.controlCategory === "Device" ? "MDATP" : "MCAS",
    threats: ["Account breach", "Elevation of privilege"],
    tier: "Core",
    userImpact: pick(["Low", "Moderate"]),
    vendorInformation: { provider: "SecureScore", providerVersion: null, subProvider: null, vendor: "Microsoft" },
    complianceInformation: [],
    controlStateUpdates: [{ assignedTo: null, comment: null, state: "Default", updatedBy: null, updatedDateTime: null }],
  }));
}

function appsCatalog() {
  const deployed = DEPLOYED_APPS.map((a) => {
    const devices = APP_INSTALL.get(a.id) || [];
    const both = a.platform === "windows";
    return {
      ...a,
      source: both ? "both" : "deployed",
      discovered: both
        ? {
            totalDeviceCount: devices.length,
            versionCount: 2,
            versions: [
              { version: a.displayVersion, deviceCount: Math.round(devices.length * 0.85), ids: [hex(32)] },
              { version: "précédente", deviceCount: devices.length - Math.round(devices.length * 0.85), ids: [hex(32)] },
            ],
            matchedName: a.displayName,
          }
        : undefined,
    };
  });
  const discovered = DISCOVERED_APPS.map((a) => ({
    ...a,
    source: "discovered",
    discovered: {
      totalDeviceCount: int(3, 40),
      versionCount: int(1, 4),
      versions: [{ version: `${int(1, 9)}.${int(0, 9)}.${int(0, 9)}`, deviceCount: int(3, 40), ids: [a.id] }],
      matchedName: null,
    },
  }));
  return [...deployed, ...discovered];
}

function installSummary() {
  const byApp = {};
  let installed = 0;
  let failed = 0;
  let pending = 0;
  for (const a of DEPLOYED_APPS) {
    const rows = APP_INSTALL.get(a.id) || [];
    const c = { installed: 0, failed: 0, pending: 0, notInstalled: 0, notApplicable: 0 };
    for (const r of rows) {
      if (r.installState === "installed") c.installed++;
      else if (r.installState === "failed") c.failed++;
      else c.pending++;
    }
    byApp[a.id] = c;
    installed += c.installed;
    failed += c.failed;
    pending += c.pending;
  }
  return {
    appsCount: DEPLOYED_APPS.length,
    appsWithData: DEPLOYED_APPS.length,
    installedTotal: installed,
    failedTotal: failed,
    pendingTotal: pending,
    notInstalledTotal: 0,
    notApplicableTotal: 0,
    installRate: Math.round((installed / (installed + failed + pending)) * 1000) / 10,
    byApp,
  };
}

function detectedAppsFor(device) {
  const apps = DEPLOYED_APPS.filter((a) => (device.operatingSystem === "macOS" ? a.platform === "macos" : a.platform === "windows"));
  return [...apps.map((a) => ({ id: hex(32), displayName: a.displayName, version: a.displayVersion, platform: a.platform, sizeInByte: int(5, 400) * 1_000_000 })),
    ...DISCOVERED_APPS.slice(0, 4).map((a) => ({ id: a.id, displayName: a.displayName, version: `${int(1, 9)}.${int(0, 9)}`, platform: "windows", sizeInByte: int(5, 200) * 1_000_000 }))];
}

// ── Pandore: Defender ──────────────────────────────────────────────────────────────────────

function defenderSummary() {
  const count = (key) => ALL_MACHINES.reduce((acc, m) => ((acc[m[key]] = (acc[m[key]] || 0) + 1), acc), {});
  return {
    totalMachines: ALL_MACHINES.length,
    byOnboardingStatus: count("onboardingStatus"),
    byHealthStatus: count("healthStatus"),
    byOSPlatform: count("osPlatform"),
    byExposureLevel: count("exposureLevel"),
  };
}

const RECOMMENDATIONS = [
  ["Update Google Chrome", "chrome", "google", "Software", 6.4, true],
  ["Turn on Microsoft Defender Credential Guard", "windows_11", "microsoft", "Security controls", 5.1, false],
  ["Block Office applications from creating child processes", "office", "microsoft", "Security controls", 4.8, false],
  ["Update Microsoft Windows 10", "windows_10", "microsoft", "Software", 4.6, true],
  ["Disable SMBv1 client driver", "windows_11", "microsoft", "Security controls", 3.9, false],
  ["Update Oracle JRE", "jre", "oracle", "Software", 3.2, true],
  ["Update Adobe Acrobat Reader DC", "acrobat_reader_dc", "adobe", "Software", 2.7, false],
  ["Enable 'Local Security Authority (LSA) protection'", "windows_11", "microsoft", "Security controls", 2.2, false],
];
function recommendations(top) {
  return RECOMMENDATIONS.slice(0, top).map(([recommendationName, productName, vendor, category, score, exploit], i) => ({
    id: `va-_-${vendor}-_-${productName}-${i}`,
    productName,
    recommendationName,
    weaknesses: category === "Software" ? int(4, 40) : 0,
    vendor,
    recommendedVersion: "",
    recommendedVendor: "",
    recommendedProgram: "",
    recommendationCategory: category,
    subCategory: category === "Software" ? "" : "Attack Surface Reduction",
    severityScore: score,
    publicExploit: exploit,
    activeAlert: false,
    associatedThreats: [],
    remediationType: category === "Software" ? "Update" : "ConfigurationChange",
    status: "Active",
    configScoreImpact: category === "Software" ? 0 : score,
    exposureImpact: score,
    totalMachineCount: MACHINES.length,
    exposedMachinesCount: int(5, 70),
    nonProductivityImpactedAssets: 0,
    relatedComponent: productName,
    hasUnpatchableCve: false,
    tags: [],
    exposedCriticalDevices: 0,
  }));
}

function cveDevices(cve) {
  const pool = MACHINES.filter((m) => (cve.software_name === "macos" ? m.osPlatform === "macOS" : m.osPlatform !== "macOS"));
  return pool.slice(0, Math.min(cve.affected_count, pool.length)).map((m) => ({
    hostname: m.computerDnsName,
    rbac_group: m.rbacGroupName,
    disk_paths: [`C:\\Program Files\\${cve.software_vendor}\\${cve.software_name}\\${cve.software_name}.exe`],
    registry_paths: [],
  }));
}
function searchVulnerabilities(query, max) {
  const q = String(query || "").toLowerCase();
  return CVES.filter((c) => c.cve_code.toLowerCase().includes(q) || c.software_name.includes(q) || c.software_vendor.includes(q))
    .slice(0, max)
    .map((c) => {
      const devices = cveDevices(c);
      return {
        cve_code: c.cve_code,
        severity: c.severity,
        cvss_score: c.cvss_score,
        exploitability_level: c.exploitability_level,
        description: `Vulnérabilité fictive affectant ${c.software_name} (mode démo).`,
        epss: c.epss,
        exploit_in_wild: c.exploit_in_wild,
        exploit_kit: c.exploitability_level === "ExploitIsInKit",
        security_update_available: true,
        software_vendor: c.software_vendor,
        software_name: c.software_name,
        affected_count: devices.length,
        affected_hostnames: devices.map((d) => d.hostname).join(", "),
        disk_paths: devices[0]?.disk_paths[0] || "",
        registry_paths: "",
        rbac_groups: "Postes de travail",
        first_seen: dateOnly(NOW - 20 * DAY),
        last_seen: dateOnly(NOW),
        devices,
      };
    });
}

function vulnerableApps(top) {
  const bySoftware = new Map();
  for (const c of CVES) {
    const key = `${c.software_vendor}|${c.software_name}`;
    const e = bySoftware.get(key) || { software_vendor: c.software_vendor, software_name: c.software_name, cve_count: 0, device_count: 0 };
    e.cve_count++;
    e.device_count = Math.max(e.device_count, c.affected_count);
    bySoftware.set(key, e);
  }
  return [...bySoftware.values()]
    .sort((a, b) => b.device_count * b.cve_count - a.device_count * a.cve_count)
    .slice(0, top)
    .map((e) => ({ ...e, paths: [`C:\\Program Files\\${e.software_vendor}\\${e.software_name}`], device_names: MACHINES.slice(0, Math.min(e.device_count, 20)).map((m) => m.computerDnsName) }));
}

function alertDetail(alert) {
  return {
    "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Alerts/$entity",
    ...clean(alert),
    evidence: [
      {
        entityType: alert.category === "Execution" ? "Process" : "File",
        evidenceCreationTime: alert.alertCreationTime,
        sha1: hex(40),
        sha256: hex(64),
        fileName: alert.category === "Execution" ? "powershell.exe" : "invoice_2026.js",
        filePath: alert.category === "Execution" ? "C:\\Windows\\System32\\WindowsPowerShell\\v1.0" : `C:\\Users\\${alert._user.upn.split("@")[0]}\\Downloads`,
        processId: alert.category === "Execution" ? int(1000, 9000) : null,
        processCommandLine: alert.category === "Execution" ? "powershell.exe -NoProfile -EncodedCommand SQBFAFgA..." : null,
        processCreationTime: null,
        parentProcessId: null,
        parentProcessCreationTime: null,
        parentProcessFileName: alert.category === "Execution" ? "winword.exe" : null,
        parentProcessFilePath: null,
        ipAddress: null,
        url: null,
        registryKey: null,
        registryHive: null,
        registryValueType: null,
        registryValue: null,
        registryValueName: null,
        accountName: alert._user.upn.split("@")[0],
        domainName: "DEMO",
        userSid: null,
        aadUserId: alert._user.id,
        userPrincipalName: alert._user.upn,
        detectionStatus: "Detected",
      },
    ],
  };
}

function deviceOverview(name) {
  const device = deviceByName(name);
  const machine = machineByName(name);
  return {
    deviceName: name,
    intune: device
      ? { found: true, device: clean(device), complianceStatuses: devicePolicyStatuses(device), detectedApps: detectedAppsFor(device), error: null }
      : { found: false, device: null, complianceStatuses: null, detectedApps: null, error: null },
    defender: machine
      ? {
          found: true,
          machine: {
            ...clean(machine),
            ipAddresses: [
              { ipAddress: machine.lastIpAddress, macAddress: hex(12).toUpperCase(), type: "Ethernet", operationalStatus: "Up" },
              { ipAddress: "127.0.0.1", macAddress: "", type: "SoftwareLoopback", operationalStatus: "Up" },
            ],
          },
          alerts: clean(ALERTS.filter((a) => a.machineId === machine.id)),
          vulnerabilities: CVES.filter((c) => (machine.osPlatform === "macOS") === (c.software_name === "macos")).slice(0, 60).map((c) => ({ cve_code: c.cve_code, software_vendor: c.software_vendor, software_name: c.software_name, severity: c.severity })),
          error: null,
        }
      : { found: false, machine: null, alerts: null, vulnerabilities: null, error: null },
  };
}

function deviceInventory() {
  const names = new Set([...DEVICES.map((d) => d.deviceName.toLowerCase()), ...ALL_MACHINES.map((m) => m.computerDnsName)]);
  return [...names].map((n) => {
    const d = deviceByName(n);
    const m = ALL_MACHINES.find((x) => x.computerDnsName === n);
    return {
      name: d ? d.deviceName : n,
      operating_system: d ? d.operatingSystem : m.osPlatform,
      user: d ? d.userPrincipalName : "",
      compliance_state: d ? d.complianceState : null,
      exposure_level: m ? m.exposureLevel : null,
      health_status: m ? m.healthStatus : null,
      last_sync_intune: d ? d.lastSyncDateTime : null,
      last_seen_defender: m ? m.lastSeen : null,
      has_intune: Boolean(d),
      has_defender: Boolean(m),
    };
  });
}

function history() {
  return Array.from({ length: 90 }, (_, i) => {
    const t = NOW - (89 - i) * DAY;
    const p = i / 89;
    const total = 118 + Math.round(p * 14);
    const nonCompliant = Math.max(6, Math.round(22 - p * 12 + Math.sin(i / 3) * 2));
    return {
      date: dateOnly(t),
      intune: {
        totalDevices: total,
        nonCompliantCount: nonCompliant,
        complianceRate: Math.round((79 + p * 7 + Math.sin(i / 4)) * 10) / 10,
        complianceRateRule: "compliant-only",
      },
      defender: { totalMachines: 112 + Math.round(p * 10), exposureScore: Math.round((38 - p * 9 + Math.sin(i / 5) * 1.5) * 10) / 10, nonOnboardedCount: 20 - Math.round(p * 6) },
      vanitas: vanitasHistoryPoint(i, p),
    };
  });
}

function vanitasHistoryPoint(i, p) {
  return {
    totalAgents: Math.min(18, 10 + Math.round(p * 8)),
    onlineAgents: Math.min(16, 8 + Math.round(p * 8)),
    complianceRate: Math.round((74 + p * 12 + Math.sin(i / 3) * 2) * 10) / 10,
    patchOk: 6 + Math.round(p * 7),
    patchPending: 4 - Math.round(p * 2),
    patchOff: 1,
    suspiciousNew: Math.max(0, Math.round(4 + Math.sin(i / 2) * 3)),
    suspiciousHigh: Math.max(0, Math.round(1 + Math.sin(i / 2) * 1.5)),
    eolOccurrences: 9 - Math.round(p * 4),
  };
}

function anssiMatches() {
  const items = [
    ["Multiples vulnérabilités dans Google Chrome", "chrome", "google"],
    ["Multiples vulnérabilités dans Microsoft Windows", "windows_11", "microsoft"],
    ["Vulnérabilité dans Mozilla Firefox", "firefox", "mozilla"],
    ["Multiples vulnérabilités dans Adobe Acrobat Reader", "acrobat_reader_dc", "adobe"],
    ["Vulnérabilité dans 7-Zip", "7-zip", "7-zip"],
    ["Multiples vulnérabilités dans Oracle Java", "jre", "oracle"],
  ];
  return items.map(([title, software, vendor], i) => {
    const related = CVES.filter((c) => c.software_name === software).slice(0, 3).map((c) => c.cve_code);
    return {
      certfr_ref: `DEMO-AVI-${pad3(100 + i)}`,
      title,
      published: dateOnly(NOW - (i * 2 + 1) * DAY),
      url: "https://www.cert.ssi.gouv.fr/avis/",
      cve: related,
      summary: `Avis fictif généré pour le mode démo : ${title.toLowerCase()}.`,
      solution: "Se référer au bulletin de sécurité de l'éditeur pour l'obtention des correctifs.",
      matched_software: `${vendor} ${software}`,
      matched_query: software,
      matched_device_count: int(4, 60),
    };
  });
}
const pad3 = (n) => String(n).padStart(4, "0");

// ── Vanitas ────────────────────────────────────────────────────────────────────────────────

const agentById = (id) => AGENTS.find((a) => a.id === id);

function agentApps(agent) {
  return once(`apps:${agent.id}`, () =>
    SOFTWARE_LIST.filter(([, n]) => !["windows_11", "windows_10", "macos"].includes(n)).map(([vendor, name, version]) => ({
      name: name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
      version,
      publisher: vendor,
      install_date: dateOnly(NOW - int(10, 400) * DAY).replace(/-/g, ""),
    }))
  );
}

function agentInventory(agent) {
  const d = agent._device;
  return {
    agent_id: agent.id,
    hostname: agent.hostname,
    collected_at: agent.last_seen,
    apps: agentApps(agent),
    os_caption: d.osVersion.startsWith("10.0.19") ? "Microsoft Windows 10 Professionnel" : "Microsoft Windows 11 Professionnel",
    os_version: d.osVersion.split(".").slice(0, 3).join("."),
    os_build_number: d.osVersion.split(".")[2],
    os_architecture: "64 bits",
    os_registered_user: d.userDisplayName,
    os_install_date: d.enrolledDateTime,
    os_utc_offset: "+120",
  };
}

function agentVulns(agent) {
  return once(`vulns:${agent.id}`, () =>
    CVES.filter((c) => ["chrome", "firefox", "7-zip", "notepad++", "vlc_media_player", "jre", "acrobat_reader_dc"].includes(c.software_name) && chance(0.35)).map((c) => ({
      product_name: c.software_name,
      installed_version: SOFTWARE_LIST.find(([, n]) => n === c.software_name)?.[2] ?? null,
      cve_id: c.cve_code,
      cvss_score: c.cvss_score,
      severity: c.severity.toUpperCase(),
      published: `${c.published}T00:00:00Z`,
      version_affected: true,
    }))
  );
}

function topVulnerabilities(limit) {
  const counts = new Map();
  for (const a of AGENTS) for (const v of agentVulns(a)) {
    const e = counts.get(v.cve_id) || { cve_id: v.cve_id, product_name: v.product_name, cvss_score: v.cvss_score, severity: v.severity, device_count: 0 };
    e.device_count++;
    counts.set(v.cve_id, e);
  }
  return [...counts.values()].sort((a, b) => b.device_count - a.device_count || (b.cvss_score || 0) - (a.cvss_score || 0)).slice(0, limit);
}

function agentCommands(agent) {
  return once(`cmds:${agent.id}`, () => {
    const d = agent._device;
    const base = NOW - int(1, 20) * HOUR;
    // Ids unique across the fleet (like the real server) — the fleet-wide lists key rows by id.
    const cmd = (id, type, minutesAgo, result, extra = {}) => ({
      id: AGENTS.indexOf(agent) * 100 + id,
      command_type: type,
      parameters: extra.parameters ?? null,
      status: extra.status ?? "completed",
      created_at: iso(base - minutesAgo * 60_000),
      completed_at: extra.status === "running" ? null : iso(base - minutesAgo * 60_000 + 40_000),
      success: extra.status === "running" ? null : extra.success ?? true,
      result: result === null ? null : JSON.stringify(result),
      actor: extra.actor ?? "admin.demo",
    });
    const hardware = {
      manufacturer: d.manufacturer,
      model: d.model,
      serial_number: d.serialNumber,
      uuid: uuid().toUpperCase(),
      bios_version: "1.21.0",
      bios_release_date: "2026-03-14",
      chassis_type: "Notebook",
      motherboard_model: "0WK8X1",
      motherboard_serial_number: `/DEMO${hex(6).toUpperCase()}/`,
      total_memory_bytes: d.physicalMemoryInBytes,
      memory_modules: [
        { slot: "DIMM A", capacity_bytes: d.physicalMemoryInBytes / 2, speed_mhz: 5200, manufacturer: "Micron" },
        { slot: "DIMM B", capacity_bytes: d.physicalMemoryInBytes / 2, speed_mhz: 5200, manufacturer: "Micron" },
      ],
      disks: [{ model: "NVMe SSD 512GB", size_bytes: 512_110_190_592, interface_type: "SCSI", media_type: "Fixed hard disk media" }],
      graphics_cards: [{ name: "Intel(R) Iris(R) Xe Graphics", driver_version: "31.0.101.5186", adapter_ram_bytes: 1_073_741_824 }],
      network_adapters: [{ description: "Intel(R) Wi-Fi 6E AX211 160MHz", mac_address: d.wiFiMacAddress.match(/.{2}/g).join(":"), ip_addresses: ["10.20.12.44"] }],
      pci_devices: Array.from({ length: 24 }, (_, i) => ({ name: `PCI device ${i + 1}` })),
      dns_host_name: agent.hostname,
      domain: "demo.example",
      primary_ip_address: "10.20.12.44",
      session_user: `DEMO\\${d.userPrincipalName.split("@")[0]}`,
    };
    const diagnostic = {
      os_version: d.osVersion,
      uptime: `${int(0, 9)}.${int(1, 23)}:${int(10, 59)}:${int(10, 59)}`,
      disk_total_bytes: d.totalStorageSpaceInBytes,
      disk_free_bytes: d.freeStorageSpaceInBytes,
    };
    const updates = { pending_count: 2, titles: ["Mise à jour cumulative pour Windows 11 (fictive)", "Mise à jour de la plateforme antimalware Microsoft Defender (fictive)"] };
    return [
      cmd(5, "check_windows_updates", 30, updates, { actor: "planificateur" }),
      cmd(4, "system_diagnostic", 90, diagnostic),
      cmd(3, "hardware_inventory", 240, hardware),
      cmd(2, "compliance_check", 600, { ok: true }, { actor: "planificateur" }),
      cmd(1, "force_inventory", 1440, { ok: true }),
    ];
  });
}

function fleetCommands() {
  return AGENTS.flatMap((a) => agentCommands(a).map((c) => ({ ...c, agent_id: a.id, hostname: a.hostname }))).sort((x, y) => (x.created_at < y.created_at ? 1 : -1));
}

function agentCompliance(agent) {
  return {
    agent_id: agent.id,
    hostname: agent.hostname,
    collected_at: agent.last_seen,
    results: VANITAS_RULES.map((r) => {
      const compliant = once(`rule:${r.id}:${agent.id}`, () => (chance(0.03) ? null : rand() < r._rate));
      return { rule_id: r.id, rule_name: r.name, compliant, detail: compliant === false ? "Contrôle en échec (donnée fictive)" : compliant === null ? "Erreur d'exécution du script" : null };
    }),
  };
}

function complianceFleetSummary() {
  return VANITAS_RULES.map((r) => {
    let ok = 0;
    let ko = 0;
    let err = 0;
    for (const a of AGENTS) {
      const res = agentCompliance(a).results.find((x) => x.rule_id === r.id);
      if (res.compliant === true) ok++;
      else if (res.compliant === false) ko++;
      else err++;
    }
    return { rule_id: r.id, rule_name: r.name, compliant_count: ok, non_compliant_count: ko, error_count: err };
  });
}

function suspiciousEvents() {
  return once("susp", () =>
    Array.from({ length: 22 }, (_, i) => {
      const [signal_type, severity, summary, matched_rule] = SIGNALS[i % SIGNALS.length];
      const agent = AGENTS[(i * 5) % AGENTS.length];
      const occurred = NOW - int(10, 14 * 24 * 60) * 60_000;
      const status = i < 5 ? "new" : weighted([["new", 25], ["acknowledged", 30], ["false_positive", 30], ["escalated", 15]]);
      return {
        id: hex(32),
        agent_id: agent.id,
        hostname: agent.hostname,
        signal_type,
        severity,
        matched_rule,
        summary,
        local_event_id: hex(16),
        occurred_at: iso(occurred),
        received_at: iso(occurred + 20_000),
        status,
        handled_by: status === "new" ? null : "admin.demo",
        handled_at: status === "new" ? null : iso(occurred + int(1, 30) * HOUR),
        handled_note: status === "false_positive" ? "Outil d'administration légitime." : null,
      };
    }).sort((a, b) => (a.occurred_at < b.occurred_at ? 1 : -1))
  );
}

function filterSuspicious(params) {
  return suspiciousEvents().filter(
    (e) =>
      (!params.get("agent_id") || e.agent_id === params.get("agent_id")) &&
      (!params.get("signal_type") || e.signal_type === params.get("signal_type")) &&
      (!params.get("severity") || e.severity === params.get("severity")) &&
      (!params.get("status") || e.status === params.get("status")) &&
      (!params.get("since") || e.occurred_at >= params.get("since")) &&
      (!params.get("until") || e.occurred_at <= params.get("until"))
  );
}

function patchStatus() {
  return AGENTS.map((a, i) => {
    const group = VANITAS_GROUPS.find((g) => a.group_ids.includes(g.id) && g.patch_enabled) || null;
    const status = !group ? "off" : weighted([["ok", 55], ["pending-install", 15], ["pending-window", 15], ["installing", 8], ["forced", 7]]);
    const kb = (n) => ({ kb: `KB50${44200 + n}`, title: `Mise à jour de sécurité fictive ${n}` });
    return {
      agent_id: a.id,
      hostname: a.hostname,
      group_id: group?.id ?? null,
      group_name: group?.name ?? null,
      status,
      available: status === "ok" ? [] : [kb(i)],
      todo: status === "pending-install" ? [kb(i)] : [],
      in_progress: status === "installing" ? [kb(i)] : [],
      installed: status === "ok" || status === "forced" ? [kb(i + 50)] : [],
      installed_at: status === "ok" ? ago(int(1, 10) * DAY) : null,
      forced_at: status === "forced" ? ago(int(1, 3) * DAY) : null,
      updated_at: ago(int(1, 6) * HOUR),
      window_start: group?.patch_window_start ?? null,
      window_end: group?.patch_window_end ?? null,
      grace_days: group?.patch_grace_days ?? null,
    };
  });
}

const INSTALLERS = [
  ["Notepad++", "8.7.1", "npp.8.7.1.Installer.x64.exe", "npp.8.7.1.Installer.x64.exe /S"],
  ["7-Zip", "24.08", "7z2408-x64.msi", "msiexec /i 7z2408-x64.msi /qn"],
  ["VLC media player", "3.0.21", "vlc-3.0.21-win64.exe", "vlc-3.0.21-win64.exe /S"],
  ["Outil de gestion des notes de frais", "3.4.0", "notes-frais-3.4.0.msi", "msiexec /i notes-frais-3.4.0.msi /qn"],
].map(([name, version, original_filename, install_command]) => ({
  id: hex(32),
  name,
  version,
  original_filename,
  install_command,
  sha256: hex(64),
  size_bytes: int(2, 90) * 1_000_000,
  uploaded_at: ago(int(5, 60) * DAY),
}));

function installerDeployments() {
  return INSTALLERS.slice(0, 3).map((inst, k) => {
    const group = VANITAS_GROUPS[k];
    const targets = AGENTS.filter((a) => a.group_ids.includes(group.id));
    return {
      installer_id: inst.id,
      targets: [group.name],
      devices: targets.map((a, i) => ({
        agent_id: a.id,
        hostname: a.hostname,
        status: i === 1 && k === 0 ? "bad" : i === 2 ? "pending" : "ok",
        result: i === 1 && k === 0 ? "Code de sortie 1603" : null,
        created_at: ago((k + 1) * DAY),
        completed_at: i === 2 ? null : ago((k + 1) * DAY - 5 * 60_000),
        target_label: group.name,
      })),
    };
  });
}

function activityLog() {
  const fromCommands = fleetCommands().slice(0, 30).map((c) => ({
    id: `cmd-${c.agent_id}-${c.id}`,
    source: "command",
    category: "poste",
    actor: c.actor,
    action: c.command_type,
    target_label: c.hostname,
    detail: null,
    // Même contrat que `routes/activity.py::_command_outcome` : "ok" | "fail" | "pending".
    outcome: c.status === "pending" || c.status === "running" ? "pending" : c.success === false ? "fail" : "ok",
    created_at: c.created_at,
    completed_at: c.completed_at,
    parameters: null,
  }));
  const audit = [
    // Actions d'audit réelles (val.verb.<catégorie>.<action>, écrites par routes/*.py côté serveur).
    ["groupe", "updated", "Postes Finance", "Fenêtre de maintenance modifiée"],
    ["application", "created", "Notepad++ 8.7.1", null],
    ["conformite", "updated", "LAPS configuré", "Script mis à jour"],
    ["poste", "removed", "DEMO-LAP-040", null],
  ].map(([category, action, target_label, detail], i) => ({
    id: `audit-${i}`,
    source: "audit",
    category,
    actor: "admin.demo",
    action,
    target_label,
    detail,
    outcome: null, // une entrée "audit" n'a jamais de résultat (contrat serveur)
    created_at: ago((i + 1) * 9 * HOUR),
    completed_at: null,
    parameters: null,
  }));
  return [...fromCommands, ...audit].sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
}

function agentEol(agent) {
  const findings = [];
  if (agent._device.osVersion.startsWith("10.0.19")) {
    findings.push({ type: "os", name: "Windows 10", version: "22H2", message: "Fin de support depuis le 14 octobre 2025", eol_date: "2025-10-14", days_until_eol: -373, is_eol: true, product_slug: "windows" });
  }
  findings.push({ type: "software", name: "Python", version: "3.10.11", message: "Fin de support dans 12 jours", eol_date: dateOnly(NOW + 12 * DAY), days_until_eol: 12, is_eol: false, product_slug: "python" });
  if (agent.hostname.endsWith("1")) {
    findings.push({ type: "software", name: "Java 8", version: "8.0.411", message: "Fin de support (date exacte non communiquée par l'éditeur)", eol_date: null, days_until_eol: null, is_eol: true, product_slug: "oracle-jdk" });
  }
  return findings;
}

function recentAlerts(limit) {
  const recent = [
    ["stale", AGENTS[5], `« ${AGENTS[5].hostname} » ne s'est pas manifesté depuis plus de 12 h.`, 3 * DAY],
    ["cert", AGENTS[7], `Le certificat de « ${AGENTS[7].hostname} » expire dans 12 jours.`, 2 * DAY],
    ["vuln", AGENTS[1], `Nouvelle vulnérabilité critique détectée sur « ${AGENTS[1].hostname} ».`, 20 * HOUR],
    ["compliance", AGENTS[4], `Nouvel échec de conformité sur « ${AGENTS[4].hostname} » : LAPS configuré.`, 8 * HOUR],
  ].map(([type, a, message, msAgo]) => ({ type, agent_id: a.id, hostname: a.hostname, message, at: ago(msAgo) }));
  return { recent: recent.slice(0, limit), stale_threshold_hours: 12 };
}

const PROFILES = [
  { id: hex(32), name: "Support niveau 1", perms: { postes: "read", terminal: "none", applications: "read", conformite: "read", groupes: "read", activites_suspectes: "read" }, created_at: ago(40 * DAY), updated_at: ago(3 * DAY) },
  { id: hex(32), name: "Support niveau 2", perms: { postes: "write", terminal: "write", applications: "write", conformite: "read", groupes: "write", activites_suspectes: "write" }, created_at: ago(40 * DAY), updated_at: ago(3 * DAY) },
  { id: hex(32), name: "Sécurité (SOC)", perms: { postes: "read", terminal: "none", applications: "none", conformite: "write", groupes: "read", activites_suspectes: "write" }, created_at: ago(30 * DAY), updated_at: ago(8 * DAY) },
  { id: hex(32), name: "Auditeur externe", perms: { postes: "read", terminal: "none", applications: "read", conformite: "read", groupes: "read", activites_suspectes: "none" }, created_at: ago(12 * DAY), updated_at: ago(12 * DAY) },
];

const AGENT_PACKAGES = [
  { id: hex(32), version: "2.4.1", original_filename: "EndpointAgent-2.4.1.zip", sha256: hex(64), size_bytes: 71_220_431, uploaded_at: ago(9 * DAY) },
  { id: hex(32), version: "2.3.0", original_filename: "EndpointAgent-2.3.0.zip", sha256: hex(64), size_bytes: 70_984_112, uploaded_at: ago(48 * DAY) },
];

// ── Router ─────────────────────────────────────────────────────────────────────────────────

const DEMO_USER = {
  username: "admin.demo",
  role: "admin",
  profile_id: null,
  vanitas_perms: { postes: "write", terminal: "write", applications: "write", conformite: "write", groupes: "write", activites_suspectes: "write" },
};

const GET_ROUTES = [
  [/^\/api\/auth\/me$/, () => DEMO_USER],
  // Comptes fictifs (page Profils) — même forme que `backend/auth/store.py::list_users`, dont un
  // lecteur sans aucun accès pour le bandeau « sans aucun accès ».
  [/^\/api\/auth\/users$/, () => [
    ["admin.demo", "admin", null, 120],
    ["support.demo", "viewer", 0, 60],
    ["tech.demo", "viewer", 1, 45],
    ["soc.demo", "viewer", 2, 20],
    ["nouveau.demo", "viewer", null, 2],
  ].map(([username, role, profile, days]) => ({ id: `demo-user-${username}`, username, username_lower: username, role, profile_id: profile === null ? null : PROFILES[profile].id, created_at: ago(days * DAY) }))],
  [/^\/api\/health$/, () => ({ status: "ok" })],
  // Intune
  [/^\/api\/intune\/summary$/, intuneSummary],
  [/^\/api\/intune\/compliance-policy-summary$/, policySummary],
  [/^\/api\/intune\/compliance-detail$/, complianceDetail],
  [/^\/api\/intune\/devices\/([^/]+)\/compliance-status$/, ([id], q) => {
    const device = DEVICES.find((d) => d.id === id);
    const policy = COMPLIANCE_POLICIES.find((p) => p.id === q.get("policy_id"));
    if (!device || !policy) return [];
    const row = POLICY_ROWS.get(policy.id).find((r) => r.device === device);
    return settingsFor(policy.displayName, row?.status || "compliant");
  }],
  [/^\/api\/intune\/secure-score$/, (_, q) => secureScoreHistory(Number(q.get("days")) || 30)],
  [/^\/api\/intune\/secure-score-control-profiles$/, controlProfiles],
  [/^\/api\/intune\/apps-catalog$/, () => once("catalog", appsCatalog)],
  [/^\/api\/intune\/apps\/install-summary$/, installSummary],
  [/^\/api\/intune\/apps\/([^/]+)\/assignments$/, () => ({ required: ["Tous les appareils Windows"], available: ["Utilisateurs - Informatique"], excluded: ["Postes kiosque"] })],
  [/^\/api\/intune\/apps\/([^/]+)\/install-status$/, ([id]) => {
    const devices = APP_INSTALL.get(id) || [];
    return { total: devices.length, devices };
  }],
  [/^\/api\/intune\/discovered-apps\/([^/]+)\/devices$/, () => {
    const devices = DEVICES.filter((d) => d.operatingSystem === "Windows").slice(0, int(3, 15)).map((d) => ({ deviceName: d.deviceName, userPrincipalName: d.userPrincipalName, userDisplayName: d.userDisplayName, operatingSystem: d.operatingSystem, osVersion: d.osVersion, lastSyncDateTime: d.lastSyncDateTime, complianceState: d.complianceState, managementState: "managed", manufacturer: d.manufacturer, model: d.model, deviceId: d.id, department: d._department }));
    return { total: devices.length, devices };
  }],
  [/^\/api\/intune\/app-library$/, () => once("library", () => [
    ["Outil de gestion des notes de frais", "Demo Software", "3.4.0", "manual"],
    ["Notepad++", "Notepad++ Team", "8.7.1", "packaged"],
    ["7-Zip", "Igor Pavlov", "24.08", "packaged"],
    ["VLC media player", "VideoLAN", "3.0.21", "packaged"],
    ["Client VPN de démonstration", "Demo Networks", "7.4.1", "manual"],
  ].map(([displayName, publisher, version, source], i) => ({
    id: hex(32),
    source,
    displayName,
    publisher,
    version,
    note: source === "manual" ? "Installé manuellement par le service informatique." : null,
    addedAt: ago((40 - i * 6) * DAY),
    updatedAt: ago((5 + i) * DAY),
    package: source === "packaged"
      ? {
          intunewinFileName: `${displayName.replace(/\W+/g, "")}-${version}.intunewin`,
          installCommand: "install.cmd",
          uninstallCommand: "uninstall.cmd",
          detectionScript: "# Script de détection fictif\nexit 0",
          requirements: { operatingSystem: "Windows 10 1607 ou supérieur", architecture: "x64" },
          config: { sourceType: "msi", installMode: "silent", options: [], detectionMode: "greaterOrEqual" },
          repo: null,
        }
      : null,
    icon: null,
  })))],
  // Defender
  [/^\/api\/defender\/summary$/, defenderSummary],
  [/^\/api\/defender\/exposure-score$/, () => ({ "@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#ExposureScore/$entity", time: ago(HOUR), score: 29.4, rbacGroupName: null, rbacGroupId: null })],
  [/^\/api\/defender\/recommendations$/, (_, q) => recommendations(Number(q.get("top")) || 8)],
  [/^\/api\/defender\/non-onboarded$/, () => clean(NON_ONBOARDED)],
  [/^\/api\/defender\/machines$/, () => clean(ALL_MACHINES)],
  [/^\/api\/defender\/alerts$/, (_, q) => clean(ALERTS.slice(0, Number(q.get("top")) || 200))],
  [/^\/api\/defender\/alerts\/([^/]+)$/, ([id]) => {
    const alert = ALERTS.find((a) => a.id === id);
    return alert ? alertDetail(alert) : demoError;
  }],
  [/^\/api\/defender\/vulnerabilities$/, (_, q) => searchVulnerabilities(q.get("query"), Number(q.get("max_results")) || 20)],
  [/^\/api\/defender\/vulnerability-inventory$/, () => CVES.map((c) => ({ cve_code: c.cve_code, software_vendor: c.software_vendor, software_name: c.software_name, affected_count: c.affected_count }))],
  [/^\/api\/defender\/exposure-vulnerable-apps$/, (_, q) => vulnerableApps(Number(q.get("top")) || 5)],
  [/^\/api\/defender\/machines\/([^/]+)\/vulnerable-software$/, (_, q) => vulnerableApps(Number(q.get("top")) || 5).map(({ software_vendor, software_name, cve_count }) => ({ software_vendor, software_name, cve_count, paths: [] }))],
  [/^\/api\/defender\/watched-cves$/, () => once("watched", () => [CVES[2], CVES[70], CVES[130]].map((c) => ({ cve_code: c.cve_code, added_at: ago(12 * DAY), last_checked: ago(2 * HOUR), last_error: null, result: searchVulnerabilities(c.cve_code, 1)[0] || null })))],
  [/^\/api\/defender\/anssi-matches$/, () => once("anssi", anssiMatches)],
  // Transverse
  [/^\/api\/history$/, () => once("history", history)],
  [/^\/api\/device-overview$/, (_, q) => deviceOverview(q.get("device_name") || "")],
  [/^\/api\/device-inventory$/, () => once("inventory", deviceInventory)],
  // Vanitas
  [/^\/api\/vanitas\/agents$/, () => clean(AGENTS)],
  [/^\/api\/vanitas\/agents\/([^/]+)$/, ([id]) => (agentById(id) ? agentInventory(agentById(id)) : demoError)],
  [/^\/api\/vanitas\/agents\/([^/]+)\/vulnerabilities$/, ([id]) => (agentById(id) ? agentVulns(agentById(id)) : [])],
  [/^\/api\/vanitas\/agents\/([^/]+)\/commands$/, ([id]) => (agentById(id) ? agentCommands(agentById(id)) : [])],
  [/^\/api\/vanitas\/agents\/([^/]+)\/compliance$/, ([id]) => (agentById(id) ? agentCompliance(agentById(id)) : demoError)],
  [/^\/api\/vanitas\/agents\/([^/]+)\/eol$/, ([id]) => (agentById(id) ? agentEol(agentById(id)) : [])],
  [/^\/api\/vanitas\/agents\/([^/]+)\/shell\/sessions\/latest$/, () => null],
  [/^\/api\/vanitas\/commands$/, fleetCommands],
  [/^\/api\/vanitas\/history$/, () => once("history", history).map((p) => ({ date: p.date, vanitas: p.vanitas }))],
  [/^\/api\/vanitas\/vulnerabilities\/top$/, (_, q) => topVulnerabilities(Number(q.get("limit")) || 5)],
  [/^\/api\/vanitas\/enrollment-defaults$/, () => ({ server_url: "https://vanitas.demo.example:8443", same_machine_url: "https://localhost:8443" })],
  [/^\/api\/vanitas\/compliance\/rules\/summary$/, () => clean(VANITAS_RULES).map(({ id, name, enabled, updated_at }) => ({ id, name, enabled, updated_at }))],
  [/^\/api\/vanitas\/compliance\/rules$/, () => clean(VANITAS_RULES)],
  [/^\/api\/vanitas\/compliance\/summary$/, () => once("compSum", complianceFleetSummary)],
  [/^\/api\/vanitas\/cve-avis\/([^/]+)$/, () => null],
  [/^\/api\/vanitas\/alerts\/recent$/, (_, q) => recentAlerts(Number(q.get("limit")) || 20)],
  [/^\/api\/vanitas\/groups$/, () => clean(VANITAS_GROUPS)],
  [/^\/api\/vanitas\/groups\/([^/]+)\/members$/, ([id]) => AGENTS.filter((a) => a.group_ids.includes(id)).map((a) => a.hostname).sort()],
  [/^\/api\/vanitas\/patch-status$/, () => once("patch", patchStatus)],
  [/^\/api\/vanitas\/installers$/, () => INSTALLERS],
  [/^\/api\/vanitas\/installer-deployments$/, () => once("deploy", installerDeployments)],
  [/^\/api\/vanitas\/activity-log$/, () => once("activity", activityLog)],
  [/^\/api\/vanitas\/agent-packages$/, () => AGENT_PACKAGES],
  [/^\/api\/vanitas\/agent-packages\/latest$/, () => AGENT_PACKAGES[0]],
  [/^\/api\/vanitas\/profiles$/, () => PROFILES],
  [/^\/api\/vanitas\/suspicious-events\/summary$/, () => {
    const by_severity = {};
    const by_status = {};
    for (const e of suspiciousEvents()) {
      by_severity[e.severity] = (by_severity[e.severity] || 0) + 1;
      by_status[e.status] = (by_status[e.status] || 0) + 1;
    }
    return { by_severity, by_status };
  }],
  [/^\/api\/vanitas\/suspicious-events$/, (_, q) => filterSuspicious(q)],
  [/^\/api\/vanitas\/suspicious-events\/([^/]+)\/correlation$/, ([id]) => {
    const e = suspiciousEvents().find((x) => x.id === id);
    return e ? deviceOverview(e.hostname) : demoError;
  }],
  [/^\/api\/vanitas\/suspicious-events\/([^/]+)$/, ([id]) => {
    const e = suspiciousEvents().find((x) => x.id === id);
    return e ? { ...e, detail: { process_name: "powershell.exe", parent_process: "winword.exe", command_line: "powershell.exe -NoProfile -EncodedCommand SQBFAFgA...", user: `DEMO\\${AGENTS[0]._device.userPrincipalName.split("@")[0]}` } } : demoError;
  }],
];

// Réponse d'erreur métier dans la forme attendue (dict ou liste) — contrat HTTP 200 du backend.
function notAvailable(path) {
  const listLike = /\/(agents|commands|installers|groups|profiles|events|users|machines|alerts|vulnerabilities|policies|apps|cves)(\?|$)/.test(path);
  return listLike ? [demoError] : demoError;
}

/** Point d'entrée appelé par api.js en mode démo. Simule une petite latence réseau. */
export async function demoRequest(method, path) {
  await new Promise((r) => setTimeout(r, 120));
  const url = new URL(path, "http://demo.local");
  if (method === "POST" && url.pathname === "/api/auth/login") return { ok: true, username: DEMO_USER.username, role: DEMO_USER.role };
  if (method === "POST" && url.pathname === "/api/auth/logout") return { ok: true };
  if (method !== "GET") return demoError;
  for (const [re, handler] of GET_ROUTES) {
    const m = url.pathname.match(re);
    if (m) return handler(m.slice(1).map(decodeURIComponent), url.searchParams);
  }
  return notAvailable(url.pathname);
}

export const DEMO_DOMAIN = DOMAIN;
export const DEMO_USERS_COUNT = USERS.length;
