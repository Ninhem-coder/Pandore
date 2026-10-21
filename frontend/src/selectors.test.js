import { describe, it, expect } from "vitest";
import {
  computeTopRiskDevices,
  computeNewDevices,
  groupComplianceDetailByOS,
  buildDonutEntries,
  computeSecureScoreByCategory,
  computeSecureScoreQuickWins,
  computeSecureScoreAllControls,
  computeHistoryTrend,
  computeVanitasTrend,
  computeDevicePosture,
  buildCveExportData,
} from "./selectors.js";

/**
 * Tests unitaires des dérivations métier de selectors.js — extraits de theme.test.js à la
 * revue d'architecture du 2026-08-17 en même temps que le code qu'ils couvrent (voir
 * selectors.js). Se concentre sur les fonctions dont un bug a DÉJÀ été observé en prod dans
 * cette session (computeTopRiskDevices — filtre "Low" trop permissif ; buildDonutEntries —
 * ordre de "Autres politiques") pour éviter une régression silencieuse.
 *
 * Les trois describe Secure Score ci-dessous (ajoutés à la revue de code du 2026-08-18)
 * couvrent la jointure `controlScore.controlName === controlProfile.id` que le code
 * documente lui-même comme "PAS ENCORE VÉRIFIÉE sur données réelles" (voir selectors.js,
 * docstring de computeSecureScoreQuickWins) : le point le plus important à figer par un
 * test n'est pas le cas où la jointure matche, mais celui où elle ne matche PAS — pour
 * documenter la dégradation silencieuse attendue (liste vide, pas d'erreur) plutôt que de
 * la découvrir le jour où SecurityEvents.Read.All sera accordé et que de vraies données
 * arriveront.
 */

describe("computeTopRiskDevices", () => {
  it("exclut les devices sans signal de risque réel (régression 'Low' pur)", () => {
    const machines = [
      { id: "a", exposureLevel: "High" },
      { id: "b", exposureLevel: "Low" }, // ne doit PAS apparaître : Low pur sans alerte
      { id: "c", exposureLevel: "Medium" },
      { id: "d", exposureLevel: "Informational" },
    ];
    const result = computeTopRiskDevices(machines, [], 50);
    expect(result.map((m) => m.id)).toEqual(["a", "c"]);
  });

  it("inclut un device Low s'il a une alerte active", () => {
    const machines = [{ id: "e", exposureLevel: "Low" }];
    const alerts = [{ machineId: "e", status: "New" }];
    const result = computeTopRiskDevices(machines, alerts, 50);
    expect(result.map((m) => m.id)).toEqual(["e"]);
  });

  it("ne compte pas les alertes résolues", () => {
    const machines = [{ id: "f", exposureLevel: "Low" }];
    const alerts = [{ machineId: "f", status: "Resolved" }];
    const result = computeTopRiskDevices(machines, alerts, 50);
    expect(result).toHaveLength(0);
  });

  it("trie par exposureLevel puis alertes puis riskScore", () => {
    const machines = [
      { id: "low-alert", exposureLevel: "Medium", alertCount: 0 },
      { id: "high-noalert", exposureLevel: "High" },
    ];
    const alerts = [{ machineId: "low-alert", status: "New" }];
    const result = computeTopRiskDevices(machines, alerts, 50);
    expect(result[0].id).toBe("high-noalert");
  });

  it("respecte la limite", () => {
    const machines = Array.from({ length: 10 }, (_, i) => ({ id: `m${i}`, exposureLevel: "High" }));
    expect(computeTopRiskDevices(machines, [], 3)).toHaveLength(3);
  });
});

describe("computeNewDevices", () => {
  const now = new Date("2026-08-10T12:00:00Z");

  it("garde uniquement les devices vus dans la fenêtre", () => {
    const machines = [
      { id: "recent", firstSeen: "2026-08-09T00:00:00Z" }, // 1j
      { id: "old", firstSeen: "2026-07-01T00:00:00Z" }, // trop vieux
      { id: "boundary", firstSeen: "2026-08-03T12:00:00Z" }, // exactement 7j
    ];
    const result = computeNewDevices(machines, 7, 100, now);
    expect(result.map((m) => m.id).sort()).toEqual(["boundary", "recent"]);
  });

  it("trie du plus récent au plus ancien", () => {
    const machines = [
      { id: "a", firstSeen: "2026-08-05T00:00:00Z" },
      { id: "b", firstSeen: "2026-08-09T00:00:00Z" },
    ];
    const result = computeNewDevices(machines, 7, 100, now);
    expect(result.map((m) => m.id)).toEqual(["b", "a"]);
  });

  it("ignore les devices sans firstSeen ou en erreur", () => {
    const machines = [{ id: "err", error: true, firstSeen: "2026-08-09T00:00:00Z" }, { id: "nofs" }];
    expect(computeNewDevices(machines, 7, 100, now)).toHaveLength(0);
  });
});

describe("buildDonutEntries", () => {
  it("trie par valeur décroissante et calcule les fractions", () => {
    const { total, entries } = buildDonutEntries({ a: 10, b: 30, c: 60 });
    expect(total).toBe(100);
    expect(entries.map((e) => e.key)).toEqual(["c", "b", "a"]);
    expect(entries[0].fraction).toBeCloseTo(0.6);
  });

  it("épingle les clés pinLast en dernière position même si leur valeur est haute", () => {
    const { entries } = buildDonutEntries({ real: 10, other: 999 }, { pinLast: ["other"] });
    expect(entries.map((e) => e.key)).toEqual(["real", "other"]);
  });

  it("ignore les valeurs nulles/négatives/non numériques", () => {
    const { entries } = buildDonutEntries({ a: 5, b: 0, c: -1, d: "x" });
    expect(entries.map((e) => e.key)).toEqual(["a"]);
  });
});

describe("groupComplianceDetailByOS", () => {
  it("compte chaque appareil une seule fois, dans sa situation la plus grave", () => {
    const complianceDetail = {
      policies: [
        {
          id: "pol1",
          displayName: "Politique 1",
          failedCount: 2,
          devices: [
            { deviceName: "PC-1", operatingSystem: "Windows", complianceCategory: "Non conforme" },
            { deviceName: "PC-2", operatingSystem: "Windows", complianceCategory: "Non applicable" },
          ],
        },
        {
          id: "pol2",
          displayName: "Politique 2",
          failedCount: 1,
          devices: [
            // Même appareil que ci-dessus mais "Non applicable" ici : sa pire situation
            // (Non conforme, via pol1) doit l'emporter, pas être écrasée par ce second passage.
            { deviceName: "PC-1", operatingSystem: "Windows", complianceCategory: "Non applicable" },
          ],
        },
      ],
    };

    const { osGroups, distinctDevices, byCategory } = groupComplianceDetailByOS(complianceDetail);
    expect(osGroups).toHaveLength(1);
    expect(osGroups[0].os).toBe("Windows");
    // PC-1 = Non conforme (pire cas retenu), PC-2 = Non applicable (informational, pas compté).
    expect(osGroups[0].count).toBe(1);
    expect(distinctDevices).toBe(1);
    expect(byCategory["Non conforme"]).toBe(1);
  });

  it("exclut les OS sans aucun appareil réellement en faute", () => {
    const complianceDetail = {
      policies: [
        {
          id: "pol1",
          displayName: "Politique 1",
          devices: [{ deviceName: "Mac-1", operatingSystem: "macOS", complianceCategory: "Non applicable" }],
        },
      ],
    };
    const { osGroups } = groupComplianceDetailByOS(complianceDetail);
    expect(osGroups).toHaveLength(0);
  });

  it("retombe sur 'Inconnu' si operatingSystem est absent", () => {
    const complianceDetail = {
      policies: [
        {
          id: "pol1",
          displayName: "Politique 1",
          devices: [{ deviceName: "X", complianceCategory: "Non conforme" }],
        },
      ],
    };
    const { osGroups } = groupComplianceDetailByOS(complianceDetail);
    expect(osGroups[0].os).toBe("Inconnu");
  });
});

describe("computeSecureScoreByCategory", () => {
  it("agrège score/maxScore par catégorie et calcule le pourcentage", () => {
    const controlScores = [
      { controlName: "c1", controlCategory: "Identité", score: 5 },
      { controlName: "c2", controlCategory: "Identité", score: 3 },
      { controlName: "c3", controlCategory: "Appareils", score: 8 },
    ];
    const controlProfiles = [
      { id: "c1", controlCategory: "Identité", maxScore: 10 },
      { id: "c2", controlCategory: "Identité", maxScore: 10 },
      { id: "c3", controlCategory: "Appareils", maxScore: 10 },
    ];
    const result = computeSecureScoreByCategory(controlScores, controlProfiles);
    const identite = result.find((r) => r.category === "Identité");
    expect(identite).toMatchObject({ score: 8, maxScore: 20, percentage: 40 });
  });

  it("trie par pourcentage décroissant", () => {
    const controlScores = [
      { controlName: "low", controlCategory: "A", score: 1 },
      { controlName: "high", controlCategory: "B", score: 9 },
    ];
    const controlProfiles = [
      { id: "low", controlCategory: "A", maxScore: 10 },
      { id: "high", controlCategory: "B", maxScore: 10 },
    ];
    const result = computeSecureScoreByCategory(controlScores, controlProfiles);
    expect(result.map((r) => r.category)).toEqual(["B", "A"]);
  });

  it("ignore les entrées sans score/maxScore numérique ou en erreur", () => {
    const controlScores = [{ controlName: "c1", controlCategory: "A", score: "pas un nombre" }, null];
    const controlProfiles = [{ id: "c1", controlCategory: "A", error: true }, { controlCategory: "A" }];
    expect(computeSecureScoreByCategory(controlScores, controlProfiles)).toEqual([]);
  });

  it("une catégorie sans AUCUN profil catalogue n'apparaît pas (pas de maxScore connu)", () => {
    // Reflète la limite documentée dans selectors.js : le pourcentage par catégorie dépend
    // entièrement du catalogue controlProfiles — sans lui, pas de ligne du tout pour cette
    // catégorie, même si des scores existent.
    const controlScores = [{ controlName: "c1", controlCategory: "Orpheline", score: 5 }];
    expect(computeSecureScoreByCategory(controlScores, [])).toEqual([]);
  });
});

describe("computeSecureScoreQuickWins", () => {
  const controlScores = [
    { controlName: "c1", controlCategory: "Identité", score: 2, description: "Contrôle 1" },
    { controlName: "c2", controlCategory: "Identité", score: 9, description: "Contrôle 2" },
    { controlName: "c3", controlCategory: "Appareils", score: 5, description: "Contrôle 3" },
  ];
  const controlProfiles = [
    { id: "c1", maxScore: 10, title: "Titre 1", actionUrl: "https://example/1" },
    { id: "c2", maxScore: 10, title: "Titre 2" },
    { id: "c3", maxScore: 5, title: "Titre 3" }, // gap 0 : déjà acquis, ne doit pas apparaître
  ];

  it("calcule le gap (maxScore - score) et garde les plus gros écarts en tête", () => {
    const result = computeSecureScoreQuickWins(controlScores, controlProfiles);
    expect(result.map((r) => r.controlName)).toEqual(["c1", "c2"]);
    expect(result[0]).toMatchObject({ gap: 8, maxScore: 10, score: 2, actionUrl: "https://example/1" });
  });

  it("exclut un contrôle déjà à son score maximal (gap nul)", () => {
    const result = computeSecureScoreQuickWins(controlScores, controlProfiles);
    expect(result.find((r) => r.controlName === "c3")).toBeUndefined();
  });

  it("respecte topN", () => {
    const result = computeSecureScoreQuickWins(controlScores, controlProfiles, { topN: 1 });
    expect(result).toHaveLength(1);
    expect(result[0].controlName).toBe("c1");
  });

  it("dégradation silencieuse si la jointure controlName/id ne matche JAMAIS (catalogue vide ou format différent) — pas d'erreur, liste vide", () => {
    // Cas explicitement signalé comme "pas encore vérifié sur données réelles" dans le
    // docstring de selectors.js : tant que controlProfiles ne matche aucun controlName,
    // aucun gap n'est calculable et la fonction doit renvoyer [] plutôt que planter.
    const result = computeSecureScoreQuickWins(controlScores, [{ id: "id-qui-ne-matche-rien", maxScore: 10 }]);
    expect(result).toEqual([]);
  });

  it("ignore les entrées de score sans valeur numérique", () => {
    const result = computeSecureScoreQuickWins([{ controlName: "c1" }, null], controlProfiles);
    expect(result).toEqual([]);
  });
});

describe("computeSecureScoreAllControls", () => {
  const controlScores = [
    { controlName: "c1", controlCategory: "Identité", score: 2 },
    { controlName: "c2", controlCategory: "Identité", score: 10 },
    { controlName: "c3", controlCategory: "Appareils", score: 0 },
    { controlName: "c4", controlCategory: "Appareils", score: 1 },
  ];
  const controlProfiles = [
    { id: "c1", maxScore: 10 },
    { id: "c2", maxScore: 10 }, // gap 0 : implemented
    { id: "c3", maxScore: 8 },
    { id: "c4", maxScore: 6 },
  ];

  it("regroupe par catégorie et calcule toDoCount (contrôles non encore acquis)", () => {
    const result = computeSecureScoreAllControls(controlScores, controlProfiles);
    const identite = result.find((r) => r.category === "Identité");
    expect(identite.controls).toHaveLength(2);
    expect(identite.toDoCount).toBe(1); // c1 à corriger, c2 déjà acquis
  });

  it("trie les catégories par toDoCount décroissant", () => {
    // Appareils : c3 + c4 non-acquis (toDoCount 2) ; Identité : seul c1 non-acquis
    // (toDoCount 1) — Appareils doit donc passer en tête malgré son ordre d'apparition
    // plus tardif dans controlScores.
    const result = computeSecureScoreAllControls(controlScores, controlProfiles);
    expect(result.map((r) => r.category)).toEqual(["Appareils", "Identité"]);
  });

  it("trie les contrôles au sein d'une catégorie par gap décroissant", () => {
    const result = computeSecureScoreAllControls(controlScores, controlProfiles);
    const identite = result.find((r) => r.category === "Identité");
    expect(identite.controls.map((c) => c.controlName)).toEqual(["c1", "c2"]);
  });

  it("dégradation silencieuse si la jointure ne matche jamais : tous les contrôles restent listés, marqués non-acquis, gap inconnu", () => {
    const result = computeSecureScoreAllControls(controlScores, []);
    const allControls = result.flatMap((r) => r.controls);
    expect(allControls).toHaveLength(4);
    expect(allControls.every((c) => c.implemented === false && c.gap === null)).toBe(true);
  });
});

describe("computeHistoryTrend", () => {
  it("calcule le delta vs 7 jours et vs 30 jours en cherchant le dernier point connu à cette date ou avant", () => {
    const points = [
      { date: "2026-05-20", intune: { complianceRate: 80 }, defender: { exposureScore: 40 } },
      // Trou volontaire : le dashboard n'a pas tourné tous les jours. Ce point (2026-08-01)
      // tombe DANS la fenêtre des 7 jours (cutoff 2026-08-11) mais PAS dans celle des 30
      // jours (cutoff 2026-07-19) — sert à vérifier que les deux fenêtres retrouvent
      // chacune le bon point de comparaison, pas le même par accident.
      { date: "2026-08-01", intune: { complianceRate: 85 }, defender: { exposureScore: 35 } },
      { date: "2026-08-18", intune: { complianceRate: 92 }, defender: { exposureScore: 20 } },
    ];
    const trend = computeHistoryTrend(points);
    expect(trend.intune.current).toBe(92);
    expect(trend.intune.delta7).toBe(7); // 92 - 85 (dernier point ≤ 2026-08-11)
    expect(trend.intune.delta30).toBe(12); // 92 - 80 (dernier point ≤ 2026-07-19)
    expect(trend.defender.current).toBe(20);
    expect(trend.defender.delta7).toBe(-15); // 20 - 35
  });

  it("renvoie current/delta null si l'historique est vide", () => {
    const trend = computeHistoryTrend([]);
    expect(trend.intune).toEqual({ current: null, delta7: null, delta30: null, series: [] });
    expect(trend.defender).toEqual({ current: null, delta7: null, delta30: null, series: [] });
  });

  it("delta null si aucun point ne couvre la fenêtre demandée (historique trop jeune)", () => {
    const points = [{ date: "2026-08-18", intune: { complianceRate: 92 }, defender: { exposureScore: 20 } }];
    const trend = computeHistoryTrend(points);
    expect(trend.intune.current).toBe(92);
    expect(trend.intune.delta7).toBeNull();
    expect(trend.intune.delta30).toBeNull();
  });

  it("ignore les points sans ce domaine (null, ex. défaillance Intune ou Defender ce jour-là)", () => {
    const points = [
      { date: "2026-08-17", intune: null, defender: { exposureScore: 30 } },
      { date: "2026-08-18", intune: { complianceRate: 92 }, defender: null },
    ];
    const trend = computeHistoryTrend(points);
    expect(trend.intune.series).toEqual([92]);
    expect(trend.defender.series).toEqual([30]);
  });

  it("trie les points par date même si le backend les renvoyait dans le désordre", () => {
    const points = [
      { date: "2026-08-18", intune: { complianceRate: 92 }, defender: null },
      { date: "2026-08-01", intune: { complianceRate: 70 }, defender: null },
    ];
    const trend = computeHistoryTrend(points);
    expect(trend.intune.current).toBe(92); // le plus récent, pas le dernier du tableau d'origine
    expect(trend.intune.series).toEqual([70, 92]);
  });

  it("arrondit `current` à 1 décimale (bug de revue de code du 2026-08-20 : Defender renvoie un score avec de nombreuses décimales)", () => {
    const points = [{ date: "2026-08-18", intune: null, defender: { exposureScore: 26.988728272748943 } }];
    const trend = computeHistoryTrend(points);
    expect(trend.defender.current).toBe(27);
  });

  it("`rangeDays` limite uniquement la série renvoyée (sparkline) — current/delta7/delta30 restent calculés sur l'historique complet", () => {
    const points = [
      { date: "2026-05-01", intune: { complianceRate: 60 }, defender: null },
      { date: "2026-08-01", intune: { complianceRate: 85 }, defender: null },
      { date: "2026-08-11", intune: { complianceRate: 88 }, defender: null },
      { date: "2026-08-18", intune: { complianceRate: 92 }, defender: null },
    ];
    const full = computeHistoryTrend(points);
    const last2 = computeHistoryTrend(points, 2);

    expect(full.intune.series).toEqual([60, 85, 88, 92]);
    expect(last2.intune.series).toEqual([88, 92]);
    // current et les deltas ne bougent pas selon la fenêtre d'affichage choisie.
    expect(last2.intune.current).toBe(full.intune.current);
    expect(last2.intune.delta7).toBe(full.intune.delta7);
    expect(last2.intune.delta30).toBe(full.intune.delta30);
  });

  it("`rangeDays` plus grand que l'historique disponible ne tronque rien", () => {
    const points = [
      { date: "2026-08-17", intune: { complianceRate: 90 }, defender: null },
      { date: "2026-08-18", intune: { complianceRate: 92 }, defender: null },
    ];
    const trend = computeHistoryTrend(points, 90);
    expect(trend.intune.series).toEqual([90, 92]);
  });
});

describe("computeVanitasTrend", () => {
  it("extrait chaque métrique du domaine vanitas et calcule current/delta7/série", () => {
    const points = [
      { date: "2026-09-10", vanitas: { complianceRate: 80, suspiciousNew: 30, onlineAgents: 4, eolOccurrences: 5 } },
      { date: "2026-09-17", vanitas: { complianceRate: 92, suspiciousNew: 12, onlineAgents: 5, eolOccurrences: 2 } },
    ];
    const trend = computeVanitasTrend(points);
    expect(trend.complianceRate.current).toBe(92);
    expect(trend.complianceRate.delta7).toBe(12); // 92 - 80 (point ≤ cutoff 7j)
    expect(trend.complianceRate.series).toEqual([80, 92]);
    expect(trend.suspiciousNew.current).toBe(12);
    expect(trend.suspiciousNew.delta7).toBe(-18);
    expect(trend.eolOccurrences.series).toEqual([5, 2]);
  });

  it("ignore les jours sans point vanitas (null — antérieurs au jalon ou domaine en erreur)", () => {
    const points = [
      { date: "2026-09-15", vanitas: null },
      { date: "2026-09-16", vanitas: { complianceRate: 88 } },
      { date: "2026-09-17", vanitas: { complianceRate: 90 } },
    ];
    const trend = computeVanitasTrend(points);
    expect(trend.complianceRate.series).toEqual([88, 90]);
    // une métrique absente d'un point présent reste vide plutôt que 0 trompeur
    expect(trend.suspiciousNew.series).toEqual([]);
    expect(trend.suspiciousNew.current).toBeNull();
  });

  it("renvoie des métriques vides sur un historique vide ou sans domaine vanitas", () => {
    const trend = computeVanitasTrend([{ date: "2026-09-17", intune: { complianceRate: 90 } }]);
    expect(trend.complianceRate).toEqual({ current: null, delta7: null, delta30: null, series: [] });
  });
});

describe("computeDevicePosture", () => {
  it("renvoie null si l'appareil n'a été trouvé dans aucun des deux systèmes", () => {
    expect(computeDevicePosture({ intune: { found: false }, defender: { found: false } })).toBeNull();
  });

  it("Sain, sans nuance, quand les deux systèmes sont propres", () => {
    const posture = computeDevicePosture({
      intune: { found: true, device: { complianceState: "compliant" } },
      defender: { found: true, machine: { exposureLevel: "Low" }, alerts: [] },
    });
    expect(posture).toEqual({ tone: "good", label: "Sain", reasons: [], partial: false, activeAlertsCount: 0 });
  });

  it("Critique si non conforme côté Intune, même si Defender ne voit rien à signaler", () => {
    const posture = computeDevicePosture({
      intune: { found: true, device: { complianceState: "noncompliant" } },
      defender: { found: true, machine: { exposureLevel: "Low" }, alerts: [] },
    });
    expect(posture.tone).toBe("danger");
    expect(posture.reasons).toContain("appareil non conforme (Intune)");
  });

  it("Critique si une alerte active de sévérité High, même appareil conforme Intune (le pire signal l'emporte, pas une moyenne)", () => {
    const posture = computeDevicePosture({
      intune: { found: true, device: { complianceState: "compliant" } },
      defender: {
        found: true,
        machine: { exposureLevel: "Low" },
        alerts: [{ status: "New", severity: "High" }],
      },
    });
    expect(posture.tone).toBe("danger");
    expect(posture.reasons).toContain("alerte active de sévérité élevée");
  });

  it("ignore les alertes résolues ou en erreur dans le décompte des alertes actives", () => {
    const posture = computeDevicePosture({
      intune: { found: true, device: { complianceState: "compliant" } },
      defender: {
        found: true,
        machine: { exposureLevel: "Low" },
        alerts: [{ status: "Resolved", severity: "High" }, { error: true }],
      },
    });
    expect(posture.tone).toBe("good");
    expect(posture.activeAlertsCount).toBe(0);
  });

  it("À surveiller (pas Critique) pour des alertes actives de sévérité non élevée", () => {
    const posture = computeDevicePosture({
      intune: { found: true, device: { complianceState: "compliant" } },
      defender: {
        found: true,
        machine: { exposureLevel: "Low" },
        alerts: [{ status: "InProgress", severity: "Medium" }],
      },
    });
    expect(posture.tone).toBe("warning");
    expect(posture.activeAlertsCount).toBe(1);
  });

  it("partial=true quand un seul des deux systèmes a trouvé l'appareil", () => {
    const posture = computeDevicePosture({
      intune: { found: true, device: { complianceState: "compliant" } },
      defender: { found: false },
    });
    expect(posture.partial).toBe(true);
    expect(posture.tone).toBe("good");
  });
});

describe("buildCveExportData", () => {
  const sampleCve = {
    cve_code: "CVE-2024-3400",
    severity: "Critical",
    cvss_score: 10,
    exploitability_level: "High",
    security_update_available: true,
    affected_count: 2,
    first_seen: "2026-08-01T08:00:00Z",
    last_seen: "2026-08-19T08:00:00Z",
    devices: [
      {
        hostname: "DEMO-WKS-104",
        rbac_group: "Sièges",
        disk_paths: ["C:\\Program Files\\7-Zip\\7z.exe", "C:\\Users\\mvi\\Downloads\\7z.exe"],
        registry_paths: [],
      },
      {
        hostname: "DEMO-WKS-105",
        rbac_group: null,
        disk_paths: [],
        registry_paths: ["HKLM\\SOFTWARE\\7-Zip"],
      },
    ],
  };

  it("reprend les mêmes champs que le bandeau de métadonnées de VulnCard", () => {
    const { summary } = buildCveExportData(sampleCve);
    const byLabel = Object.fromEntries(summary.map((row) => [row.label, row.value]));
    expect(byLabel["CVE"]).toBe("CVE-2024-3400");
    expect(byLabel["Sévérité"]).toBe("Critical");
    expect(byLabel["Score CVSS"]).toBe(10);
    expect(byLabel["Correctif disponible"]).toBe("Oui");
    expect(byLabel["Devices exposés"]).toBe(2);
    expect(byLabel["1ère détection (évidence logicielle)"]).toBe("2026-08-01T08:00:00Z");
  });

  it("joint les chemins par un saut de ligne, comme un chemin par ligne à l'écran (PathList)", () => {
    const { devices } = buildCveExportData(sampleCve);
    expect(devices[0].diskPaths).toBe("C:\\Program Files\\7-Zip\\7z.exe\nC:\\Users\\mvi\\Downloads\\7z.exe");
    expect(devices[0].registryPaths).toBe("");
    expect(devices[1].diskPaths).toBe("");
    expect(devices[1].registryPaths).toBe("HKLM\\SOFTWARE\\7-Zip");
  });

  it("laisse un groupe RBAC absent en chaîne vide plutôt qu'en 'null' littéral", () => {
    const { devices } = buildCveExportData(sampleCve);
    expect(devices[1].rbacGroup).toBe("");
  });

  it("retombe sur affected_count via devices.length quand affected_count est absent", () => {
    const { summary } = buildCveExportData({ ...sampleCve, affected_count: undefined });
    const byLabel = Object.fromEntries(summary.map((row) => [row.label, row.value]));
    expect(byLabel["Devices exposés"]).toBe(2);
  });

  it("ne plante pas sur une CVE sans device exposé", () => {
    const { summary, devices } = buildCveExportData({ cve_code: "CVE-2024-9999", devices: [] });
    expect(devices).toEqual([]);
    const byLabel = Object.fromEntries(summary.map((row) => [row.label, row.value]));
    expect(byLabel["Sévérité"]).toBe("Inconnu");
    expect(byLabel["Correctif disponible"]).toBe("Non connu");
  });

  it("ne plante pas sur une entrée complètement vide/absente", () => {
    expect(() => buildCveExportData(undefined)).not.toThrow();
    expect(() => buildCveExportData({})).not.toThrow();
  });
});
