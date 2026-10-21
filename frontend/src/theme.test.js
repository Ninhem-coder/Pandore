import { describe, it, expect } from "vitest";
import {
  levelForScore,
  pluralCategory,
  friendlyErrorMessage,
  formatRelativeDays,
  secureScoreLevel,
  policyStatusLabel,
  policyStatusSeverity,
  translateThreat,
} from "./theme.js";

/**
 * Tests unitaires des design tokens purs de theme.js — revue de code frontend, 💡 suggestion
 * #11 ("le module le plus critique du dashboard n'a aucun test"). Les dérivations métier
 * (computeTopRiskDevices, groupComplianceDetailByOS, buildDonutEntries, ...) ont été
 * déplacées dans selectors.js à la revue d'architecture du 2026-08-17 — voir
 * selectors.test.js pour leurs tests, dont plusieurs couvrent des bugs déjà observés en
 * prod dans cette session.
 */

describe("levelForScore", () => {
  it("classe correctement les trois paliers Microsoft", () => {
    expect(levelForScore(0).level).toBe("low");
    expect(levelForScore(29).level).toBe("low");
    expect(levelForScore(30).level).toBe("medium");
    expect(levelForScore(69).level).toBe("medium");
    expect(levelForScore(70).level).toBe("high");
    expect(levelForScore(100).level).toBe("high");
  });

  it("clampe les valeurs hors bornes plutôt que de planter", () => {
    expect(levelForScore(-5).level).toBe("low");
    expect(levelForScore(150).level).toBe("high");
  });
});

describe("pluralCategory", () => {
  it("laisse au singulier quand n <= 1", () => {
    expect(pluralCategory("Non conforme", 1)).toBe("non conforme");
    expect(pluralCategory("Non conforme", 0)).toBe("non conforme");
  });

  it("gère le pluriel irrégulier de 'erreur'", () => {
    expect(pluralCategory("Erreur", 3)).toBe("erreurs");
  });

  it("garde 'en attente' invariable au pluriel", () => {
    expect(pluralCategory("En attente", 5)).toBe("en attente");
  });

  it("ajoute un 's' par défaut", () => {
    expect(pluralCategory("Non conforme", 2)).toBe("non conformes");
  });
});

describe("friendlyErrorMessage", () => {
  it("reformule 'Failed to fetch' en français", () => {
    const { text, raw } = friendlyErrorMessage("Failed to fetch");
    expect(text).toBe("Le serveur local ne répond pas.");
    expect(raw).toBe("Failed to fetch");
  });

  it("laisse passer un message déjà compréhensible tel quel", () => {
    const { text, raw } = friendlyErrorMessage("Le tenant Azure est introuvable");
    expect(text).toBe(raw);
  });

  it("gère une entrée non-string sans planter", () => {
    expect(friendlyErrorMessage(undefined).text).toBe("Erreur inconnue");
  });
});

describe("formatRelativeDays", () => {
  const now = new Date("2026-08-10T15:00:00Z");

  it("retourne 'aujourd'hui' pour le jour même", () => {
    expect(formatRelativeDays("2026-08-10T02:00:00Z", now)).toBe("aujourd'hui");
  });

  it("gère le singulier/pluriel", () => {
    expect(formatRelativeDays("2026-08-09T02:00:00Z", now)).toBe("il y a 1j");
    expect(formatRelativeDays("2026-08-04T02:00:00Z", now)).toBe("il y a 6j");
  });

  it("retourne un texte de repli sur une date invalide", () => {
    expect(formatRelativeDays("pas-une-date", now)).toBe("date inconnue");
  });
});

describe("secureScoreLevel", () => {
  it("a une sémantique de couleur INVERSÉE par rapport à levelForScore (haut = bon)", () => {
    expect(secureScoreLevel(0).level).toBe("high");
    expect(secureScoreLevel(49).level).toBe("high");
    expect(secureScoreLevel(50).level).toBe("medium");
    expect(secureScoreLevel(74).level).toBe("medium");
    expect(secureScoreLevel(75).level).toBe("low");
    expect(secureScoreLevel(100).level).toBe("low");
  });

  it("clampe les valeurs hors bornes plutôt que de planter", () => {
    expect(secureScoreLevel(-10).level).toBe("high");
    expect(secureScoreLevel(999).level).toBe("low");
  });

  it("traite une valeur absente comme 0 (donc 'high', pire cas)", () => {
    expect(secureScoreLevel(undefined).level).toBe("high");
    expect(secureScoreLevel(null).level).toBe("high");
  });
});

describe("policyStatusLabel", () => {
  it("traduit les états bruts Graph par politique connus", () => {
    expect(policyStatusLabel("nonCompliant")).toBe("Non conforme");
    expect(policyStatusLabel("compliant")).toBe("Conforme");
    expect(policyStatusLabel("conflict")).toBe("Erreur");
    expect(policyStatusLabel("notAssigned")).toBe("Inconnu");
  });

  it("renvoie un tiret pour un état absent (jamais 'undefined' affiché)", () => {
    expect(policyStatusLabel(null)).toBe("—");
    expect(policyStatusLabel("")).toBe("—");
  });

  it("laisse passer une valeur inconnue telle quelle plutôt que d'inventer une traduction", () => {
    expect(policyStatusLabel("unePlateformeInconnue")).toBe("unePlateformeInconnue");
  });
});

describe("policyStatusSeverity", () => {
  it("fait remonter les échecs (nonCompliant) avant les états neutres", () => {
    expect(policyStatusSeverity("nonCompliant")).toBeLessThan(policyStatusSeverity("compliant"));
    expect(policyStatusSeverity("error")).toBeLessThan(policyStatusSeverity("notApplicable"));
  });

  it("ignore la casse et les espaces superflus", () => {
    expect(policyStatusSeverity("  nonCompliant  ")).toBe(policyStatusSeverity("nonCompliant"));
  });

  it("retombe sur la pire gravité (6) pour un état non reconnu, y compris vide/absent", () => {
    expect(policyStatusSeverity("quelqueChoseDeNouveau")).toBe(6);
    expect(policyStatusSeverity(null)).toBe(6);
    expect(policyStatusSeverity(undefined)).toBe(6);
  });
});

describe("translateThreat", () => {
  it("traduit les menaces documentées de secureScoreControlProfiles", () => {
    expect(translateThreat("ransomware")).toBe("Rançongiciel");
    expect(translateThreat("elevationOfPrivilege")).toBe("Élévation de privilèges");
  });

  it("génère un TitleCase générique pour une valeur camelCase non traduite", () => {
    // Pas de traduction FR vérifiée pour cette valeur -> humanizeThreat plutôt qu'une
    // traduction inventée (voir commentaire de translateThreat dans theme.js).
    expect(translateThreat("someFutureThreatType")).toBe("Some Future Threat Type");
  });

  it("gère une valeur absente sans planter", () => {
    expect(translateThreat(undefined)).toBe(undefined);
    expect(translateThreat("")).toBe("");
  });
});
