import { describe, it, expect } from "vitest";
import { computeSettingsState, ReconciliationNote } from "./ComplianceOsGrid.jsx";

/**
 * Même principe que RiskDevicesList.test.js/NewDevicesList.test.js (voir leur commentaire) :
 * ni computeSettingsState ni ReconciliationNote n'utilisent de hook, donc les appeler
 * directement comme des fonctions suffit à vérifier leur logique, sans jsdom/RTL. Ajoutés à
 * la revue de code du 2026-08-20 : ces deux fonctions décident silencieusement ce qui est
 * affiché/masqué à l'utilisateur (un device recalculé "conforme" disparaît de la liste, une
 * note de réconciliation apparaît ou non) — les moins chères à tester de tout le fichier,
 * jusqu'ici les seules non couvertes.
 */

describe("computeSettingsState", () => {
  it("renvoie null si l'entrée est absente", () => {
    expect(computeSettingsState(undefined)).toBeNull();
    expect(computeSettingsState(null)).toBeNull();
  });

  it("renvoie null pendant le chargement ou en cas d'erreur réseau", () => {
    expect(computeSettingsState({ loading: true })).toBeNull();
    expect(computeSettingsState({ error: "boom" })).toBeNull();
  });

  it("renvoie null si aucun réglage n'a été remonté par Graph", () => {
    expect(computeSettingsState({ settings: [] })).toBeNull();
    expect(computeSettingsState({})).toBeNull();
  });

  it("renvoie 'compliant' seulement si TOUS les réglages sont compliant", () => {
    expect(computeSettingsState({ settings: [{ state: "compliant" }, { state: "compliant" }] })).toBe("compliant");
  });

  it("renvoie 'nonCompliant' si au moins un réglage est en échec (sans erreur)", () => {
    expect(computeSettingsState({ settings: [{ state: "compliant" }, { state: "nonCompliant" }] })).toBe(
      "nonCompliant"
    );
  });

  it("renvoie 'error' si au moins un réglage est en erreur ou en conflit, même prioritaire sur nonCompliant", () => {
    expect(
      computeSettingsState({ settings: [{ state: "nonCompliant" }, { state: "error" }] })
    ).toBe("error");
    expect(computeSettingsState({ settings: [{ state: "compliant" }, { state: "conflict" }] })).toBe("error");
  });

  it("est insensible à la casse de l'état", () => {
    expect(computeSettingsState({ settings: [{ state: "Compliant" }] })).toBe("compliant");
    expect(computeSettingsState({ settings: [{ state: "ERROR" }] })).toBe("error");
  });
});

describe("ReconciliationNote", () => {
  const compliantSettings = [{ state: "compliant" }, { state: "compliant" }];

  it("affiche la note quand tous les réglages sont compliant mais l'agrégat par politique dit encore autre chose", () => {
    const el = ReconciliationNote({ policyStatus: "nonCompliant", settings: compliantSettings });
    expect(el).not.toBeNull();
    expect(el.type).toBe("p");
    expect(el.props.className).toBe("footnote");
  });

  it("ne s'affiche pas si l'agrégat par politique est déjà 'compliant' (rien à réconcilier)", () => {
    expect(ReconciliationNote({ policyStatus: "compliant", settings: compliantSettings })).toBeNull();
  });

  it("ne s'affiche pas si au moins un réglage n'est pas compliant", () => {
    const settings = [{ state: "compliant" }, { state: "nonCompliant" }];
    expect(ReconciliationNote({ policyStatus: "nonCompliant", settings })).toBeNull();
  });

  it("ne s'affiche pas si la liste de réglages est vide", () => {
    expect(ReconciliationNote({ policyStatus: "nonCompliant", settings: [] })).toBeNull();
  });

  it("ne s'affiche pas si policyStatus est absent", () => {
    expect(ReconciliationNote({ policyStatus: null, settings: compliantSettings })).toBeNull();
  });
});
