import { describe, it, expect } from "vitest";
import { resolveSearchTab, bumpSearchNav, bumpVanitasNav } from "./navigation.js";

/**
 * Tests de ../navigation.js — logique d'aiguillage extraite de Dashboard.jsx à la revue de
 * code du 2026-08-20 pour être testable sans jsdom/React Testing Library (voir le
 * commentaire de navigation.js).
 */

describe("resolveSearchTab", () => {
  it("route une CVE (insensible à la casse) vers Vulnérabilités", () => {
    expect(resolveSearchTab("CVE-2024-3400")).toBe("vulnerabilities");
    expect(resolveSearchTab("cve-2021-44228")).toBe("vulnerabilities");
  });

  it("route tout le reste (nom d'appareil) vers Appareil (vue 360°)", () => {
    expect(resolveSearchTab("lse-wks-mvi-2")).toBe("device-overview");
    expect(resolveSearchTab("guillaume_noinville_iPhone18,3")).toBe("device-overview");
    expect(resolveSearchTab("")).toBe("device-overview");
  });
});

describe("bumpSearchNav", () => {
  it("démarre le token à 1 quand il n'y a pas de recherche précédente (searchNav initial null)", () => {
    expect(bumpSearchNav(null, "device-overview", "lse-wks-mvi-2")).toEqual({
      tab: "device-overview",
      query: "lse-wks-mvi-2",
      token: 1,
    });
  });

  it("incrémente le token à CHAQUE appel, même avec la même query/tab (reclic sur le même device)", () => {
    const first = bumpSearchNav(null, "vulnerabilities", "CVE-2024-3400");
    const second = bumpSearchNav(first, "vulnerabilities", "CVE-2024-3400");
    expect(first.token).toBe(1);
    expect(second.token).toBe(2);
    expect(second.tab).toBe("vulnerabilities");
    expect(second.query).toBe("CVE-2024-3400");
  });

  it("repart de 1 si le searchNav précédent n'a pas de token (forme inattendue)", () => {
    expect(bumpSearchNav({}, "device-overview", "x")).toEqual({ tab: "device-overview", query: "x", token: 1 });
  });
});

describe("bumpVanitasNav", () => {
  it("démarre le token à 1 quand il n'y a pas de navigation Vanitas précédente", () => {
    expect(bumpVanitasNav(null, "vanitas-devices", { selectAgentId: "abc" })).toEqual({
      tab: "vanitas-devices",
      payload: { selectAgentId: "abc" },
      token: 1,
    });
  });

  it("incrémente le token à CHAQUE appel, même vers la même cible avec le même payload (reclic sur le même poste)", () => {
    const first = bumpVanitasNav(null, "vanitas-vulnerabilities", { cveId: "CVE-2024-3400" });
    const second = bumpVanitasNav(first, "vanitas-vulnerabilities", { cveId: "CVE-2024-3400" });
    expect(first.token).toBe(1);
    expect(second.token).toBe(2);
    expect(second.tab).toBe("vanitas-vulnerabilities");
    expect(second.payload).toEqual({ cveId: "CVE-2024-3400" });
  });

  it("repart de 1 si la navigation précédente n'a pas de token (forme inattendue)", () => {
    expect(bumpVanitasNav({}, "vanitas-eol", { query: "LAPTOP-KVC1F4CM" })).toEqual({
      tab: "vanitas-eol",
      payload: { query: "LAPTOP-KVC1F4CM" },
      token: 1,
    });
  });
});
