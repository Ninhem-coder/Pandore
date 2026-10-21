import { describe, it, expect } from "vitest";
import { isCveLike } from "./GlobalSearch.jsx";

/**
 * Tests de GlobalSearch.jsx::isCveLike (revue de code du 2026-08-20) — fonction pure, sans
 * dépendance au DOM/React, testable directement comme n'importe quelle fonction de
 * selectors.js/theme.js.
 */
describe("isCveLike", () => {
  it("reconnaît un identifiant CVE, insensible à la casse et aux espaces autour", () => {
    expect(isCveLike("CVE-2024-3400")).toBe(true);
    expect(isCveLike("cve-2024-3400")).toBe(true);
    expect(isCveLike("  CVE-2021-44228  ")).toBe(true);
  });

  it("rejette un nom d'appareil ou une entrée vide/absente", () => {
    expect(isCveLike("lse-wks-mvi-2")).toBe(false);
    expect(isCveLike("guillaume_noinville_iPhone18,3")).toBe(false);
    expect(isCveLike("")).toBe(false);
    expect(isCveLike(undefined)).toBe(false);
    expect(isCveLike(null)).toBe(false);
  });

  it("rejette un identifiant CVE mal formé (année/numéro incomplets)", () => {
    expect(isCveLike("CVE-24-3400")).toBe(false);
    expect(isCveLike("CVE-2024-")).toBe(false);
  });
});
