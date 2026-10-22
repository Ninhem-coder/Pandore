import { describe, expect, it } from "vitest";
import { DEFAULT_LANG, LANGUAGES, MESSAGES, formatStamp, normalizeLang, translate } from "./core.js";

describe("dictionaries", () => {
  it("every language has exactly the keys of the reference language", () => {
    const reference = Object.keys(MESSAGES[DEFAULT_LANG]).sort();
    for (const { code } of LANGUAGES) {
      expect(Object.keys(MESSAGES[code]).sort(), code).toEqual(reference);
    }
  });

  it("translations keep the same placeholders", () => {
    const placeholders = (s) => (s.match(/\{\w+\}/g) || []).sort();
    for (const [key, template] of Object.entries(MESSAGES[DEFAULT_LANG])) {
      for (const { code } of LANGUAGES) {
        expect(placeholders(MESSAGES[code][key]), `${code} ${key}`).toEqual(placeholders(template));
      }
    }
  });
});

describe("translate", () => {
  it("returns the string of the requested language", () => {
    expect(translate("fr", "nav.settings")).toBe("Paramètres");
    expect(translate("en", "nav.settings")).toBe("Settings");
  });

  it("falls back to French for an unknown language and to the key for an unknown key", () => {
    expect(normalizeLang("de")).toBe("fr");
    expect(translate("de", "nav.settings")).toBe("Paramètres");
    expect(translate("en", "does.not.exist")).toBe("does.not.exist");
  });

  it("fills placeholders and leaves unknown ones untouched", () => {
    expect(translate("en", "nav.navigation", { world: "Vanitas" })).toBe("Vanitas navigation");
    expect(translate("en", "nav.navigation", {})).toBe("{world} navigation");
  });

  it("picks the plural form for the language", () => {
    expect(translate("en", "vanitas.status.online", { count: 1 })).toBe("Vanitas server · 1 endpoint online");
    expect(translate("en", "vanitas.status.online", { count: 0 })).toBe("Vanitas server · 0 endpoints online");
    expect(translate("fr", "vanitas.status.online", { count: 3 })).toBe("Serveur Vanitas · 3 postes en ligne");
  });
});

describe("formatStamp", () => {
  const date = new Date(2026, 9, 22, 9, 14);

  it("formats the date in the language's conventions", () => {
    expect(formatStamp("fr", date)).toBe("généré le 22/10/2026 à 09:14");
    expect(formatStamp("en", date)).toBe("generated on 10/22/2026 at 09:14 AM");
  });
});
