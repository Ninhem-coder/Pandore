import fr from "./fr.js";
import en from "./en.js";

/**
 * Interface translation — pure functions, no React (tested in `i18n.test.js`).
 *
 * Messages are flat `{ key: template }` dictionaries, one per language. A template may hold
 * `{name}` placeholders. A key with a numeric `count` variable can have plural forms
 * `<key>.one` / `<key>.other`, chosen with `Intl.PluralRules` for the language. A key missing
 * in a language falls back to French, then to the key itself, so a forgotten translation
 * never breaks a page.
 */

export const DEFAULT_LANG = "fr";
export const STORAGE_KEY = "pandore.lang";

export const LANGUAGES = [
  { code: "fr", label: "Français" },
  { code: "en", label: "English" },
];

export const LOCALES = { fr: "fr-FR", en: "en-US" };

export const MESSAGES = { fr, en };

export function normalizeLang(value) {
  return Object.hasOwn(MESSAGES, value) ? value : DEFAULT_LANG;
}

function lookup(lang, key) {
  return MESSAGES[lang][key] ?? MESSAGES[DEFAULT_LANG][key];
}

export function translate(lang, key, vars) {
  const code = normalizeLang(lang);
  let template;
  if (vars && typeof vars.count === "number") {
    const form = new Intl.PluralRules(LOCALES[code]).select(vars.count);
    template = lookup(code, `${key}.${form}`) ?? lookup(code, `${key}.other`);
  }
  template ??= lookup(code, key) ?? key;
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (match, name) => (name in vars ? String(vars[name]) : match));
}

/** "généré le 22/10/2026 à 09:14" / "generated on 10/22/2026 at 09:14 AM". */
export function formatStamp(lang, date) {
  const code = normalizeLang(lang);
  const locale = LOCALES[code];
  return translate(code, "masthead.stamp", {
    date: date.toLocaleDateString(locale, { day: "2-digit", month: "2-digit", year: "numeric" }),
    time: date.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" }),
  });
}
