import fr from "./fr.js";
import en from "./en.js";
import AREAS from "./messages/index.js";

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

/** Shell strings (`fr.js`/`en.js`) plus one module per area of the interface (`messages/`). */
export const MESSAGES = {
  fr: Object.assign({}, fr, ...AREAS.map((area) => area.fr)),
  en: Object.assign({}, en, ...AREAS.map((area) => area.en)),
};

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

let currentLang = DEFAULT_LANG;

/** Called by `I18nProvider` whenever the language changes (and once at start-up). */
export function setCurrentLang(lang) {
  currentLang = normalizeLang(lang);
}

export function getLang() {
  return currentLang;
}

export function currentLocale() {
  return LOCALES[currentLang];
}

/**
 * Translation in the current language, for code that is not a shell component: page content,
 * label tables, selectors, exports. Page content is remounted when the language changes (see
 * Dashboard.jsx), so values computed with `tr` never go stale there. Shell components that stay
 * mounted (sidebar, masthead) use `t` from `useI18n()` instead.
 */
export function tr(key, vars) {
  return translate(currentLang, key, vars);
}

/**
 * Object whose values are translated on read: `labels.compliant` returns `tr("<prefix>.compliant")`.
 * Lets label tables keep their `TABLE[value]` call sites.
 */
export function localizedTable(prefix, keys) {
  const table = {};
  for (const key of keys) {
    Object.defineProperty(table, key, { enumerable: true, get: () => tr(`${prefix}.${key}`) });
  }
  return Object.freeze(table);
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
