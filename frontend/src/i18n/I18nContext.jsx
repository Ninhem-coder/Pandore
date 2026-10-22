import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { LOCALES, STORAGE_KEY, normalizeLang, translate } from "./core.js";

const I18nContext = createContext(null);

function readStoredLang() {
  try {
    return normalizeLang(localStorage.getItem(STORAGE_KEY));
  } catch {
    return normalizeLang(null);
  }
}

/**
 * Interface language for the whole app. The choice is kept per browser (localStorage) and
 * mirrored on `<html lang>` so screen readers and the browser's hyphenation follow it.
 */
export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(readStoredLang);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  const setLang = useCallback((next) => {
    const code = normalizeLang(next);
    setLangState(code);
    try {
      localStorage.setItem(STORAGE_KEY, code);
    } catch {
      // localStorage unavailable: the choice lasts for this session only.
    }
  }, []);

  const value = useMemo(
    () => ({ lang, locale: LOCALES[lang], setLang, t: (key, vars) => translate(lang, key, vars) }),
    [lang, setLang]
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

/** `{ lang, locale, setLang, t }` — `t(key, vars)` returns the string for the current language. */
export function useI18n() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useI18n must be used inside <I18nProvider>");
  return ctx;
}
