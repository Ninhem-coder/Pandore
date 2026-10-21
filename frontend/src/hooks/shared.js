import { useRef, useState } from "react";
import { cachedCall, invalidateCache } from "../cache.js";

/**
 * Internes PARTAGÉS des hooks de données (2026-09-12, découpage de l'ex-`useDashboardData.js`
 * monolithique en modules par domaine — `dashboardData.js`/`vulnerabilities.js`/`apps.js`/
 * `vanitas.js`, tous re-exportés par le barrel `useDashboardData.js` pour ne changer aucun
 * import consommateur). Les deux détecteurs d'erreur ET le cache générique `useKeyedFetch`
 * vivent ici : utilisés par les quatre modules de domaine à la fois.
 */

export function isErrorPayload(payload) {
  return payload && typeof payload === "object" && payload.error === true;
}

/**
 * Détecte le contrat d'erreur des endpoints annotés `list[dict]` côté backend :
 * `handle_tool_errors` y renvoie `[error]` (une liste à un seul élément d'erreur), jamais
 * un objet `{error: true}` nu — voir le commentaire de useSecureScore, qui documentait ce
 * contrat en premier. Extrait à la revue d'architecture du 2026-08-17 : la même fonction
 * `asError` était recopiée à l'identique dans useSecureScore, useOverviewSignals,
 * useDefenderAlerts, useExposureVulnerableApps et useDeviceVulnerableSoftware — cinq copies du
 * même filtre, avec le risque qu'une future correction n'en corrige qu'une partie.
 */
export function listPayloadError(payload) {
  return Array.isArray(payload) && payload.length === 1 && isErrorPayload(payload[0]) ? payload[0] : null;
}

/**
 * Cache générique par clé (level, machineId, alertId, ...) — extrait à la revue
 * d'architecture du 2026-08-17 de trois hooks quasi identiques (useAlertDetails,
 * useExposureVulnerableApps, useDeviceVulnerableSoftware) qui réimplémentaient chacun le
 * même besoin : charger à la demande au premier accès à une clé, mémoriser le résultat en
 * cache, ne jamais relancer un fetch déjà en cours ou terminé pour cette clé.
 *
 * `startedRef` (Set, plutôt qu'un simple test sur `state[key]` dans un setState updater)
 * évite de relancer un fetch si `ensureLoaded` est appelé deux fois de suite avant le premier
 * re-render (ex. double clic) — repris de l'useAlertDetails d'origine, dont c'était déjà le
 * comportement ; useExposureVulnerableApps/useDeviceVulnerableSoftware n'avaient qu'une garde
 * plus faible (`state[key]` dans l'updater), donc l'unification durcit aussi ces deux-là au
 * lieu de se contenter du plus petit dénominateur commun.
 *
 * @param fetchFn (key) => Promise<payload brut de l'API>
 * @param toError (payload) => objet d'erreur `{message}` ou `null` — le contrat de
 *   détection d'erreur diffère selon l'endpoint (payload nu `{error:true,...}` pour
 *   /api/defender/alerts/{id}, liste à un seul élément d'erreur pour les endpoints annotés
 *   `list[dict]` côté backend — voir `listPayloadError`), donc pas figé dans le hook.
 * @param emptyValue valeur de `data` tant que rien n'est chargé ou en cas d'erreur — `[]`
 *   pour les deux hooks "logiciels vulnérables" (consommé via `.length`/`.map`), `null` pour
 *   useAlertDetails (un détail d'alerte est un objet, pas une liste).
 * @param cacheNamespace (2026-08-27, demande de Nicolas : "les chargements sont longs entre
 *   les pages... un cache avec un TTL de 2h") — préfixe distinguant les clés de CE hook dans
 *   le cache partagé (cache.js) de celles des autres consommateurs de useKeyedFetch (ex. un
 *   `machineId` et un `appId` qui coïncideraient par hasard ne doivent jamais se répondre l'un
 *   l'autre). `startedRef` garde son rôle initial — éviter un double `fetchFn(key)` avant le
 *   premier re-render — mais ne suffit plus À LUI SEUL à couvrir les visites répétées : lui est
 *   local au montage du composant (redémarre à zéro à chaque remontage d'onglet), alors que
 *   `cachedCall` survit, LUI, aux montages/démontages.
 */
export function useKeyedFetch(fetchFn, toError, emptyValue = null, cacheNamespace = "keyedFetch") {
  const [state, setState] = useState({});
  const startedRef = useRef(new Set());

  function ensureLoaded(key) {
    if (!key || startedRef.current.has(key)) return;
    startedRef.current.add(key);
    setState((prev) => ({ ...prev, [key]: { loading: true, data: emptyValue, error: null } }));

    const cacheKey = `${cacheNamespace}:${key}`;
    cachedCall(cacheKey, () => fetchFn(key)).then(
      (payload) => {
        const err = toError(payload);
        if (err) invalidateCache(cacheKey);
        setState((prev) => ({
          ...prev,
          [key]: { loading: false, data: err ? emptyValue : payload, error: err?.message ?? null },
        }));
      },
      (err) => {
        setState((prev) => ({ ...prev, [key]: { loading: false, data: emptyValue, error: err.message } }));
      }
    );
  }

  return { state, ensureLoaded };
}
