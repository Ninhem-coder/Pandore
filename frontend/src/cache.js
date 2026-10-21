/**
 * Cache mémoire partagé (2026-08-27, demande de Nicolas : "je trouve que les chargements sont
 * longs entre les pages... mettre un cache avec un TTL de 2h") — cadrage confirmé via
 * `AskUserQuestion` : cache seul, PAS de préchargement à froid de tous les onglets au
 * démarrage. Chaque onglet reste chargé à la demande au premier clic comme avant ; seul le
 * résultat est désormais réutilisé sur les visites suivantes.
 *
 * Cause racine du ralentissement identifiée avant d'écrire ce module : `Dashboard.jsx::TABS`
 * change le TYPE du composant rendu à chaque clic d'onglet (`const ActiveTab = TABS[activeTab]`
 * puis `<ActiveTab .../>`) — React démonte donc l'ancien composant et en remonte un nouveau à
 * CHAQUE navigation, y compris vers un onglet déjà visité. L'état local (`useState`) de chaque
 * hook de `useDashboardData.js` repart alors de zéro, relançant tous ses appels API depuis le
 * début. Un cache au niveau MODULE (ce fichier), hors du cycle de vie React, survit lui à ces
 * montages/démontages — une clé reste disponible jusqu'à expiration du TTL, quel que soit le
 * nombre de fois où le composant qui l'utilise est démonté/remonté.
 */
const DEFAULT_TTL_MS = 2 * 60 * 60 * 1000; // 2h

const entries = new Map(); // key -> { promise, timestamp }

/**
 * Renvoie la promesse déjà en cache pour `key` si elle a moins de `ttlMs`, sinon appelle
 * `fetchFn()` et met sa promesse en cache immédiatement (pas seulement le résultat une fois
 * résolu) — deux appels concurrents pour la MÊME clé (ex. deux composants montés en même temps)
 * partagent ainsi la même requête en vol plutôt que d'en déclencher deux identiques.
 *
 * Un échec réseau/HTTP (rejet de la promesse — voir getJSON/postJSON dans api.js, qui lèvent
 * sur un HTTP non-2xx) retire automatiquement l'entrée : la prochaine visite retente plutôt que
 * de ré-utiliser indéfiniment une promesse déjà rejetée jusqu'à expiration du TTL.
 *
 * Ce module ne connaît PAS la forme de chaque payload (une erreur "métier" `{error:true,...}`,
 * voir handle_tool_errors côté backend, arrive en HTTP 200 — la promesse se résout normalement,
 * ce module ne peut pas la distinguer d'un succès). À charge de l'appelant d'invoquer
 * `invalidateCache(key)` s'il détecte une erreur métier après coup, pour qu'une prochaine
 * visite retente au lieu de re-servir la même erreur pendant tout le TTL — voir les hooks de
 * useDashboardData.js, qui le font tous systématiquement.
 */
export function cachedCall(key, fetchFn, ttlMs = DEFAULT_TTL_MS) {
  const now = Date.now();
  const hit = entries.get(key);
  if (hit && now - hit.timestamp < ttlMs) {
    return hit.promise;
  }
  const promise = fetchFn();
  entries.set(key, { promise, timestamp: now });
  promise.catch(() => {
    if (entries.get(key)?.promise === promise) entries.delete(key);
  });
  return promise;
}

/** Retire une entrée du cache — à appeler quand l'appelant détecte lui-même une erreur
 * "métier" dans un payload par ailleurs résolu avec succès (voir `cachedCall` ci-dessus). */
export function invalidateCache(key) {
  entries.delete(key);
}

/**
 * Vide le cache en entier — appelée par `AuthGate.jsx` à la déconnexion ET avant une connexion
 * réussie (2026-09-07, revue de sécurité). Ce cache vit au niveau MODULE, hors du cycle de vie
 * React ET hors de l'état d'authentification : sans cet appel, un compte qui se connecte sur le
 * même onglet dans les 2h suivant la déconnexion d'un AUTRE compte (ex. admin puis viewer sur un
 * poste partagé) aurait continué de recevoir en mémoire des réponses mises en cache PAR le
 * premier compte, sans jamais repasser par le serveur — donc sans jamais revalider ses propres
 * droits sur cette donnée précise (le cas concret repéré : `useVanitasComplianceRules()` met en
 * cache le catalogue COMPLET admin-only, `script_content` inclus, sous une clé fixe).
 */
export function clearAllCache() {
  entries.clear();
}
