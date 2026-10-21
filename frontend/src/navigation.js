import { isCveLike } from "./components/GlobalSearch.jsx";

/**
 * Aiguillage de la recherche globale (2026-08-20) — extrait de Dashboard.jsx (revue de code
 * du 2026-08-20) pour rendre cette logique testable sans dépendre de jsdom/React Testing
 * Library : `handleGlobalSearch`/`handleNavigate` restent dans Dashboard.jsx (elles pilotent
 * du state React), mais l'aiguillage lui-même — pur, sans effet de bord — vit ici. Voir
 * navigation.test.js.
 */

/**
 * Une CVE (CVE-AAAA-N...) va vers "Vulnérabilités" (recherche déjà existante par CVE/
 * logiciel) ; tout le reste est traité comme un nom d'appareil et va vers "Appareil" (vue
 * 360°, recherche déjà existante par nom) — voir GlobalSearch.jsx::isCveLike pour la
 * détection. Pas de troisième recherche réimplémentée ici, uniquement un aiguillage vers les
 * deux qui existent déjà.
 */
export function resolveSearchTab(query) {
  return isCveLike(query) ? "vulnerabilities" : "device-overview";
}

/**
 * Construit le prochain `searchNav` (Dashboard.jsx) à partir du précédent. `token` incrémente
 * à CHAQUE appel, y compris si `tab`/`query` sont identiques à l'appel précédent (ex. reclic
 * sur le même device depuis un autre onglet, ou deux recherches de suite sur la même CVE) —
 * sans lui, l'effet de l'onglet cible (VulnerabilitiesTab.jsx/DeviceOverviewTab.jsx, gardé
 * sur `initialQuery?.token`) ne redéclencherait rien la deuxième fois puisque la dépendance
 * n'aurait pas changé.
 */
export function bumpSearchNav(prevNav, tab, query) {
  return { tab, query, token: (prevNav?.token ?? 0) + 1 };
}

/**
 * Équivalent de `bumpSearchNav` pour l'arbre Vanitas (2026-09-11, "revoir la Vue d'ensemble...
 * je veux qu'elle devienne bien interactive") — jusqu'ici `onNavigateVanitas` ne pouvait que
 * changer d'onglet (`setVanitasTab`, un simple setter de chaîne), aucune tuile/ligne de la Vue
 * d'ensemble ne pouvait renvoyer vers un poste précis, une CVE précise ou un filtre déjà
 * appliqué. `payload` est une forme libre (interprétée par la page cible : `{selectAgentId}`/
 * `{filter}` pour "Postes", `{cveId}` pour "Vulnérabilités", `{query}` pour "Logiciels
 * obsolètes") — même principe de `token` que `bumpSearchNav` : incrémente à CHAQUE appel, même
 * vers la même cible avec le même payload, pour que l'effet de la page cible se redéclenche à
 * chaque clic (ex. re-cliquer sur le même poste depuis un autre endroit).
 */
export function bumpVanitasNav(prevNav, tab, payload) {
  return { tab, payload, token: (prevNav?.token ?? 0) + 1 };
}
