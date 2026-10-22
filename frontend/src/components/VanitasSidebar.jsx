import { useEffect } from "react";
import { useI18n } from "../i18n/I18nContext.jsx";
import { useVanitasAgents } from "../hooks/useDashboardData.js";
import { hasAnyVanitasAccess, hasVanitasAccess, isOnline } from "../pages/vanitasShared.jsx";
import {
  IconGrid,
  IconLaptop,
  IconShield,
  IconTerminal,
  IconAlertTriangle,
  IconPackage,
  IconLayers,
  IconUpload,
  IconSend,
  IconLibrary,
  IconKey,
  IconDownload,
  IconBook,
  IconRadar,
  IconRefresh,
} from "./icons.jsx";

/**
 * Navigation de la catégorie "Vanitas" (2026-09-04, jalon 5) — projet personnel séparé
 * `endpoint-agent/` (agent .NET en mTLS), intégré dans ce dashboard via `backend/vanitas/`.
 * Nommé "Vanitas" pour ne pas se confondre avec "Pandore", le nom/la marque de CE dashboard
 * lui-même (logo `LogoMark` dans Sidebar.jsx).
 *
 * Liste plate à 3 entrées à l'origine ; "Postes"/"Commandes" regroupées le 2026-09-06 sous
 * "Inventaire"/"Administration" (demande de Nicolas) — même mécanisme `{ group, items }` que
 * `NAV_TREE` de Sidebar.jsx.
 *
 * "Sécurité" (jalon 11, conformité) — nouveau groupe, aucun équivalent avant ce jalon.
 * "Conformité" (vue fleet-wide HUD) y vit seule — "Règles de conformité" (ex-catalogue de
 * scripts, page d'administration séparée sous "Administration") a été RETIRÉE le 2026-09-09
 * ("on gère tout depuis Conformité") : créer/activer/modifier/supprimer une règle se fait
 * désormais directement depuis "Conformité" (bouton "+ Créer une règle" + popup de détail par
 * règle, voir VanitasComplianceTab.jsx).
 *
 * Refonte du 2026-09-09 (maquette interactive approuvée par Nicolas — "garder un peu le
 * thème cyberpunk mais en restant très pro") : ce rail plat rejoint le MÊME squelette de
 * navigation repliable que Sidebar.jsx (classes `.rail-*` partagées, voir styles.css) —
 * Pandore et Vanitas sont désormais UN SEUL système de navigation à deux habillages, pas deux
 * mécanismes divergents. L'habillage `.vanitas-rail` reste, lui, entièrement propre à cette
 * catégorie (jetons HUD --hud-*, jamais mélangés aux tokens --amber/--star du reste du
 * dashboard). Toujours PAS d'accordéon (aucun item de `VANITAS_NAV` n'a de `children` — 3
 * groupes plats suffisent pour ces pages), contrairement à `NAV_TREE` de Sidebar.jsx.
 *
 * Refonte du 2026-10-21 (maquette `Design/maquettes/refonte-ui.html`) : ce fichier ne porte plus
 * de composant de rail — le rendu est fait par la sidebar unifiée de Sidebar.jsx (rail des
 * mondes + colonne). Il reste la source de vérité de l'arbre Vanitas (`VANITAS_NAV`), du filtre
 * de permissions, de `VanitasMark` et du pied de colonne (`VanitasNavFooter`).
 *
 * `requires` (2026-09-10, profils Vanitas) — remplace l'ancien `adminOnly` par un critère plus
 * fin, vérifié via `hasVanitasAccess`/`hasAnyVanitasAccess` (vanitasShared.jsx, même fonction
 * que côté serveur `auth/vanitas_profiles.py::has_access`) :
 * - `{ module, level }` : exige cette permission (un admin l'a toujours) — les pages qui
 *   correspondent à UN module précis (Postes/Terminal/Applications/Conformité/Groupes).
 * - `{ any: true }` : exige seulement qu'UN profil quelconque soit assigné — les pages
 *   d'observation fleet-wide qui recoupent tous les modules (Vue d'ensemble, Catalogue
 *   d'application, Vulnérabilités, Journal), cohérent avec `require_vanitas_any` côté serveur.
 * - `{ adminOnly: true }` : reste réservé aux actions d'administration PANDORE qui ne sont pas
 *   une capacité Vanitas parmi d'autres (gérer les profils/comptes eux-mêmes — "Profils").
 * Un compte viewer SANS profil assigné (`hasAnyVanitasAccess` faux) ne voit donc plus AUCUN
 * item Vanitas hormis "Vue d'ensemble" elle-même — cohérent avec "aucun accès à rien" par
 * défaut (demande de Nicolas).
 */
// Labels are not stored here: `nav.item.<key>` and `nav.group.<group>` in i18n/{fr,en}.js.
export const VANITAS_NAV = [
  { key: "vanitas-overview", icon: <IconGrid /> },
  // "Catalogue d'application" (2026-09-09) — item nu de lecture seule, voir
  // `VanitasAppCatalogTab.jsx`. "Applications" (l'ajout/la modification du catalogue)
  // redescend sous "Administration", voir plus bas.
  { key: "vanitas-app-catalog", icon: <IconLibrary />, requires: { any: true } },
  {
    group: "security",
    items: [
      // "Activités suspectes" (jalon "détection d'activités suspectes sur les postes",
      // 2026-09-14) — nichée ici (demande de Nicolas le 2026-09-14, remplace le placement
      // top-level initial du plan validé). Gardé en LECTURE seule ici (les 3 actions de triage
      // restent gatées en écriture À L'INTÉRIEUR de la page elle-même, voir
      // `hasVanitasAccess(user, "activites_suspectes", "write")` dans VanitasSuspiciousActivityTab.jsx).
      {
        key: "vanitas-suspicious-activity",
        icon: <IconRadar />,
        requires: { module: "activites_suspectes", level: "read" },
      },
      { key: "vanitas-compliance", icon: <IconShield />, requires: { module: "conformite", level: "read" } },
      // "Vulnérabilités" (2026-09-09) — agrégat fleet-wide, aucun module précis, voir
      // VanitasVulnerabilitiesTab.jsx.
      { key: "vanitas-vulnerabilities", icon: <IconAlertTriangle />, requires: { any: true } },
      // "Logiciels obsolètes (EOL)" (2026-09-08) — vue PAR POSTE (voir vanitas_eol.py), même
      // permission que "Postes" côté serveur (require_vanitas_read("postes")).
      { key: "vanitas-eol", icon: <IconPackage />, requires: { module: "postes", level: "read" } },
    ],
  },
  {
    group: "inventory",
    items: [
      { key: "vanitas-devices", icon: <IconLaptop />, requires: { module: "postes", level: "read" } },
      // "Groupes" (2026-09-08) — ranger les postes dans des groupes nommés, voir
      // VanitasGroupsTab.jsx/VanitasGroupDetail.jsx.
      { key: "vanitas-groups", icon: <IconLayers />, requires: { module: "groupes", level: "read" } },
      // "Applications déployées" (2026-09-10, "avoir une page pour voir les applications
      // qu'on a déployées") — LECTURE seule d'un agrégat de commandes `install_application`
      // déjà envoyées, même permission que le catalogue ("applications") puisque c'est la
      // même donnée (postes/versions déployés) vue sous un autre angle.
      {
        key: "vanitas-deployed-apps",
        icon: <IconSend />,
        requires: { module: "applications", level: "read" },
      },
      // "Mises à jour Vanitas" (2026-09-17, maquette validée par Nicolas) — déploiement réel
      // des correctifs de sécurité Windows (politique par groupe, fenêtre de maintenance,
      // délai de grâce), voir VanitasPatchTab.jsx. Permission "postes" comme "Postes"
      // ci-dessus : consulter/forcer un redémarrage porte sur des machines, pas une propriété
      // de groupe — la politique elle-même (par groupe) reste gérée en "groupes" écriture, la
      // même distinction déjà en place pour "Pousser une application".
      {
        key: "vanitas-patch",
        icon: <IconRefresh />,
        requires: { module: "postes", level: "read" },
      },
    ],
  },
  {
    group: "administration",
    items: [
      // "Journal" (2026-09-09, ex-"Commandes") — journal d'activité unifié, agrégat fleet-wide.
      { key: "vanitas-commands", icon: <IconTerminal />, requires: { any: true } },
      // "Ajouter un poste" (2026-09-11, "que se soit plus simple à mettre en place via une
      // page sur Vanitas directement") — génère un token d'enrôlement + la commande d'install,
      // voir VanitasEnrollTab.jsx. Même permission que retirer un poste (`vanitas-devices`
      // écriture) : générer un token permet d'enrôler n'importe quel agent SYSTEM.
      { key: "vanitas-enroll", icon: <IconDownload />, requires: { module: "postes", level: "write" } },
      // "Applications" (2026-09-08, redescendu ici le 2026-09-09) — ajout ET modification du
      // catalogue d'installeurs (voir VanitasInstallersTab.jsx). Ancien `adminOnly` remplacé
      // par la permission "applications" (2026-09-10, profils Vanitas).
      { key: "vanitas-installers", icon: <IconUpload />, requires: { module: "applications", level: "read" } },
      // "Profils" (2026-09-10, nouveau) — gestion des profils Vanitas ET des comptes eux-mêmes
      // (déplacée depuis Paramètres). Reste `adminOnly` STRICT (pas `requires: {module}`) :
      // c'est une action d'administration Pandore, jamais une capacité Vanitas assignable via
      // un profil — sinon un profil "tout en écriture" pourrait s'auto-assigner l'admin.
      { key: "vanitas-profiles", icon: <IconKey />, requires: { adminOnly: true } },
    ],
  },
  // "Documentation" (2026-09-10, demande de Nicolas) — item nu, accessible à tout compte
  // ayant un accès Vanitas quelconque (même critère que "Vue d'ensemble"/"Catalogue
  // d'application" : ce n'est pas une capacité par module, c'est une page de référence).
  // Rangé sous un groupe "Aide" depuis la refonte de la sidebar du 2026-10-21 (maquette
  // `Design/maquettes/refonte-ui.html`), à la place de l'ancien épinglage en bas de rail.
  { group: "help", items: [{ key: "vanitas-docs", icon: <IconBook />, requires: { any: true } }] },
];

export function isVanitasNavItemVisible(item, user) {
  const req = item.requires;
  if (!req) return true;
  if (req.adminOnly) return user.role === "admin";
  if (req.any) return hasAnyVanitasAccess(user);
  return hasVanitasAccess(user, req.module, req.level ?? "read");
}

/** Réticule de visée / balayage radar — repris de `Design/vanitas-icon.svg` (charte graphique
 * §9 : "le réticule de visée... associé aux vues de surveillance continue et de détection"),
 * simplifié pour rester lisible à 15-20px. `currentColor` : la teinte cyan vient du contexte
 * (`.app-sidebar[data-world="vanitas"]`), pas d'un dégradé embarqué — contrairement au
 * `LogoMark` de Pandore. Sert d'icône du monde Vanitas dans le rail (Sidebar.jsx). */
export function VanitasMark({ size = 15 }) {
  return (
    <svg viewBox="0 0 20 20" width={size} height={size} fill="none" aria-hidden="true">
      <circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="1" opacity="0.35" />
      <circle cx="10" cy="10" r="4.2" stroke="currentColor" strokeWidth="1.4" />
      <path d="M10 3.2v1.8M10 15v1.8M3.2 10h1.8M15 10h1.8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      <circle cx="10" cy="10" r="1" fill="currentColor" />
    </svg>
  );
}

/** Pied de la colonne Vanitas : état de la flotte (compte de postes en ligne). `onlineCount`
 * reste `null` tant que le premier chargement n'a pas abouti, plutôt que d'afficher un
 * "0 en ligne" trompeur pendant le chargement. */
export function VanitasNavFooter() {
  const { t } = useI18n();
  const agents = useVanitasAgents();

  useEffect(() => {
    agents.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Serveur injoignable (status "error") : dit explicitement plutôt que de rester sur "…" à
  // vie — constaté au 1er lancement de la refonte, serveur Vanitas éteint.
  if (agents.state.status === "error") {
    return (
      <span className="asb-sync" title={agents.state.error || undefined}>
        <span className="asb-dot down" />
        {t("vanitas.status.unreachable")}
      </span>
    );
  }
  const onlineCount = agents.state.status === "done" ? agents.state.data.filter(isOnline).length : null;
  return (
    <span className="asb-sync">
      <span className={`asb-dot${onlineCount ? " live" : ""}`} />
      {onlineCount === null ? t("vanitas.status.loading") : t("vanitas.status.online", { count: onlineCount })}
    </span>
  );
}
