/**
 * Icônes de navigation — traits fins façon feather-icons, dessinées à la main pour
 * éviter une dépendance externe juste pour 5 pictogrammes. viewBox 20x20, stroke =
 * currentColor (héritent la couleur du .nav-item, actif ou non — voir Sidebar.jsx).
 *
 * `aria-hidden="true"` (ajouté à la revue de code du 2026-08-17) : ces icônes sont toujours
 * accompagnées d'un libellé texte visible (titre de nav-item, titre de SummaryCard…) — sans
 * cet attribut, un lecteur d'écran annonçait un <svg> sans nom accessible juste avant/après
 * ce même libellé, un doublon inutile plutôt qu'une information manquante.
 */
const common = {
  width: 19,
  height: 19,
  viewBox: "0 0 20 20",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": "true",
};

export function IconGrid() {
  return (
    <svg {...common}>
      <rect x="2.5" y="2.5" width="6" height="6" rx="1.2" />
      <rect x="11.5" y="2.5" width="6" height="6" rx="1.2" />
      <rect x="2.5" y="11.5" width="6" height="6" rx="1.2" />
      <rect x="11.5" y="11.5" width="6" height="6" rx="1.2" />
    </svg>
  );
}

export function IconShield() {
  return (
    <svg {...common}>
      <path d="M10 2.2 L16.5 4.6 V9.5 C16.5 13.8 13.8 16.7 10 17.8 C6.2 16.7 3.5 13.8 3.5 9.5 V4.6 Z" />
      <path d="M7.2 9.8 L9.2 11.8 L13 7.4" />
    </svg>
  );
}

export function IconLayers() {
  return (
    <svg {...common}>
      <path d="M10 2.5 L17.5 6.5 L10 10.5 L2.5 6.5 Z" />
      <path d="M2.5 10.2 L10 14.2 L17.5 10.2" />
      <path d="M2.5 13.9 L10 17.9 L17.5 13.9" />
    </svg>
  );
}

export function IconTarget() {
  return (
    <svg {...common}>
      <circle cx="10" cy="10" r="7" />
      <circle cx="10" cy="10" r="3.6" />
      <circle cx="10" cy="10" r="0.6" fill="currentColor" />
    </svg>
  );
}

// Profils Vanitas (2026-09-10) — nav "Profils" (Administration), représente un contrôle
// d'accès (clé), distincte de IconShield (déjà utilisée pour "Conformité").
export function IconKey() {
  return (
    <svg {...common}>
      <circle cx="7" cy="13" r="3.3" />
      <path d="M9.3 10.7 L16.5 3.5 M13.5 6.5 L15.5 8.5 M15.7 4.3 L17.5 6.1" />
    </svg>
  );
}

export function IconWrench() {
  return (
    <svg {...common}>
      <path d="M13.2 3.2 a4 4 0 0 0 -5.4 4.7 L3 12.7 a1.9 1.9 0 0 0 2.7 2.7 l4.8 -4.8 a4 4 0 0 0 4.7 -5.4 l-2.6 2.6 -2 -2 z" />
    </svg>
  );
}

/* Icônes ajoutées pour la passe design du 2026-08-06 (badges des tuiles KPI, `SummaryCard`
 * — voir styles.css `.strip-icon`), même famille de traits fins viewBox 20x20. */

export function IconLaptop() {
  return (
    <svg {...common}>
      <rect x="3" y="3.5" width="14" height="9" rx="1.2" />
      <path d="M1.6 16.5 h16.8 M8.2 16.5 v-1.2 h3.6 v1.2" />
    </svg>
  );
}

export function IconAlertTriangle() {
  return (
    <svg {...common}>
      <path d="M10 2.8 L18 16.2 H2 Z" />
      <path d="M10 8 v4" />
      <circle cx="10" cy="14.3" r="0.6" fill="currentColor" />
    </svg>
  );
}

export function IconGauge() {
  return (
    <svg {...common}>
      <path d="M3 14.5 a7 7 0 1 1 14 0" />
      <path d="M10 10.5 L13.2 6.8" />
      <circle cx="10" cy="10.5" r="1" fill="currentColor" />
    </svg>
  );
}

/* Ajoutée pour "Suivi CVE" (2026-08-10, sous-catégorie Defender > Vulnérabilité) — un signet
 * pour représenter des CVE "épinglées"/suivies, distinct du triangle d'alerte de la recherche
 * ponctuelle (IconAlertTriangle). */
export function IconBookmark() {
  return (
    <svg {...common}>
      <path d="M5.5 2.8 h9 a1 1 0 0 1 1 1 V17.2 L10 13.6 L4.5 17.2 V3.8 a1 1 0 0 1 1 -1 Z" />
    </svg>
  );
}

/* Ajoutée pour la recherche globale du masthead (2026-08-20, voir GlobalSearch.jsx) — simple
 * loupe, distincte de IconTarget (cercles concentriques, déjà utilisé pour "Par criticité")
 * pour ne pas réutiliser une icône qui porte déjà un autre sens ailleurs dans l'app. */
export function IconSearch() {
  return (
    <svg {...common}>
      <circle cx="8.6" cy="8.6" r="5.6" />
      <path d="M12.7 12.7 L17.5 17.5" />
    </svg>
  );
}

/* Ajoutée pour le bouton "Exporter Excel" de VulnCard (VulnerabilitiesTab.jsx, 2026-08-21,
 * demande de Nicolas) — flèche vers un plateau, pictogramme "téléchargement" classique,
 * distincte de IconLaptop (qui représente un appareil, pas une action). */
export function IconDownload() {
  return (
    <svg {...common}>
      <path d="M10 2.8 V12.2 M6.2 8.6 L10 12.4 L13.8 8.6" />
      <path d="M3.2 14.8 V16.2 A1 1 0 0 0 4.2 17.2 H15.8 A1 1 0 0 0 16.8 16.2 V14.8" />
    </svg>
  );
}

/* Ajoutée pour la "Bibliothèque d'application" (2026-08-26, AppCatalogTab.jsx, remplace le
 * catalogue d'apps détectées) — étagère à 3 niveaux, distincte d'IconPackage (une boîte
 * unique, déjà prise par l'onglet "Application"/l'icône du wizard) et d'IconLayers (déjà
 * prise par "Conformité Intune"). */
export function IconLibrary() {
  return (
    <svg {...common}>
      <path d="M3 4.5h14M3 10h14M3 15.5h14" />
      <path d="M6 4.5v-1M14 4.5v-1M6 15.5v1M14 15.5v1" />
    </svg>
  );
}

/* Ajoutée pour l'assistant de packaging Win32 (2026-08-26, DeployAppWizard.jsx) — flèche
 * inversée par rapport à IconDownload (plateau vers le haut), pour le dépôt direct d'un
 * installeur plutôt que le téléchargement d'un livrable. */
export function IconUpload() {
  return (
    <svg {...common}>
      <path d="M10 12.2 V2.8 M6.2 6.4 L10 2.6 L13.8 6.4" />
      <path d="M3.2 14.8 V16.2 A1 1 0 0 0 4.2 17.2 H15.8 A1 1 0 0 0 16.8 16.2 V14.8" />
    </svg>
  );
}

/* Ajoutée pour l'onglet "Application Intune" (2026-08-25, demande de Nicolas : nouvel onglet
 * avec les sous-catégories "Catalogue d'application"/"Application déployée") — pictogramme
 * "boîte/paquet", pour ne pas réutiliser IconLaptop (représente un appareil) ni IconLayers
 * (déjà pris par "Conformité Intune" en icône de sous-catégorie) sur un onglet qui parle
 * d'applications, pas d'appareils ni de politiques. */
export function IconPackage() {
  return (
    <svg {...common}>
      <path d="M10 2.2 L17 6.2 V13.8 L10 17.8 L3 13.8 V6.2 Z" />
      <path d="M3 6.2 L10 10.2 L17 6.2" />
      <path d="M10 10.2 V17.8" />
    </svg>
  );
}

/* Poignée de glisser-déposer (2026-08-27, "Vue d'ensemble (test)" — OverviewTestTab.jsx) —
 * 6 points en grille 2×3, motif "grip" standard (Trello, Notion...) plutôt qu'une flèche à 4
 * directions : signale "attrape ici pour déplacer" sans ambiguïté avec une icône de
 * redimensionnement. Points pleins (`fill: currentColor`) plutôt que des traits — seule
 * icône de ce fichier à déroger au style `stroke`, la texture "poignée" physique appelle des
 * points pleins plutôt que des contours. */
export function IconGrip() {
  return (
    <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <circle cx="7" cy="4.5" r="1.4" />
      <circle cx="13" cy="4.5" r="1.4" />
      <circle cx="7" cy="10" r="1.4" />
      <circle cx="13" cy="10" r="1.4" />
      <circle cx="7" cy="15.5" r="1.4" />
      <circle cx="13" cy="15.5" r="1.4" />
    </svg>
  );
}

/** Bulle de commentaire — ajoutée le 2026-08-28 (redesign du panneau de détail d'alerte,
 * WidgetsTestTab.jsx) pour donner un repère visuel à la section "Commentaires", même esprit
 * dessiné à la main que le reste de ce fichier. */
export function IconMessage() {
  return (
    <svg {...common}>
      <path d="M3.5 4.5h13a1 1 0 0 1 1 1v7.2a1 1 0 0 1-1 1H9.2L5.8 16.8v-3.1H3.5a1 1 0 0 1-1-1v-7.2a1 1 0 0 1 1-1Z" />
    </svg>
  );
}

/** Flèche circulaire — bouton "Rafraîchir" du masthead (Dashboard.jsx, 2026-08-28, demande de
 * Nicolas). Arc ouvert (5/6 de cercle) + pointe de flèche à l'extrémité supérieure, motif
 * "refresh" minimaliste courant, dessiné à la main comme le reste de ce fichier plutôt qu'une
 * icône de police externe. */
export function IconRefresh() {
  return (
    <svg {...common}>
      <path d="M15.7 10a5.7 5.7 0 1 1-1.9-4.25" />
      <path d="M15.7 3.4v3.5h-3.5" />
    </svg>
  );
}

/** 4 flèches vers les coins — bouton "Agrandir" du panneau détail d'app déployée
 * (DeployedAppsTab.jsx, 2026-09-02, demande de Nicolas). Motif "expand/maximize" standard,
 * deux paires de coins opposés plutôt qu'une icône de police externe. */
export function IconExpand() {
  return (
    <svg {...common}>
      <path d="M7 3H3v4M13 3h4v4M7 17H3v-4M13 17h4v-4" />
    </svg>
  );
}

/** Terminal/invite de commande — Sidebar "Vanitas", item "Commandes" (2026-09-04, jalon 5) :
 * cadre + chevron, motif standard pour "canal de commande", aucune icône existante ne
 * représentait ce concept précis. */
export function IconTerminal() {
  return (
    <svg {...common}>
      <rect x="2.5" y="4" width="15" height="12" rx="2" />
      <path d="M6 8.5 9 10l-3 1.5M10.5 12.5h3.5" />
    </svg>
  );
}

/** Engrenage — bouton "Paramètres" du masthead (2026-09-08, authentification multi-comptes :
 * changer son identifiant/mot de passe, gestion des comptes pour un admin). Motif classique
 * "roue dentée" simplifié à 6 dents pour rester lisible à 19px, aucune icône existante ne
 * représentait ce concept. */
export function IconSettings() {
  return (
    <svg {...common}>
      <circle cx="10" cy="10" r="2.6" />
      <path d="M10 3.2v2.1M10 14.7v2.1M16.8 10h-2.1M5.3 10H3.2M14.6 5.4l-1.5 1.5M6.9 13.1l-1.5 1.5M14.6 14.6l-1.5-1.5M6.9 6.9 5.4 5.4" />
    </svg>
  );
}

/** Chevron simple — caret d'accordéon (sous-catégories de Sidebar.jsx) et flèche de
 * repli/dépli du rail de navigation (2026-09-09, refonte de la sidebar en rail unique
 * repliable — voir Sidebar.jsx/VanitasSidebar.jsx). Tourné à 180° via CSS selon le contexte
 * plutôt que dessiné deux fois. */
export function IconChevronRight() {
  return (
    <svg {...common}>
      <path d="M7.5 4.5 13 10l-5.5 5.5" />
    </svg>
  );
}

/** "Applications déployées" (2026-09-10, nav Vanitas > Inventaire) — flèche sortant d'un
 * poste, distincte d'`IconUpload` (dépôt DANS le catalogue) : celle-ci part du poste vers
 * l'extérieur, l'idée de "ce qui a déjà été poussé sur le parc" plutôt que "ajouter au
 * catalogue". */
export function IconSend() {
  return (
    <svg {...common}>
      <rect x="3" y="4" width="10" height="8" rx="1" />
      <path d="M6 16h4" />
      <path d="M12 6l5-2v5" />
      <path d="M17 4l-6 6" />
    </svg>
  );
}

/** Déconnexion — pied de rail de navigation (2026-09-09, refonte de la sidebar). Porte
 * ouverte + flèche sortante, motif classique "logout" simplifié au trait pour rester
 * cohérent avec le reste de ce fichier. */
export function IconLogout() {
  return (
    <svg {...common}>
      <path d="M8 3.5H4.5A1.5 1.5 0 0 0 3 5v10a1.5 1.5 0 0 0 1.5 1.5H8" />
      <path d="M12.5 6.5 16.5 10l-4 3.5M16.2 10H7.5" />
    </svg>
  );
}

/** Livre ouvert — pictogramme de "Documentation" (2026-09-10, jalon documentation
 * utilisateur Vanitas). Reliure centrale + deux pages, motif classique gardé au trait
 * fin pour rester cohérent avec le reste de ce fichier plutôt qu'un pictogramme plein. */
export function IconBook() {
  return (
    <svg {...common}>
      <path d="M10 5.2c-1.3-1-3-1.4-5.5-1.4a1 1 0 0 0-1 1v9.4a1 1 0 0 0 1 1c2.5 0 4.2.4 5.5 1.4" />
      <path d="M10 5.2c1.3-1 3-1.4 5.5-1.4a1 1 0 0 1 1 1v9.4a1 1 0 0 1-1 1c-2.5 0-4.2.4-5.5 1.4" />
      <path d="M10 5.2V16.6" />
    </svg>
  );
}

/** Balayage radar — nav "Activités suspectes" (jalon "détection d'activités suspectes sur les
 * postes", 2026-09-14). Repris du même motif "réticule/balayage" que `VanitasMark`
 * (VanitasSidebar.jsx, charte graphique §9 : imagerie radar/HUD associée à la surveillance
 * continue et la détection), distinct de `IconTarget` (déjà utilisé pour la criticité/les
 * vulnérabilités — cercles concentriques sans balayage) et de `IconAlertTriangle` (déjà utilisé
 * pour "Vulnérabilités", un agrégat fleet-wide différent). Arc de balayage + point détecté,
 * plutôt qu'un simple triangle d'alerte de plus. */
export function IconRadar() {
  return (
    <svg {...common}>
      <circle cx="10" cy="10" r="7" opacity="0.35" />
      <circle cx="10" cy="10" r="4" opacity="0.6" />
      <path d="M10 10 L15.2 6.4A7 7 0 0 1 10 17V10Z" fill="currentColor" stroke="none" opacity="0.5" />
      <circle cx="10" cy="10" r="0.9" fill="currentColor" />
      <circle cx="13.6" cy="7.2" r="0.9" fill="currentColor" />
    </svg>
  );
}


/** Cloche — item "Alertes" de la sidebar (refonte du 2026-10-21, maquette `Design/maquettes/refonte-ui.html`). */
export function IconBell() {
  return (
    <svg {...common}>
      <path d="M5 13.5V9a5 5 0 0 1 10 0v4.5l1.3 1.7H3.7Z" />
      <path d="M8.3 17.5h3.4" />
    </svg>
  );
}

/** Crayon — item "Modifier une application" de la sidebar (même refonte). */
export function IconPencil() {
  return (
    <svg {...common}>
      <path d="M3.5 16.5h3.3l9-9-3.3-3.3-9 9Z" />
      <path d="m11.2 5.5 3.3 3.3" />
    </svg>
  );
}

/** Globe — interface language menu in the sidebar rail. */
export function IconGlobe() {
  return (
    <svg {...common}>
      <circle cx="10" cy="10" r="7" />
      <path d="M3 10h14" />
      <path d="M10 3c1.9 2 2.9 4.3 2.9 7s-1 5-2.9 7c-1.9-2-2.9-4.3-2.9-7s1-5 2.9-7Z" />
    </svg>
  );
}

/** Check mark — selected entry of a menu. */
export function IconCheck() {
  return (
    <svg {...common}>
      <path d="M4.5 10.5 8.2 14l7.3-8" />
    </svg>
  );
}
