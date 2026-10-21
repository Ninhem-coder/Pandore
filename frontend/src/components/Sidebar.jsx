import { Fragment, useEffect, useState } from "react";
import { useAuth } from "../AuthContext.jsx";
import {
  IconGrid,
  IconShield,
  IconAlertTriangle,
  IconGauge,
  IconBookmark,
  IconLaptop,
  IconPackage,
  IconLibrary,
  IconUpload,
  IconSearch,
  IconSettings,
  IconLogout,
  IconBell,
  IconPencil,
} from "./icons.jsx";
import { VANITAS_NAV, VanitasMark, VanitasNavFooter, isVanitasNavItemVisible } from "./VanitasSidebar.jsx";

/**
 * Arbre de navigation Pandore — regroupé le 2026-10-21 selon la maquette de refonte validée par
 * Nicolas (`Design/maquettes/refonte-ui.html`, structure inspirée de Lumis) : une seule liste à
 * plat de groupes `{ group, items }` + un item nu ("Dashboard"), plus de niveau "catégorie" à
 * sous-groupes. Les CLÉS de routage sont toutes inchangées (même convention que tous les
 * renommages précédents de ce fichier, voir docs/internal/HISTORY.md) — seuls libellés/regroupement
 * changent :
 *  - "Appareil" > "Rechercher" → groupe "Appareils" > "Fiche appareil" (`device-overview`) ;
 *  - "Sécurité" > "Analyse" / "Vulnérabilité" → deux groupes "Sécurité" et "Vulnérabilités" ;
 *  - "Application" → groupe "Applications", "Catalogue d'application" → "Catalogue",
 *    "Application déployée" → "Applications déployées".
 * `widgets-test` reste la clé de "Alertes" (ex-"Widgets (test)", voir WidgetsTestTab.jsx).
 */
export const NAV_TREE = [
  { key: "overview", label: "Dashboard", icon: <IconGrid /> },
  {
    group: "Appareils",
    items: [
      { key: "device-inventory", label: "Inventaire", icon: <IconLaptop /> },
      { key: "device-overview", label: "Fiche appareil", icon: <IconSearch /> },
    ],
  },
  {
    group: "Sécurité",
    items: [
      { key: "intune", label: "Conformité", icon: <IconShield /> },
      { key: "secure-score", label: "Secure Score", icon: <IconGauge /> },
      { key: "widgets-test", label: "Alertes", icon: <IconBell /> },
    ],
  },
  {
    group: "Vulnérabilités",
    items: [
      { key: "vulnerabilities", label: "Vulnérabilités", icon: <IconAlertTriangle /> },
      { key: "cve-watch", label: "Suivi CVE", icon: <IconBookmark /> },
    ],
  },
  {
    group: "Applications",
    items: [
      { key: "app-catalog", label: "Catalogue", icon: <IconLibrary /> },
      { key: "app-deployed", label: "Applications déployées", icon: <IconPackage /> },
      { key: "app-add", label: "Ajouter une application", icon: <IconUpload /> },
      { key: "app-edit", label: "Modifier une application", icon: <IconPencil /> },
    ],
  },
];

/** Clés de toutes les pages atteignables, à plat. */
export const NAV_KEYS = NAV_TREE.flatMap((entry) => (entry.group ? entry.items.map((i) => i.key) : [entry.key]));

/* Marque seule (bouclier + serrure) extraite du logo Pandore (`Design/pandore-icon.svg`),
   recadrée sur son pictogramme pour tenir dans le badge du rail. */
function LogoMark({ size = 20 }) {
  return (
    <svg viewBox="0 0 60 62" width={size} height={size} aria-hidden="true">
      <defs>
        <linearGradient id="asbLogoIcon" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor="#F6B27E" />
          <stop offset="100%" stopColor="#EE9A5C" />
        </linearGradient>
      </defs>
      <path d="M30 0 C42 6 52 8 60 8 C60 34 52 52 30 62 C8 52 0 34 0 8 C8 8 18 6 30 0 Z" fill="url(#asbLogoIcon)" />
      <circle cx="30" cy="28" r="7" fill="#0A0E1A" />
      <path d="M26.5 32 L33.5 32 L31 44 L29 44 Z" fill="#0A0E1A" />
    </svg>
  );
}

function NavRow({ item, active, onSelect }) {
  const isActive = active === item.key;
  return (
    <button
      type="button"
      className={`asb-item${isActive ? " active" : ""}`}
      onClick={() => onSelect(item.key)}
      aria-current={isActive ? "page" : undefined}
    >
      <span className="asb-item-icon">{item.icon}</span>
      <span className="asb-item-label">{item.label}</span>
    </button>
  );
}

/** Rend un arbre `[{key,…} | {group, items}]` — commun aux deux mondes. `isVisible` filtre les
 * items selon les permissions (Vanitas) ; un groupe dont plus aucun item n'est visible disparaît
 * avec son en-tête. */
function NavList({ tree, active, onSelect, isVisible = () => true }) {
  return tree.map((entry) => {
    if (entry.group) {
      const items = entry.items.filter(isVisible);
      if (!items.length) return null;
      return (
        <Fragment key={`g-${entry.group}`}>
          <p className="asb-group">{entry.group}</p>
          {items.map((item) => (
            <NavRow key={item.key} item={item} active={active} onSelect={onSelect} />
          ))}
        </Fragment>
      );
    }
    if (!isVisible(entry)) return null;
    return <NavRow key={entry.key} item={entry} active={active} onSelect={onSelect} />;
  });
}

/** Petit bouton carré du rail, avec infobulle (`data-tip`) à droite. */
function RailButton({ label, current, onClick, children }) {
  return (
    <button
      type="button"
      className={`asb-rail-btn${current ? " current" : ""}`}
      onClick={onClick}
      aria-label={label}
      aria-pressed={current === undefined ? undefined : current}
      data-tip={label}
    >
      {children}
    </button>
  );
}

const WORLDS = {
  intune: { label: "Pandore", sub: "Intune · Defender" },
  vanitas: { label: "Vanitas", sub: "Rien n'échappe." },
};

/**
 * Sidebar unifiée Pandore + Vanitas (refonte du 2026-10-21, maquette approuvée par Nicolas :
 * "on garde tout le design de la sidebar [de la maquette] mais le contenu des pages reste le
 * même"). Remplace les deux rails repliables séparés (ex-`Sidebar` + `VanitasSidebar` par défaut)
 * par la structure Lumis :
 *  - un RAIL d'icônes fixe (56px) : marque, un bouton par « monde » (Pandore/Vanitas — c'est
 *    le SEUL à basculer `source` depuis le retrait du sélecteur du masthead), recherche (Ctrl K),
 *    Paramètres, déconnexion, avatar ;
 *  - une COLONNE de navigation (248px) propre au monde actif, repliable — re-cliquer le monde
 *    actif dans le rail ou le bouton de repli ; état persisté dans `sidebarCollapsed` (même clé
 *    que l'ancien rail, la préférence d'un utilisateur est conservée).
 * Habillage par monde via `data-world` sur la racine (tokens `--sb-*`, voir styles.css
 * `.app-sidebar`) — même séparation qu'avant entre jetons Pandore et HUD Vanitas.
 */
export default function Sidebar({ source, onSourceChange, active, vanitasActive, onSelect, onSelectVanitas, onOpenSettings, onOpenSearch, stamp }) {
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem("sidebarCollapsed") === "1";
    } catch {
      return false;
    }
  });

  function setCollapsedPersist(next) {
    setCollapsed(next);
    try {
      localStorage.setItem("sidebarCollapsed", next ? "1" : "0");
    } catch {
      // localStorage indisponible — préférence non persistée, pas bloquant.
    }
  }

  // Ctrl/Cmd + K → recherche globale (raccourci annoncé dans l'infobulle du rail).
  useEffect(() => {
    function handleKeyDown(event) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        onOpenSearch();
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [onOpenSearch]);

  function handleWorld(world) {
    if (world === source) {
      setCollapsedPersist(!collapsed);
      return;
    }
    onSourceChange(world);
    if (collapsed) setCollapsedPersist(false);
  }

  const world = WORLDS[source] ?? WORLDS.intune;
  const isVanitas = source === "vanitas";
  const initials = (user.username || "?").slice(0, 2).toUpperCase();
  const roleLabel = user.role === "admin" ? "Admin" : "Lecture seule";

  return (
    <aside className={`app-sidebar${collapsed ? " collapsed" : ""}`} data-world={isVanitas ? "vanitas" : "pandore"}>
      <div className="asb-rail" aria-label="Mondes">
        <span className="asb-logo" aria-hidden="true">
          <LogoMark size={22} />
        </span>
        <RailButton label="Pandore" current={!isVanitas} onClick={() => handleWorld("intune")}>
          <IconShield />
        </RailButton>
        <RailButton label="Vanitas" current={isVanitas} onClick={() => handleWorld("vanitas")}>
          <VanitasMark size={19} />
        </RailButton>
        <span className="asb-rail-sep" />
        <RailButton label="Rechercher (Ctrl K)" onClick={onOpenSearch}>
          <IconSearch />
        </RailButton>
        <span className="asb-rail-spacer" />
        <RailButton label="Paramètres" onClick={onOpenSettings}>
          <IconSettings />
        </RailButton>
        <RailButton label="Se déconnecter" onClick={logout}>
          <IconLogout />
        </RailButton>
        <span className="asb-avatar" title={`${user.username} · ${roleLabel}`}>
          {initials}
        </span>
      </div>

      <nav className="asb-col" aria-label={`Navigation ${world.label}`}>
        <div className="asb-col-head">
          <span className="asb-col-title">
            {isVanitas ? <VanitasMark size={18} /> : <LogoMark size={18} />}
            {world.label}
          </span>
          <span className="asb-col-sub">{world.sub}</span>
        </div>
        <div className="asb-nav">
          {isVanitas ? (
            <NavList
              tree={VANITAS_NAV}
              active={vanitasActive}
              onSelect={onSelectVanitas}
              isVisible={(item) => isVanitasNavItemVisible(item, user)}
            />
          ) : (
            <NavList tree={NAV_TREE} active={active} onSelect={onSelect} />
          )}
        </div>
        <div className="asb-col-foot">
          {isVanitas ? (
            <VanitasNavFooter />
          ) : (
            <span className="asb-sync">
              <span className="asb-dot" />
              Graph · {stamp}
            </span>
          )}
        </div>
      </nav>
    </aside>
  );
}
