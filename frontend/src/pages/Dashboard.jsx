import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import { useDashboardData } from "../hooks/useDashboardData.js";
import { friendlyErrorMessage } from "../theme.js";
import Sidebar from "../components/Sidebar.jsx";
import ErrorBoundary from "../components/ErrorBoundary.jsx";
import GlobalSearch from "../components/GlobalSearch.jsx";
import { IconRefresh } from "../components/icons.jsx";
import SettingsModal from "../components/SettingsModal.jsx";
import { resolveSearchTab, bumpSearchNav, bumpVanitasNav } from "../navigation.js";

// Code-splitting (2026-09-12) — chaque page d'onglet est chargée à la demande (`React.lazy`)
// plutôt qu'empaquetée dans le bundle initial : le premier chargement ne télécharge plus que
// la coquille + la page réellement ouverte (Vue d'ensemble), les ~30 autres pages (dont des
// fichiers >1000 lignes) arrivent au premier clic. La coquille (sidebars, ErrorBoundary,
// GlobalSearch, SettingsModal) reste en import direct : toujours nécessaire, jamais un gain à
// la différer. Le rendu de la page active est enveloppé dans <Suspense> (voir plus bas).
const OverviewTab = lazy(() => import("./OverviewTab.jsx"));
const DefenderTab = lazy(() => import("./DefenderTab.jsx"));
const IntuneTab = lazy(() => import("./IntuneTab.jsx"));
const VulnerabilitiesTab = lazy(() => import("./VulnerabilitiesTab.jsx"));
const CveWatchTab = lazy(() => import("./CveWatchTab.jsx"));
const SecureScoreTab = lazy(() => import("./SecureScoreTab.jsx"));
const WidgetsTestTab = lazy(() => import("./WidgetsTestTab.jsx"));
const DeviceOverviewTab = lazy(() => import("./DeviceOverviewTab.jsx"));
const DeviceInventoryTab = lazy(() => import("./DeviceInventoryTab.jsx"));
const AppCatalogTab = lazy(() => import("./AppCatalogTab.jsx"));
const AddAppTab = lazy(() => import("./AddAppTab.jsx"));
const EditAppTab = lazy(() => import("./EditAppTab.jsx"));
const DeployedAppsTab = lazy(() => import("./DeployedAppsTab.jsx"));
const VanitasOverviewTab = lazy(() => import("./VanitasOverviewTab.jsx"));
const VanitasDevicesTab = lazy(() => import("./VanitasDevicesTab.jsx"));
const VanitasActivityLogTab = lazy(() => import("./VanitasActivityLogTab.jsx"));
const VanitasComplianceTab = lazy(() => import("./VanitasComplianceTab.jsx"));
const VanitasVulnerabilitiesTab = lazy(() => import("./VanitasVulnerabilitiesTab.jsx"));
const VanitasEolTab = lazy(() => import("./VanitasEolTab.jsx"));
const VanitasGroupsTab = lazy(() => import("./VanitasGroupsTab.jsx"));
const VanitasInstallersTab = lazy(() => import("./VanitasInstallersTab.jsx"));
const VanitasDeployedAppsTab = lazy(() => import("./VanitasDeployedAppsTab.jsx"));
const VanitasPatchTab = lazy(() => import("./VanitasPatchTab.jsx"));
const VanitasAppCatalogTab = lazy(() => import("./VanitasAppCatalogTab.jsx"));
const VanitasProfilesTab = lazy(() => import("./VanitasProfilesTab.jsx"));
const VanitasDocsTab = lazy(() => import("./VanitasDocsTab.jsx"));
const VanitasEnrollTab = lazy(() => import("./VanitasEnrollTab.jsx"));
const VanitasSuspiciousActivityTab = lazy(() => import("./VanitasSuspiciousActivityTab.jsx"));

// Navigation réduite à Vue d'ensemble + Defender > Conformité Intune / Vulnérabilités /
// Secure Score (voir Sidebar.jsx — "Secure Score" rattachée à Defender le 2026-08-10, sur
// demande explicite de Nicolas, après être passée par un item de niveau 1 indépendant).
// "Widgets (test)" ajouté le 2026-08-12 (voir WidgetsTestTab.jsx) comme bac à sable
// temporaire, devenu le dashboard "Alertes Defender" (V42-V43) puis validé et déplacé sous
// Defender > Analyse le 2026-08-17 (V44, voir Sidebar.jsx) — la clé de routage "widgets-test"
// et le nom du fichier/composant sont volontairement restés inchangés pour limiter le risque
// de casser une référence (voir mémoire de projet).
// `RecommendationsTab.jsx` et `SettingsTab.jsx` ne sont plus routés : les fichiers restent
// sur disque mais ne sont plus atteignables, ils peuvent être supprimés manuellement.
const TABS = {
  overview: OverviewTab,
  "device-inventory": DeviceInventoryTab,
  "device-overview": DeviceOverviewTab,
  defender: DefenderTab,
  intune: IntuneTab,
  vulnerabilities: VulnerabilitiesTab,
  "cve-watch": CveWatchTab,
  "secure-score": SecureScoreTab,
  "widgets-test": WidgetsTestTab,
  // "Application Intune" (2026-08-25, demande de Nicolas) : pas de page propre pour le
  // niveau 1 (même principe que "defender" ci-dessus), seules ses sous-catégories sont
  // routées — voir Sidebar.jsx pour l'arborescence. "app-add" (2026-08-26, scission de
  // l'ancien "app-catalog" combiné) ajouté sous le groupe "Administration". "app-edit"
  // (2026-08-26, même jour, demande de Nicolas — "modifier les applications") ajouté juste en
  // dessous dans le même groupe.
  "app-catalog": AppCatalogTab,
  "app-add": AddAppTab,
  "app-edit": EditAppTab,
  "app-deployed": DeployedAppsTab,
};

const TAB_TITLES = {
  // Titre "Dashboard" (2026-08-28, demande de Nicolas), ex-"Endpoint exposure score".
  // Accroche "La boîte est ouverte." (2026-09-09, clin d'œil au nom "Pandore" — déjà validée
  // sur la proposition de sidebar interactive) — reprend enfin ici la place de l'ancien
  // "<organisation> · ..." : Nicolas avait déjà demandé de retirer toute référence au
  // nom de l'organisation ("on est à part maintenant dans cette solution"), retirée sur la
  // proposition mais jamais reportée dans le vrai masthead jusqu'ici — oubli corrigé.
  overview: { eyebrow: "La boîte est ouverte.", title: "Dashboard" },
  // "Inventaire" (2026-09-02, demande de Nicolas — maquette "Inventaire des appareils") : table
  // fleet-wide Intune + Defender réconciliés par nom, voir DeviceInventoryTab.jsx.
  "device-inventory": { eyebrow: "Pandore · Defender for Endpoint & Intune", title: "Inventaire des appareils" },
  "device-overview": { eyebrow: "Pandore · Defender for Endpoint & Intune", title: "Appareil (vue 360°)" },
  // Titre "Sécurité" (2026-08-28, demande de Nicolas), ex-"Defender" — miroir du renommage
  // Sidebar.jsx, clé de routage "defender" inchangée.
  defender: { eyebrow: "Pandore · Microsoft Defender for Endpoint", title: "Sécurité" },
  // Titre "Conformité" (2026-08-28, demande de Nicolas), ex-"Conformité Intune".
  intune: { eyebrow: "Pandore · Microsoft Defender › Intune", title: "Conformité" },
  vulnerabilities: { eyebrow: "Pandore · Microsoft Defender › Vulnérabilités", title: "Vulnérabilités" },
  "cve-watch": { eyebrow: "Pandore · Microsoft Defender › Vulnérabilités › Suivi CVE", title: "Suivi CVE" },
  "secure-score": { eyebrow: "Pandore · Microsoft Defender › Secure Score", title: "Secure score" },
  // Titre corrigé le 2026-08-17 (demande explicite de Nicolas : "pas widget de test mais
  // Alerte") — la page a de toute façon graduée hors du groupe "Test" le même jour (voir
  // Sidebar.jsx et la mémoire de projet, V44) ; clé de routage "widgets-test" inchangée.
  // Titre "Alertes" (2026-08-28, demande de Nicolas), ex-"Alertes Defender".
  "widgets-test": { eyebrow: "Pandore · Microsoft Defender › Alertes", title: "Alertes" },
  // "Bibliothèque d'application" (titre du 2026-08-26 matin) redevient "Catalogue
  // d'application" le même jour, après-midi : la page a été scindée en deux onglets
  // (Administration > "Ajouter une application" / "Catalogue d'application") — celle-ci ne
  // garde plus que la liste, "Catalogue" redevient le mot juste.
  "app-catalog": { eyebrow: "Pandore · Microsoft Intune › Applications", title: "Catalogue d'application" },
  "app-add": { eyebrow: "Pandore · Microsoft Intune › Applications", title: "Ajouter une application" },
  "app-edit": { eyebrow: "Pandore · Microsoft Intune › Applications", title: "Modifier une application" },
  "app-deployed": { eyebrow: "Pandore · Microsoft Intune › Applications", title: "Application déployée" },
};

// Catégorie "Vanitas" (2026-09-04, jalon 5) — projet personnel séparé endpoint-agent/, voir
// VanitasSidebar.jsx. Arbre de navigation totalement SÉPARÉ de TABS/TAB_TITLES ci-dessus :
// basculer la source (voir `source` dans Dashboard() plus bas) remplace Sidebar+ActiveTab par
// VanitasSidebar+VanitasActiveTab EN BLOC, jamais les deux mélangés dans le même routeur.
const VANITAS_TABS = {
  "vanitas-overview": VanitasOverviewTab,
  "vanitas-suspicious-activity": VanitasSuspiciousActivityTab,
  "vanitas-app-catalog": VanitasAppCatalogTab,
  "vanitas-devices": VanitasDevicesTab,
  "vanitas-groups": VanitasGroupsTab,
  "vanitas-deployed-apps": VanitasDeployedAppsTab,
  "vanitas-patch": VanitasPatchTab,
  "vanitas-commands": VanitasActivityLogTab,
  "vanitas-enroll": VanitasEnrollTab,
  "vanitas-compliance": VanitasComplianceTab,
  "vanitas-vulnerabilities": VanitasVulnerabilitiesTab,
  "vanitas-eol": VanitasEolTab,
  "vanitas-installers": VanitasInstallersTab,
  "vanitas-profiles": VanitasProfilesTab,
  "vanitas-docs": VanitasDocsTab,
};

const VANITAS_TAB_TITLES = {
  // Accroche "Rien n'échappe." (2026-09-09, ton cyberpunk sobre — déjà validée sur la
  // proposition de sidebar interactive, jamais reportée jusqu'ici dans le vrai masthead).
  "vanitas-overview": { eyebrow: "Rien n'échappe.", title: "Vue d'ensemble" },
  "vanitas-suspicious-activity": { eyebrow: "Vanitas · Détection", title: "Activités suspectes" },
  "vanitas-app-catalog": { eyebrow: "Vanitas · Supervision de poste", title: "Catalogue d'application" },
  "vanitas-devices": { eyebrow: "Vanitas · Supervision de poste", title: "Postes" },
  "vanitas-groups": { eyebrow: "Vanitas · Supervision de poste", title: "Groupes" },
  "vanitas-deployed-apps": { eyebrow: "Vanitas · Supervision de poste", title: "Applications déployées" },
  "vanitas-patch": { eyebrow: "Vanitas · Sécurité", title: "Mises à jour Vanitas" },
  "vanitas-commands": { eyebrow: "Vanitas · Supervision de poste", title: "Journal" },
  "vanitas-enroll": { eyebrow: "Vanitas · Administration", title: "Ajouter un poste" },
  "vanitas-compliance": { eyebrow: "Vanitas · Supervision de poste", title: "Conformité" },
  "vanitas-vulnerabilities": { eyebrow: "Vanitas · Supervision de poste", title: "Vulnérabilités" },
  "vanitas-eol": { eyebrow: "Vanitas · Supervision de poste", title: "Logiciels obsolètes" },
  "vanitas-installers": { eyebrow: "Vanitas · Supervision de poste", title: "Applications" },
  "vanitas-profiles": { eyebrow: "Vanitas · Administration", title: "Profils" },
  "vanitas-docs": { eyebrow: "Vanitas", title: "Documentation" },
};

// Fallback affiché pendant le chargement du chunk d'une page (code-splitting, voir les imports
// `lazy` en haut) — réutilise `.loading-panel` déjà stylé, cohérent avec l'écran de connexion
// à l'API. Élément stable défini une fois au niveau module.
const TAB_FALLBACK = (
  <div className="loading-panel">
    <p>&gt; Chargement…</p>
  </div>
);

function formatStamp(date) {
  const d = date.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric" });
  const t = date.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
  return `généré le ${d} à ${t}`;
}

/**
 * Coquille applicative : charge les données une seule fois (useDashboardData), affiche
 * la sidebar de navigation façon Finary (voir Sidebar.jsx), et route vers l'onglet actif
 * sans refaire les appels API à chaque changement. Le masthead (eyebrow/titre/horodatage
 * LIVE) vit ici plutôt que dans App.jsx, car son contenu dépend de l'onglet actif.
 */
export default function Dashboard() {
  // Page "Paramètres" (2026-09-08) — modale, pas un onglet de nav : ni Intune ni Vanitas, une
  // propriété du compte connecté, orthogonale aux deux arbres de navigation existants.
  // `user`/`logout` ne sont plus lus ICI depuis le 2026-09-09 (déplacés dans le pied de la
  // sidebar, voir plus bas) — `SettingsModal` lit `user` lui-même via son propre `useAuth()`.
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  // Bascule "Tenant Intune" / "Vanitas" (2026-09-04, jalon 5, maquette approuvée) — état
  // SÉPARÉ de `activeTab` : les deux arbres de navigation (Sidebar/VanitasSidebar) gardent
  // chacun leur propre position, pas de conflit d'un côté si on va-et-vient de l'autre.
  const [source, setSource] = useState("intune");
  const [vanitasTab, setVanitasTab] = useState("vanitas-overview");
  const [stamp, setStamp] = useState(() => formatStamp(new Date()));
  const data = useDashboardData();
  // Recherche globale (2026-08-20, voir GlobalSearch.jsx) : `token` incrémente à CHAQUE
  // recherche, y compris si le texte tapé est identique au précédent (ex. deux clics de
  // suite sur la même CVE depuis un autre onglet) — sans lui, un `useEffect` côté onglet
  // cible gardé sur `[query]` seul ne redéclencherait rien la deuxième fois puisque la
  // dépendance n'aurait pas changé.
  const [searchNav, setSearchNav] = useState(null);
  // Navigation Vanitas avec payload (2026-09-11, voir bumpVanitasNav ci-dessus) — même motif
  // que `searchNav`, arbre séparé.
  const [vanitasNav, setVanitasNav] = useState(null);

  useEffect(() => {
    const id = setInterval(() => setStamp(formatStamp(new Date())), 60_000);
    return () => clearInterval(id);
  }, []);

  // Navigation partagée : change d'onglet et, si une `query` est fournie, arme
  // `searchNav` pour que l'onglet cible relance sa recherche via `initialQuery` (voir
  // VulnerabilitiesTab.jsx/DeviceOverviewTab.jsx). Sans query, c'est un simple changement
  // d'onglet — exactement le comportement de `onNavigate` depuis le 2026-08-12 (tuiles
  // "Signaux" de la Vue d'ensemble). `bumpSearchNav` (../navigation.js, extrait ici à la
  // revue de code du 2026-08-20 pour être testable sans jsdom) incrémente `token` à CHAQUE
  // appel avec une query, y compris si le texte est identique au précédent (ex. reclic sur
  // le même device) — sans lui, l'effet de l'onglet cible ne redéclencherait rien la
  // deuxième fois.
  function handleNavigate(tab, query) {
    // Toute navigation vers l'arbre Intune (recherche globale, tuiles "Signaux"...) doit
    // ramener sur "Tenant Intune" si "Vanitas" était actif — sinon la page cible serait
    // montée mais invisible, cachée derrière VanitasSidebar+VanitasActiveTab.
    setSource("intune");
    setActiveTab(tab);
    if (query) {
      setSearchNav((s) => bumpSearchNav(s, tab, query));
    }
  }

  // Navigation Vanitas avec payload (2026-09-11) — même esprit que `handleNavigate` mais pour
  // l'arbre Vanitas ("vanitas-*"), qui a son propre état de tab séparé (`vanitasTab`). Sans
  // `payload`, c'est un simple changement d'onglet (comportement inchangé de l'ancien
  // `onNavigateVanitas={setVanitasTab}`) — `bumpVanitasNav` incrémente `token` à chaque appel,
  // y compris vers la même cible, pour que la page cible redéclenche son effet à chaque clic.
  function handleNavigateVanitas(tab, payload) {
    setVanitasTab(tab);
    if (payload) {
      setVanitasNav((n) => bumpVanitasNav(n, tab, payload));
    }
  }

  // Aiguillage CVE vs nom d'appareil délégué à ../navigation.js::resolveSearchTab (pas de
  // troisième recherche réimplémentée ici — uniquement un aiguillage vers les deux qui
  // existent déjà, voir le compte-rendu de revue globale du 2026-08-20, point 3.5 : "un
  // point d'entrée commun", pas une nouvelle page dédiée).
  function handleGlobalSearch(rawQuery) {
    const trimmed = rawQuery.trim();
    if (!trimmed) return;
    handleNavigate(resolveSearchTab(trimmed), trimmed);
  }

  // Bouton "Rafraîchir" (2026-08-28, demande de Nicolas — "au-dessus du texte généré le") :
  // `data.refresh()` (useDashboardData.js) invalide le cache partagé et relance les 8 appels
  // du Promise.all, puis on rebascule `stamp` sur l'instant présent — sans ce 2e appel,
  // l'horodatage resterait figé sur le chargement de page initial malgré des données
  // fraîchement re-fetchées, contradictoire avec ce que "généré le" est censé décrire.
  // Rail de la sidebar (2026-10-21) : bouton Paramètres + bouton/raccourci "Rechercher" qui
  // donne simplement le focus au champ de recherche globale du masthead (pas de seconde
  // recherche). `useCallback` : `focusGlobalSearch` est une dépendance de l'effet clavier
  // (Ctrl K) de Sidebar.jsx, inutile de le réabonner à chaque rendu.
  const openSettings = useCallback(() => setSettingsOpen(true), []);
  const focusGlobalSearch = useCallback(() => {
    const input = document.querySelector(".global-search-input");
    if (input) input.focus();
  }, []);

  async function handleRefresh() {
    await data.refresh();
    setStamp(formatStamp(new Date()));
  }

  let content;
  if (source === "vanitas") {
    // Arbre Vanitas totalement séparé : ne dépend jamais de `data`/`data.loading` (données
    // Intune), chaque page Vanitas charge la sienne via ses propres hooks
    // (useDashboardData.js) — pas de raison d'attendre l'un pour afficher l'autre.
    const VanitasActiveTab = VANITAS_TABS[vanitasTab] ?? VanitasOverviewTab;
    content = (
      <ErrorBoundary resetKey={vanitasTab}>
        <Suspense fallback={TAB_FALLBACK}>
          <VanitasActiveTab
            onNavigate={handleNavigate}
            onNavigateVanitas={handleNavigateVanitas}
            vanitasNav={vanitasNav && vanitasNav.tab === vanitasTab ? vanitasNav : null}
          />
        </Suspense>
      </ErrorBoundary>
    );
  } else if (data.loading) {
    content = (
      <div className="loading-panel">
        <p>&gt; Connexion à l'API locale…</p>
        <p className="hint">GET http://localhost:8000/api/… — voir la console de `python api_server.py` en cas d'attente longue.</p>
      </div>
    );
  } else if (data.error) {
    // Message reformulé pour rester lisible même quand `data.error` est un message brut de
    // fetch/navigateur (souvent en anglais) — le texte technique original reste affiché en
    // dessous, pour ne rien cacher au diagnostic (revue de code frontend, 💡 suggestion #12).
    const { text, raw } = friendlyErrorMessage(data.error);
    content = (
      <div className="fatal-error-panel">
        <p>&gt; Impossible de joindre l'API locale : {text}</p>
        {raw !== text && <p className="hint">Détail technique : {raw}</p>}
        <p className="hint">Vérifie que `python api_server.py` tourne bien sur le port 8000.</p>
      </div>
    );
  } else {
    const ActiveTab = TABS[activeTab] ?? OverviewTab;
    // `onNavigate` ajouté le 2026-08-12 pour le redesign de la Vue d'ensemble : ses nouvelles
    // tuiles "Signaux" (Secure Score/Suivi CVE/ANSSI/Widgets) renvoient vers la page complète
    // correspondante en un clic (sans query). Depuis le 2026-08-20, les lignes de "Top
    // devices à risque"/"Nouveaux devices" l'utilisent AVEC une query (nom de device) pour
    // sauter sur la fiche Appareil déjà chargée — `handleNavigate` gère les deux cas. Les
    // autres onglets reçoivent la prop mais l'ignorent simplement (aucun n'en a besoin
    // aujourd'hui) — pas de branchement par onglet ici.
    // `initialQuery` n'est consommé que par VulnerabilitiesTab/DeviceOverviewTab (seuls
    // onglets cibles possibles d'une navigation avec query, voir handleNavigate ci-dessus) —
    // les autres le reçoivent et l'ignorent, comme `onNavigate` déjà aujourd'hui. Filtré sur
    // `searchNav.tab === activeTab` : si l'utilisateur change d'onglet MANUELLEMENT ensuite,
    // l'ancienne recherche ne doit pas se redéclencher au retour sur cet onglet.
    content = (
      <ErrorBoundary resetKey={activeTab}>
        <Suspense fallback={TAB_FALLBACK}>
          <ActiveTab
            data={data}
            onNavigate={handleNavigate}
            initialQuery={searchNav && searchNav.tab === activeTab ? searchNav : null}
          />
        </Suspense>
      </ErrorBoundary>
    );
  }

  const titles =
    source === "vanitas"
      ? VANITAS_TAB_TITLES[vanitasTab] ?? VANITAS_TAB_TITLES["vanitas-overview"]
      : TAB_TITLES[activeTab] ?? TAB_TITLES.overview;

  return (
    <div className="app-shell">
      {/* Sidebar unifiée (refonte du 2026-10-21, voir Sidebar.jsx) : un seul composant pour les
          deux mondes — le rail bascule `source`, la colonne affiche l'arbre du monde actif. */}
      <Sidebar
        source={source}
        onSourceChange={setSource}
        active={activeTab}
        vanitasActive={vanitasTab}
        onSelect={setActiveTab}
        onSelectVanitas={setVanitasTab}
        onOpenSettings={openSettings}
        onOpenSearch={focusGlobalSearch}
        stamp={stamp}
      />
      <div className="main-content">
        {/* `dossier--wide` (2026-08-20, demande de Nicolas : "on utilise pas assez les
            cotés et tout est centré") : Vue d'ensemble, Conformité Intune, Secure Score,
            Alertes Defender, Appareil (vue 360°) ET Application déployée (2026-08-25, même
            demande reformulée : "qu'il utilise plus l'espace pas forcement full centre")
            ont chacune un rail latéral fixe (`.ov2-layout`/`.intune-layout`/
            `.securescore-layout`/`.alerts-layout`/`.device360-layout`/`.deployed-layout`,
            voir OverviewTab.jsx/IntuneTab.jsx/SecureScoreTab.jsx/WidgetsTestTab.jsx/
            DeviceOverviewTab.jsx/DeployedAppsTab.jsx) qui a besoin de cette largeur
            supplémentaire — les autres onglets gardent le conteneur standard à 1360px pour
            ne pas déplacer leur mise en page sans raison. "app-catalog" ajouté le 2026-08-26
            (retour de Nicolas : "comme les autres pages, quelque chose qui utilise plus les
            côtés") pour la grille de cartes de la bibliothèque, voir AppCatalogTab.jsx.
            "app-edit" (2026-08-26, même jour, retour de Nicolas : "le même principe que le
            catalogue des applications pour les lister") ajouté pour la même raison — son
            sélecteur d'application est passé à la même grille de cartes. "cve-watch"
            (2026-08-28, retour de Nicolas sur l'accordéon d'évidences par device : "agrandi le
            tableau si besoin tu peux prendre plus de place sur la longueur de la page") ajouté
            pour la même raison — voir CveWatchTab.jsx. "vulnerabilities" (2026-09-02, même
            demande reformulée : "on peut pas plus utiliser l'espace un peu comme on a fait sur
            les autres pages") ajouté pour la même raison — voir VulnerabilitiesTab.jsx
            (`.vuln-layout`, bandeau KPI + table + rail ANSSI). "device-inventory" (2026-09-02,
            nouvel onglet dès sa création — voir DeviceInventoryTab.jsx). */}
        <div
          className={`dossier${
            source === "vanitas" ||
            [
              "overview",
              "intune",
              "secure-score",
              "widgets-test",
              "device-overview",
              "device-inventory",
              "app-deployed",
              "app-catalog",
              "app-edit",
              "cve-watch",
              "vulnerabilities",
            ].includes(activeTab)
              ? " dossier--wide"
              : ""
          }`}
        >
          <header className="masthead">
            <div>
              {/* Badge encadré (2026-09-09, retour de Nicolas sur les accroches "La boîte est
                  ouverte."/"Rien n'échappe." : "il manque l'encadré") — même motif que
                  `.card-head h2`/`.nav-panel-group-label` déjà établi ailleurs dans ce
                  dashboard (mono/uppercase, fond+bordure+texte teintés), jamais appliqué à
                  cet `.eyebrow` avant (resté un simple texte gris depuis sa création). Ambre
                  pour Pandore (`--amber`, l'accent déjà en place partout côté Intune),
                  bleu/teal pour Vanitas (`--hud-accent`, cohérent avec le rail replié). */}
              <p className={`eyebrow${source === "vanitas" ? " eyebrow-vanitas" : " eyebrow-pandore"}`}>{titles.eyebrow}</p>
              <h1>{titles.title}</h1>
            </div>
            {/* La recherche globale a été essayée en plein milieu du masthead, puis collée
                au titre à gauche — Nicolas voulait en fait qu'elle reste avec l'horodatage
                à droite ("avec le texte à droite 'généré le...'"). `.masthead-meta-row`
                regroupe recherche + horodatage dans le même bloc droit, poussé à l'extrémité
                par le `space-between` du masthead. */}
            {/* 2026-10-21 (demande de Nicolas, "on peut mettre les deux à côté ?") : recherche et
                bouton "Rafraîchir" sur une même ligne (`.masthead-actions`), l'horodatage en
                dessous. L'ancien sélecteur "Pandore" / "Vanitas" (`.source-toggle`) qui occupait
                ce bloc a été retiré le même jour : doublon du rail de la sidebar unifiée. */}
            <div className="masthead-meta-row">
              <div className="masthead-actions">
                <GlobalSearch onSearch={handleGlobalSearch} />
                {/* Bouton "Rafraîchir" (2026-08-28) — rend "jamais re-fetchées automatiquement"
                    (note ci-dessous) "jamais SAUF sur demande explicite". `data.refreshing`
                    (useDashboardData.js) désactive le bouton et change son libellé pendant
                    l'appel — un clic pendant un rafraîchissement déjà en cours ne relance rien
                    de plus (cachedCall partage la même promesse en vol). */}
                <button
                  type="button"
                  className="masthead-refresh-btn"
                  onClick={handleRefresh}
                  disabled={data.refreshing}
                  aria-label="Rafraîchir les données du dashboard"
                >
                  <IconRefresh />
                  {data.refreshing ? "Rafraîchissement…" : "Rafraîchir"}
                </button>
              </div>
              <div className="meta">
                <div>
                  {/* Anciennement "● LIVE" : trompeur, seule l'horloge ci-dessous se rafraîchit
                      (setInterval 60s) — les données du dashboard, elles, ne sont chargées qu'une
                      fois au montage (useDashboardData) et jamais re-fetchées automatiquement
                      SAUF clic explicite sur "Rafraîchir" ci-dessus (2026-08-28). Un utilisateur
                      laissant l'onglet ouvert pouvait croire voir des données à jour en continu
                      alors qu'elles datent du dernier chargement/rafraîchissement (revue de code
                      du 2026-08-17). `stamp` reste honnête : "généré le J/M/A à HH:MM" décrit cet
                      instant précis, pas un flux continu. */}
                  <span className="stamp">●</span> {stamp}
                </div>
                {/* Compte connecté + déconnexion : déplacés dans le pied de la sidebar
                    (2026-09-09, refonte du rail repliable — voir Sidebar.jsx/
                    VanitasSidebar.jsx) — redondants ici depuis (retour de Nicolas :
                    capture du masthead avec, juste en dessous, la même chose déjà dans la
                    sidebar). `settingsOpen` reste porté par Dashboard.jsx (source de vérité
                    unique de la modale), ouverte via `onOpenSettings` passé aux deux
                    sidebars plutôt que depuis un bouton du masthead. */}
                {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
              </div>
            </div>
          </header>
          {/* `dashboard-grid--tight` (2026-08-20) : resserre le gap entre blocs sur
              Conformité Intune seulement (mockup approuvé, retour de Nicolas : "trop
              d'espace entre les blocs") — les autres onglets gardent le gap standard de
              `.dashboard-grid`, partagée par tous. */}
          <main className={`dashboard-grid${activeTab === "intune" ? " dashboard-grid--tight" : ""}`}>
            {content}
          </main>
        </div>
      </div>
    </div>
  );
}
