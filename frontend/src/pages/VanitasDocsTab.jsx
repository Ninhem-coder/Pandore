import { useEffect, useRef, useState } from "react";
import { getLang, tr } from "../i18n/core.js";
import VanitasDocsEn from "./VanitasDocsEn.jsx";
import VanitasDocsFr from "./VanitasDocsFr.jsx";
import { SECTIONS } from "./vanitasDocsParts.jsx";

/**
/**
 * "Vanitas" > Documentation (2026-09-10, demande de Nicolas — "une documentation utilisateur
 * complète, pro, qui ne ressemble pas à quelqu'un qui écrit par IA"). Page de référence pure,
 * aucune donnée chargée depuis le serveur : un sommaire à ancres (à gauche, collant) et un
 * texte suivi par domaine fonctionnel (à droite). Accessible à tout compte ayant un accès
 * Vanitas quelconque (`requires: { any: true }`, VanitasSidebar.jsx), pas réservée aux admins
 * — un compte lecture seule a lui aussi besoin de comprendre ce qu'il regarde.
 *
 * Rédigée à la main comme un vrai guide interne, pas une liste de fonctionnalités : chaque
 * section explique le POURQUOI d'un mécanisme (garde-fou d'activation des règles de
 * conformité, groupes statiques vs dynamiques...) en plus du comment, avec des mises en garde
 * explicites sur les points sensibles du produit (terminal, déploiement, cycle de vie d'un
 * poste) plutôt que de les traiter comme n'importe quel autre bouton.
 *
 * Refonte du 2026-09-14 (retour de Nicolas — "ça ne ressemble pas et ce n'est pas assez
 * détaillé, j'ai les postes mais quand je clique dessus ça me donne quoi") : chaque section
 * décrit maintenant explicitement ce qui se passe AU CLIC (panes, boutons, conséquences réelles
 * des actions), pas seulement l'écran de premier niveau. La fiche poste (section "Les postes")
 * a en plus une illustration à onglets réellement cliquables (`DeviceDetailPreview`), seule
 * section pour laquelle l'investissement se justifiait vu la profondeur de la fiche réelle
 * (11 panes) — les autres sections gardent des illustrations statiques mais enrichies, pour ne
 * pas transformer cette page en mini-application parallèle à maintenir.
 */
export default function VanitasDocsTab() {
  const [activeSection, setActiveSection] = useState(SECTIONS[0].id);
  // Ignore le scroll-spy pendant l'animation `scrollIntoView` déclenchée par un clic dans le
  // sommaire (2026-09-10, retour de Nicolas : le sommaire restait bloqué sur "Présentation"
  // même en ayant défilé jusqu'à "Conformité" — `activeSection` n'était en fait mis à jour
  // QU'au clic, jamais par le défilement naturel de la page). Sans ce garde-fou, le scroll
  // programmatique traverserait plusieurs sections en chemin et le scroll-spy réécrirait
  // `activeSection` sur une section intermédiaire avant que l'animation n'arrive à destination.
  const suppressSpyRef = useRef(false);
  const suppressTimerRef = useRef(null);

  function handleTocClick(id) {
    suppressSpyRef.current = true;
    setActiveSection(id);
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
    clearTimeout(suppressTimerRef.current);
    suppressTimerRef.current = setTimeout(() => {
      suppressSpyRef.current = false;
    }, 700);
  }

  // Scroll-spy : la section "active" du sommaire suit la lecture, pas seulement le dernier
  // clic. Technique classique (pas d'IntersectionObserver ici, dont le comportement par lots
  // devient ambigu quand plusieurs sections sont visibles à la fois) — à chaque défilement, la
  // section active est la DERNIÈRE dont le haut a franchi une ligne fixée à 25% de la hauteur
  // de la fenêtre, en partant du haut de la page.
  useEffect(() => {
    const sectionEls = SECTIONS.map((s) => document.getElementById(s.id)).filter(Boolean);
    function onScroll() {
      if (suppressSpyRef.current) return;
      const anchor = window.innerHeight * 0.25;
      let current = sectionEls[0]?.id;
      for (const el of sectionEls) {
        if (el.getBoundingClientRect().top <= anchor) current = el.id;
      }
      setActiveSection((prev) => (prev === current ? prev : current));
    }
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div className="vanitas-hud vanitas-docs">
      <div className="vanitas-docs-layout">
        <nav className="vanitas-docs-toc" aria-label={tr("vdoc.tocAria")}>
          <p className="vanitas-docs-toc-title">{tr("vdoc.toc")}</p>
          <ul>
            {SECTIONS.map((s) => (
              <li key={s.id}>
                <button
                  type="button"
                  className={activeSection === s.id ? "active" : ""}
                  onClick={() => handleTocClick(s.id)}
                >
                  {s.label}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        <div className="vanitas-docs-content">{getLang() === "en" ? <VanitasDocsEn /> : <VanitasDocsFr />}</div>
      </div>
    </div>
  );
}
