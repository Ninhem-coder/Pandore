import { useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "../AuthContext.jsx";
import { VANITAS_NAV, isVanitasNavItemVisible } from "../components/VanitasSidebar.jsx";
import { getLang, tr } from "../i18n/core.js";
import CONTENT_EN from "./vanitasDocsContent.en.js";
import CONTENT_FR from "./vanitasDocsContent.fr.js";
import { Block, Inline, Schema, countMatches } from "./vanitasDocsParts.jsx";

const GROUP_ORDER = ["start", "overview", "security", "inventory", "admin", "reference"];

/** Entrées de navigation Vanitas à plat (clé de page → entrée avec `requires`), pour ne proposer
 * « Ouvrir la page » que si le compte peut réellement l'ouvrir — même règle que la barre latérale. */
function flatNav() {
  const map = new Map();
  for (const entry of VANITAS_NAV) {
    for (const item of entry.items ?? [entry]) if (item.key) map.set(item.key, item);
  }
  return map;
}

/**
 * "Vanitas" > Documentation (2026-09-10, demande de Nicolas — "une documentation utilisateur
 * complète, pro, qui ne ressemble pas à quelqu'un qui écrit par IA"). Page de référence pure,
 * aucune donnée chargée depuis le serveur, accessible à tout compte ayant un accès Vanitas.
 * Rédigée comme un guide interne : chaque section explique le POURQUOI d'un mécanisme en plus du
 * comment, avec des mises en garde explicites sur les points sensibles (terminal, déploiement,
 * cycle de vie d'un poste). Refonte du 2026-09-14 : chaque section décrit ce qui se passe AU CLIC.
 *
 * Refonte du 2026-10-24 (maquette canvas validée par Nicolas), après la refonte des écrans
 * Vanitas la même semaine — l'ancien texte et ses illustrations décrivaient des tableaux et des
 * popups qui n'existaient plus, et quatre pages n'avaient aucune section (Logiciels obsolètes,
 * Applications déployées, Mises à jour, Ajouter un poste) :
 * - contenu en DONNÉES (vanitasDocsContent.fr.js / .en.js) plutôt qu'en JSX, pour la recherche
 *   plein texte et l'affichage section par section ;
 * - sommaire regroupé comme le menu Vanitas, badge « nouveau » sur les sections ajoutées,
 *   nombre d'occurrences par section pendant une recherche ;
 * - une section à la fois : « Ouvrir la page → » (si le compte y a accès), encadré « En bref »
 *   (à quoi ça sert / ce qu'on y fait / droits), schéma numéroté + légende, texte, Précédent /
 *   Suivant. La section affichée est mémorisée dans l'URL (#section) pour pouvoir la partager.
 * Classes `.vdc-*`.
 */
export default function VanitasDocsTab({ onNavigateVanitas }) {
  const { user } = useAuth();
  const sections = getLang() === "en" ? CONTENT_EN : CONTENT_FR;
  const [activeId, setActiveId] = useState(() => {
    const hash = typeof window !== "undefined" ? window.location.hash.slice(1) : "";
    return sections.some((s) => s.id === hash) ? hash : sections[0].id;
  });
  const [query, setQuery] = useState("");
  const articleRef = useRef(null);
  const nav = useMemo(flatNav, []);

  const q = query.trim();
  const matches = useMemo(() => {
    const m = new Map();
    if (q.length >= 2) for (const s of sections) m.set(s.id, countMatches(s, q));
    return m;
  }, [sections, q]);
  const hitSections = [...matches.values()].filter(Boolean).length;

  const idx = Math.max(0, sections.findIndex((s) => s.id === activeId));
  const section = sections[idx];
  const prev = sections[idx - 1] ?? null;
  const next = sections[idx + 1] ?? null;
  const navItem = section.page ? nav.get(section.page) : null;
  const canOpen = Boolean(navItem && onNavigateVanitas && user && isVanitasNavItemVisible(navItem, user));

  function open(id) {
    setActiveId(id);
    try {
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}#${id}`);
    } catch {
      // Navigateur restreint — la section n'est simplement pas partageable par lien.
    }
    articleRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Pendant une recherche, ouvre la première section qui contient le terme si celle affichée
  // n'en contient aucun.
  useEffect(() => {
    if (q.length < 2 || !hitSections || matches.get(activeId)) return;
    const first = sections.find((s) => matches.get(s.id));
    if (first) setActiveId(first.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);

  // L'ancre #section ne concerne que cette page : retirée en la quittant, pour ne pas traîner
  // dans l'URL des autres pages Vanitas.
  useEffect(
    () => () => {
      try {
        if (window.location.hash) window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      } catch {
        // Navigateur restreint — sans conséquence.
      }
    },
    []
  );

  const hl = q.length >= 2 ? q : "";

  return (
    <div className="vanitas-hud vdc">
      <div className="vdc-layout">
        <nav className="vdc-card vdc-toc" aria-label={tr("vdoc.tocAria")}>
          <label className="vdc-search-wrap">
            <span className="vdc-sr">{tr("vdoc.search")}</span>
            <input type="search" className="vdc-search" placeholder={tr("vdoc.search")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
          </label>
          {q.length >= 2 && (
            <span className="vdc-sub vdc-small" aria-live="polite">
              {hitSections ? tr("vdoc.hits", { count: hitSections, query: q }) : tr("vdoc.noHit", { query: q })}
            </span>
          )}
          {GROUP_ORDER.map((g) => {
            const items = sections.filter((s) => s.group === g);
            if (!items.length) return null;
            return (
              <div key={g} className="vdc-toc-group">
                <span className="vdc-lbl">{tr(`vdoc.group.${g}`)}</span>
                <ul>
                  {items.map((s) => {
                    const n = matches.get(s.id) ?? 0;
                    const dim = q.length >= 2 && !n;
                    return (
                      <li key={s.id}>
                        <button
                          type="button"
                          className={`${s.id === section.id ? "on" : ""}${dim ? " dim" : ""}`}
                          aria-current={s.id === section.id ? "page" : undefined}
                          onClick={() => open(s.id)}
                        >
                          <span>{s.title}</span>
                          {q.length >= 2 ? n > 0 && <span className="vdc-hit">{n}</span> : s.tag === "new" && <span className="vdc-tag">{tr("vdoc.tag.new")}</span>}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            );
          })}
          <span className="vdc-sub vdc-small vdc-updated">{tr("vdoc.updated")}</span>
        </nav>

        <article ref={articleRef} className="vdc-card vdc-sec" aria-labelledby="vdc-title">
          <div className="vdc-sec-head">
            <div className="vdc-sec-title">
              <span className="vdc-crumb">{tr(`vdoc.group.${section.group}`)}</span>
              <h2 id="vdc-title">{section.title}</h2>
            </div>
            {canOpen && (
              <button type="button" className="vanitas-queue-btn" onClick={() => onNavigateVanitas(section.page)}>
                {tr("vdoc.openPage")}
              </button>
            )}
          </div>

          <div className="vdc-brief">
            <div>
              <span className="vdc-lbl accent">{tr("vdoc.brief.what")}</span>
              <span>
                <Inline text={section.what} query={hl} />
              </span>
            </div>
            <div>
              <span className="vdc-lbl accent">{tr("vdoc.brief.do")}</span>
              <span>
                <Inline text={section.do} query={hl} />
              </span>
            </div>
            <div>
              <span className="vdc-lbl accent">{tr("vdoc.brief.perm")}</span>
              <span>
                <Inline text={section.perm} query={hl} />
              </span>
            </div>
          </div>

          <Schema type={section.schema} caption={section.caption} markers={section.legend?.length ?? 0} />
          {section.legend?.length > 0 && (
            <ol className="vdc-legend">
              {section.legend.map((text, i) => (
                <li key={i}>
                  <span className="vdc-num">{i + 1}</span>
                  <span>
                    <Inline text={text} query={hl} />
                  </span>
                </li>
              ))}
            </ol>
          )}

          <div className="vdc-prose">
            {section.body.map((b, i) => (
              <Block key={i} block={b} query={hl} />
            ))}
          </div>

          <div className="vdc-foot">
            {prev ? (
              <button type="button" className="vdc-nav" onClick={() => open(prev.id)}>
                <span className="vdc-lbl">{tr("vdoc.prev")}</span>
                <span>{prev.title}</span>
              </button>
            ) : (
              <span />
            )}
            {next && (
              <button type="button" className="vdc-nav next" onClick={() => open(next.id)}>
                <span className="vdc-lbl">{tr("vdoc.next")}</span>
                <span>{next.title}</span>
              </button>
            )}
          </div>
        </article>
      </div>
    </div>
  );
}
