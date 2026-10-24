import { Fragment } from "react";
import { tr } from "../i18n/core.js";

/**
 * Briques de rendu de la documentation Vanitas (refonte du 2026-10-24). Le contenu vit dans
 * vanitasDocsContent.fr.js / .en.js sous forme de données ; ce fichier sait l'afficher :
 * mise en forme en ligne (`**gras**`, `` `code` ``) avec surlignage des termes recherchés, blocs
 * (paragraphe, liste, encadrés, glossaire) et schémas numérotés de l'écran décrit.
 *
 * Les schémas ne sont PAS des captures d'écran ni des reconstitutions au pixel près (les
 * anciennes illustrations reproduisaient les tableaux d'avant la refonte et se sont démodées
 * avec elle) : une silhouette de la mise en page — bandeau, liste, détail — portant des repères
 * numérotés, expliqués par la légende de chaque section. Ils survivent à un changement de style
 * tant que la structure de la page ne change pas.
 */

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function highlight(text, query, keyPrefix) {
  if (!query) return text;
  const parts = text.split(new RegExp(`(${escapeRegExp(query)})`, "gi"));
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <mark key={`${keyPrefix}-${i}`} className="vdc-mark">
        {part}
      </mark>
    ) : (
      <Fragment key={`${keyPrefix}-${i}`}>{part}</Fragment>
    )
  );
}

/** `**gras**` et `` `code` `` ; le reste est du texte brut (jamais de HTML injecté). */
export function Inline({ text, query }) {
  const tokens = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return tokens.map((t, i) => {
    if (t.startsWith("**") && t.endsWith("**")) return <b key={i}>{highlight(t.slice(2, -2), query, i)}</b>;
    if (t.startsWith("`") && t.endsWith("`")) return <code key={i}>{highlight(t.slice(1, -1), query, i)}</code>;
    return <Fragment key={i}>{highlight(t, query, i)}</Fragment>;
  });
}

/** Texte brut d'une section (sans balisage), pour la recherche plein texte. */
export function sectionText(section) {
  const parts = [section.title, section.what, section.do, section.perm, section.caption, ...(section.legend ?? [])];
  for (const b of section.body ?? []) {
    if (b.p) parts.push(b.p);
    if (b.list) parts.push(...b.list);
    if (b.warn) parts.push(b.warn.title, b.warn.text);
    if (b.high) parts.push(b.high.title, b.high.text);
    if (b.terms) parts.push(...b.terms.flat());
  }
  return parts.filter(Boolean).join("\n").replace(/\*\*|`/g, "");
}

export function countMatches(section, query) {
  if (!query) return 0;
  return (sectionText(section).match(new RegExp(escapeRegExp(query), "gi")) ?? []).length;
}

export function Block({ block, query }) {
  if (block.p) {
    return (
      <p>
        <Inline text={block.p} query={query} />
      </p>
    );
  }
  if (block.list) {
    return (
      <ul>
        {block.list.map((item, i) => (
          <li key={i}>
            <Inline text={item} query={query} />
          </li>
        ))}
      </ul>
    );
  }
  if (block.warn || block.high) {
    const c = block.warn ?? block.high;
    return (
      <div className={`vdc-callout ${block.high ? "high" : "warn"}`}>
        <p className="vdc-callout-title">
          <Inline text={c.title} query={query} />
        </p>
        <p>
          <Inline text={c.text} query={query} />
        </p>
      </div>
    );
  }
  if (block.terms) {
    return (
      <dl className="vdc-terms">
        {block.terms.map(([term, def]) => (
          <Fragment key={term}>
            <dt>
              <Inline text={term} query={query} />
            </dt>
            <dd>
              <Inline text={def} query={query} />
            </dd>
          </Fragment>
        ))}
      </dl>
    );
  }
  return null;
}



function Bar({ w = "100%", tone }) {
  return <span className={`vdc-bar${tone ? ` ${tone}` : ""}`} style={{ width: w }} />;
}

function ListSkeleton({ marker, segmented }) {
  return (
    <div className="vdc-pane">
      {segmented ? (
        <span className="vdc-segm">
          <i className="on" />
          <i />
        </span>
      ) : (
        <span className="vdc-pane-lbl">{tr("vdoc.schema.list")}</span>
      )}
      <div className="vdc-row">
        {marker}
        <Bar w="70%" />
      </div>
      <div className="vdc-row sel">
        <Bar w="82%" tone="accent" />
      </div>
      <div className="vdc-row">
        <Bar w="60%" />
      </div>
    </div>
  );
}

/** Silhouette numérotée de l'écran décrit. Les repères suivent l'ordre de `legend`. */
export function Schema({ type, caption, markers = Infinity }) {
  if (!type || type === "none") return null;
  // Un repère sans entrée de légende dans la section n'est pas dessiné (place gardée).
  const Num = ({ n }) => (n > markers ? <span className="vdc-num-gap" /> : <span className="vdc-num">{n}</span>);
  let body;
  if (type === "split" || type === "switch") {
    body = (
      <>
        <div className="vdc-band">
          <Num n={1} />
          <Bar w="18%" />
          <Bar w="40%" tone="split" />
          <Bar w="14%" />
        </div>
        <div className="vdc-cols">
          <ListSkeleton marker={<Num n={2} />} segmented={type === "switch"} />
          <div className="vdc-pane">
            <span className="vdc-pane-lbl">{tr("vdoc.schema.detail")}</span>
            <div className="vdc-row">
              <Num n={3} />
              <Bar w="66%" />
            </div>
            <div className="vdc-row">
              <Bar w="90%" />
            </div>
            <div className="vdc-row">
              <Num n={4} />
              <span className="vdc-btn" />
            </div>
          </div>
        </div>
      </>
    );
  } else if (type === "bento") {
    body = (
      <>
        <div className="vdc-band vdc-tiles">
          <Num n={1} />
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <span key={i} className="vdc-tile" />
          ))}
        </div>
        <div className="vdc-cols wide">
          <div className="vdc-pane vdc-grid">
            <Num n={2} />
            <span className="vdc-block" />
            <span className="vdc-block tall" />
            <span className="vdc-block" />
          </div>
          <div className="vdc-pane">
            <Num n={3} />
            <span className="vdc-block sm" />
            <span className="vdc-block sm" />
          </div>
        </div>
      </>
    );
  } else if (type === "cards") {
    body = (
      <>
        <div className="vdc-band">
          <Num n={1} />
          <Bar w="20%" />
          <Bar w="20%" />
          <Bar w="20%" />
        </div>
        <div className="vdc-band">
          <Num n={2} />
          <span className="vdc-chip on" />
          <span className="vdc-chip" />
          <span className="vdc-chip" />
        </div>
        <div className="vdc-cardgrid">
          <Num n={3} />
          {[0, 1, 2].map((i) => (
            <span key={i} className="vdc-cardsk" />
          ))}
        </div>
      </>
    );
  } else if (type === "flow") {
    body = (
      <div className="vdc-cols">
        <div className="vdc-pane">
          {[1, 2, 3].map((n) => (
            <div key={n} className="vdc-row">
              <Num n={n} />
              <Bar w={n === 3 ? "85%" : "60%"} tone={n === 3 ? "accent" : undefined} />
            </div>
          ))}
        </div>
        <div className="vdc-pane">
          <Num n={4} />
          <span className="vdc-block sm dashed" />
          <span className="vdc-block sm" />
        </div>
      </div>
    );
  }
  return (
    <figure className="vdc-schema">
      <div className="vdc-schema-frame" aria-hidden="true">
        {body}
      </div>
      {caption && <figcaption>{caption}</figcaption>}
    </figure>
  );
}
