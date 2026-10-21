import { useEffect, useMemo, useRef, useState } from "react";
import {
  isErrorPayload,
  useDeviceVulnerableSoftware,
  useExposureVulnerableApps,
  useSecureScore,
} from "../hooks/useDashboardData.js";
import MedallionGauge from "../components/MedallionGauge.jsx";
import Donut from "../components/Donut.jsx";
import SummaryCard from "../components/SummaryCard.jsx";
import { IconAlertTriangle, IconLaptop, IconShield, IconLayers, IconGrid, IconWrench } from "../components/icons.jsx";
import {
  CRITICALITY_LEVELS,
  EXPOSURE_LEVEL_COLORS,
  EXPOSURE_LEVEL_LABEL_FR,
  secureScoreLevel,
  SECURE_SCORE_CATEGORY_LABEL_FR,
  translateThreat,
} from "../theme.js";
import { computeSecureScoreQuickWins, computeSecureScoreAllControls } from "../selectors.js";

const BASIS_LABEL_FR = {
  AllTenants: "moyenne tous tenants",
  TotalSeats: "tenants comparables",
  IndustryTypes: "votre secteur",
};

const COST_LABEL_FR = { low: "faible", moderate: "moyen", high: "élevé" };

// Traduction de `actionType` (secureScoreControlProfiles) — vocabulaire Graph à 3 valeurs
// documentées (Config/Review/Behavior), affiché dans la popup de détail section "En quoi ça
// consiste" (2026-09-01). Une valeur non reconnue retombe sur la chaîne brute plutôt que de
// masquer l'info — même prudence que tierColor ci-dessous pour un champ jamais vérifié en
// direct sur ce tenant avant cette fonctionnalité.
const ACTION_TYPE_LABEL_FR = {
  Config: "Modification de configuration",
  Review: "Revue / vérification",
  Behavior: "Changement de comportement utilisateur",
};

// Couleurs indicatives par tier Graph (Core / Defense in Depth / Advanced) — comparaison
// insensible à la casse/aux espaces car la graphie exacte du champ n'a pas pu être vérifiée
// sur données réelles (permission SecurityEvents.Read.All accordée le 2026-08-12, tenant pas
// encore audité en détail) ; une valeur non reconnue retombe sur la couleur neutre plutôt que
// de planter ou d'afficher une pastille vide.
const TIER_COLOR_BY_KEYWORD = [
  { keyword: "core", color: "#48C98A" },
  { keyword: "defense", color: "#E7A33C" },
  { keyword: "advanced", color: "#7C8896" },
];
function tierColor(tier) {
  const key = (tier || "").toLowerCase();
  return TIER_COLOR_BY_KEYWORD.find((t) => key.includes(t.keyword))?.color || "#6B6E76";
}

// Icône par catégorie du référentiel complet (2026-08-12, refonte "façon Par criticité"
// demandée par Nicolas) — mêmes clés que SECURE_SCORE_CATEGORY_LABEL_FR (theme.js).
const CATEGORY_ICON = {
  Identity: IconShield,
  Data: IconLayers,
  Device: IconLaptop,
  Apps: IconGrid,
  Infrastructure: IconWrench,
};

/** Chemin SVG ligne + aire (fermée sur la base) pour le tracé de tendance du score
 * (2026-08-31, maquette validée par Nicolas — "Tendance du score") — refermé pour permettre
 * un remplissage en dégradé, dupliqué localement plutôt qu'exporté depuis IntuneTab.jsx (même
 * fonction que `buildTrendPaths` là-bas) pour ne pas coupler deux pages sans rapport.
 */
function buildScoreTrendPath(values, w, h) {
  if (!values || values.length === 0) return null;
  if (values.length === 1) {
    const y = h / 2;
    return { line: `M0,${y} L${w},${y}`, area: `M0,${y} L${w},${y} L${w},${h} L0,${h} Z` };
  }
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - ((v - min) / span) * h;
    return [x, y];
  });
  const line = "M" + pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" L");
  return { line, area: `${line} L${w.toFixed(1)},${h} L0,${h} Z` };
}

/** Flèche de tendance du score — un score qui monte est toujours une bonne nouvelle
 * (`goodWhenUp` fixe, contrairement à `TrendArrowBadge` d'IntuneTab.jsx qui doit gérer les
 * deux sens selon la métrique). Composant dédié plutôt qu'importé : même raisonnement que
 * `buildScoreTrendPath` ci-dessus. */
function ScoreTrendArrow({ delta }) {
  if (delta == null) return null;
  const up = delta > 0;
  const color = delta === 0 ? "var(--ink-dim)" : up ? "var(--low)" : "var(--high)";
  return (
    <span className="secure-score-trend-delta" style={{ color }}>
      <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {up ? <path d="M10 15V5M5 10l5-5 5 5" /> : <path d="M10 5v10M5 10l5 5 5-5" />}
      </svg>
      {delta > 0 ? "+" : ""}
      {delta} pt
    </span>
  );
}

/** Pastille de tier (Core/Defense in Depth/Advanced) — affichée telle que renvoyée par
 * Graph, jamais traduite (voir tierColor ci-dessus : la graphie exacte n'est pas garantie). */
function TierBadge({ tier }) {
  if (!tier) return null;
  const color = tierColor(tier);
  return (
    <span className="cve-badge secure-score-tier-badge" style={{ borderColor: `${color}66`, color }}>
      {tier}
    </span>
  );
}

/** Menaces couvertes par un contrôle (threats de secureScoreControlProfiles) — la partie la
 * plus directement utile pour un profil cybersécurité junior : POURQUOI ce contrôle compte,
 * pas seulement combien de points il rapporte. Ajouté le 2026-08-12, demande de Nicolas. */
function ThreatTags({ threats }) {
  if (!threats || threats.length === 0) return null;
  return (
    <div className="secure-score-threat-tags">
      {threats.map((t) => (
        <span className="secure-score-threat-tag" key={t}>
          {translateThreat(t)}
        </span>
      ))}
    </div>
  );
}

// Même garde-fou que `AnssiCard.jsx`/`VulnerabilitiesTab.jsx` (revue de sécurité du
// 2026-09-02) — dupliqué ici plutôt que partagé, convention déjà en place sur ce dashboard
// pour ce genre de petit utilitaire (voir `hashString` ailleurs). Un `href` posé tel quel dans
// un attribut React depuis une donnée Graph (`rec.actionUrl`, ou le lien extrait par
// `parseRemediationText` ci-dessous) sans vérifier le schéma laisserait un `javascript:`/
// `data:` s'exécuter au clic si ce champ contenait un jour une valeur inattendue.
function isSafeHttpUrl(value) {
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

/**
 * Extrait un lien `<a href='...'>texte</a>` (parfois enveloppé dans `<b>`) d'un texte de
 * remédiation Graph — le champ `remediation` de `secureScoreControlProfiles` contient parfois
 * du HTML brut LITTÉRAL au lieu d'être interprété (bug confirmé par capture d'écran de
 * Nicolas le 2026-09-01 : "&lt;b&gt; &lt;a href=...&gt;" affiché tel quel). Parsing contrôlé
 * par regex plutôt que `dangerouslySetInnerHTML` — Graph n'est pas une source à injecter telle
 * quelle, même si le risque XSS réel est faible ici (donnée d'un tenant qu'on administre déjà).
 * Renvoie `{ before, href, label, after }` — `href`/`label` restent `null` si aucun lien n'est
 * trouvé (texte affiché intégralement via `before`, tags `<b>` simplement retirés).
 *
 * ⚠️ Revue de sécurité (2026-09-02) : `href` n'est accepté que s'il commence par `http://`/
 * `https://` — sans ce garde-fou, un champ `remediation` contenant `<a href="javascript:...">`
 * se serait retrouvé posé tel quel dans un vrai attribut `href` React (voir le rendu plus bas),
 * exécutable au clic. Le champ vient aujourd'hui du catalogue Microsoft Graph (pas d'une entrée
 * libre d'utilisateur), mais rien ne garantit que ça reste vrai indéfiniment — un lien au
 * schéma inattendu est traité comme "aucun lien trouvé" (texte intégral affiché, pas de `<a>`)
 * plutôt que rendu tel quel.
 */
function parseRemediationText(raw) {
  if (!raw) return null;
  const match = raw.match(/<a\s+href=['"]([^'"]+)['"][^>]*>([^<]*)<\/a>/i);
  const strip = (s) => s.replace(/<\/?b>/gi, "").replace(/\s+,/g, ",").replace(/\s{2,}/g, " ").trim();
  if (!match) return { before: strip(raw), href: null, label: null, after: "" };
  const [full, href, label] = match;
  const idx = raw.indexOf(full);
  const safeHref = isSafeHttpUrl(href) ? href : null;
  return {
    before: strip(raw.slice(0, idx)),
    href: safeHref,
    label: safeHref ? label.trim() : null,
    after: safeHref ? strip(raw.slice(idx + full.length)) : strip(raw.slice(idx)),
  };
}

/**
 * Une recommandation, cliquable pour ouvrir son détail complet dans une popup — quoi faire
 * concrètement (`remediation`), les menaces couvertes, en quoi consiste le contrôle et son
 * tier. Utilisée à la fois dans "Gains rapides" et dans le référentiel complet par catégorie
 * (2026-08-12, demande de Nicolas : il ne voulait pas seulement des points à gagner mais des
 * CONSEILS concrets sur quoi mettre en place).
 *
 * v3 (2026-09-01, maquette validée par Nicolas — "ça prend pas mal de place [...] on pourrait
 * pas le rendre cliquable et faire une pop-up") : n'est plus un accordéon qui pousse les
 * lignes suivantes vers le bas — le clic ouvre `ControlDetailModal` via `onOpen`, un seul
 * composant de détail partagé par les deux listes (voir SecureScoreTab).
 */
function RecommendationRow({ rec, rank, onOpen }) {
  return (
    <li className="secure-score-reco-item">
      <button type="button" className="secure-score-reco-row" onClick={() => onOpen(rec)}>
        <svg className="caret secure-score-reco-caret" viewBox="0 0 16 16" fill="none">
          <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        {rank != null && <span className="reco-rank">{String(rank).padStart(2, "0")}</span>}
        <div className="reco-main">
          <span className="reco-name">
            {rec.description}
            {rec.implemented && <span className="secure-score-implemented-badge">déjà en place</span>}
          </span>
          <span className="reco-meta">
            {SECURE_SCORE_CATEGORY_LABEL_FR[rec.category] || rec.category}
            {rec.implementationCost ? ` · coût ${COST_LABEL_FR[rec.implementationCost] || rec.implementationCost}` : ""}
            {rec.userImpact ? ` · impact ${COST_LABEL_FR[rec.userImpact] || rec.userImpact}` : ""}
          </span>
        </div>
        {rec.gap != null && rec.gap > 0 && <span className="reco-impact">+{rec.gap.toFixed(0)} pts</span>}
        {rec.tier && <TierBadge tier={rec.tier} />}
      </button>
    </li>
  );
}

/**
 * Popup de détail d'un contrôle — remplace l'accordéon en place de v2 (voir RecommendationRow
 * ci-dessus). Reprend TEL QUEL le chrome déjà en place ailleurs dans le dashboard
 * (`.wizard-overlay`/`.wizard-shell`/`.wizard-header`/`.wizard-step-body`/
 * `.deployed-detail-close` — DeployAppWizard.jsx, EditAppTab.jsx) plutôt qu'un nouveau motif
 * de popup, même comportement Échap/clic en dehors (identique à DeployAppWizard.jsx).
 *
 * 3 sections fixes (maquette validée le 2026-09-01, inspirée du portail Microsoft natif —
 * description/statut/impact/détails — et des plateformes GRC type Vanta/Drata) : ce que le
 * contrôle protège, en quoi il consiste, comment le mettre en place. Les 2 encarts "pas
 * encore branché" (portée sur le parc, historique) restent volontairement SANS chiffre
 * inventé — contrairement à la maquette (illustrative), afficher un nombre inexistant ici
 * serait pris pour une vraie donnée.
 */
function ControlDetailModal({ rec, onClose }) {
  const shellRef = useRef(null);

  useEffect(() => {
    if (!rec) return undefined;
    function handleKeyDown(e) {
      if (e.key === "Escape") onClose();
    }
    function handlePointerDown(e) {
      if (shellRef.current && !shellRef.current.contains(e.target)) onClose();
    }
    document.addEventListener("keydown", handleKeyDown);
    document.addEventListener("pointerdown", handlePointerDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("pointerdown", handlePointerDown);
    };
  }, [rec, onClose]);

  if (!rec) return null;

  const parsed = parseRemediationText(rec.remediation);
  const pct = rec.score != null && rec.maxScore ? Math.round((rec.score / rec.maxScore) * 100) : 0;

  return (
    <div className="wizard-overlay">
      <div className="wizard-shell" ref={shellRef} role="dialog" aria-modal="true" aria-label={rec.description}>
        <div className="wizard-header">
          <span className="wizard-header-icon">
            <IconShield />
          </span>
          <div className="wizard-header-text">
            <h2>{rec.description}</h2>
            <p className="card-note">
              {SECURE_SCORE_CATEGORY_LABEL_FR[rec.category] || rec.category}
              {rec.implementationCost ? ` · coût ${COST_LABEL_FR[rec.implementationCost] || rec.implementationCost}` : ""}
              {rec.userImpact ? ` · impact ${COST_LABEL_FR[rec.userImpact] || rec.userImpact}` : ""}
              {rec.tier ? " · " : ""}
              {rec.tier && <TierBadge tier={rec.tier} />}
            </p>
          </div>
          <button type="button" className="deployed-detail-close" onClick={onClose} aria-label="Fermer">
            <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        <div className="wizard-step-body">
          <div className="secure-score-detail-section secure-score-detail-sec-threat">
            <span className="secure-score-detail-section-icon">
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M10 2l7 3v5c0 4.5-3 7.5-7 8-4-.5-7-3.5-7-8V5l7-3z" />
              </svg>
            </span>
            <div className="secure-score-detail-section-body">
              <p className="secure-score-detail-section-title">Ce que ça protège</p>
              {rec.threats && rec.threats.length > 0 ? (
                <ThreatTags threats={rec.threats} />
              ) : (
                <p className="empty cve-small">Microsoft Graph ne renvoie aucune menace associée à ce contrôle.</p>
              )}
            </div>
          </div>

          <div className="secure-score-detail-section secure-score-detail-sec-what">
            <span className="secure-score-detail-section-icon">
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <rect x="3" y="3" width="14" height="14" rx="3" />
                <path d="M7 10h6M10 7v6" />
              </svg>
            </span>
            <div className="secure-score-detail-section-body">
              <p className="secure-score-detail-section-title">En quoi ça consiste</p>
              <p className="secure-score-detail-section-text">
                Microsoft ne fournit pas de description distincte du titre pour ce contrôle — le
                nom ci-dessus EST déjà la description. Ce que Graph ajoute réellement :
              </p>
              <div className="secure-score-detail-meta-chips">
                {rec.service && (
                  <span className="secure-score-detail-meta-chip">
                    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M4 10a6 6 0 1112 0 6 6 0 01-12 0z" />
                    </svg>
                    {rec.service}
                  </span>
                )}
                {rec.actionType && (
                  <span className="secure-score-detail-meta-chip">
                    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M10 3v14M3 10h14" />
                    </svg>
                    {ACTION_TYPE_LABEL_FR[rec.actionType] || rec.actionType}
                  </span>
                )}
                {!rec.service && !rec.actionType && (
                  <span className="empty cve-small">Aucune information supplémentaire renvoyée par Graph.</span>
                )}
              </div>
            </div>
          </div>

          <div className="secure-score-detail-section secure-score-detail-sec-how">
            <span className="secure-score-detail-section-icon">
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M4 10h12M10 4v12" />
              </svg>
            </span>
            <div className="secure-score-detail-section-body">
              <p className="secure-score-detail-section-title">Comment le mettre en place</p>
              {parsed ? (
                <p className="secure-score-remediation-text">
                  {parsed.before}
                  {parsed.href && (
                    <>
                      {" "}
                      <a className="secure-score-remediation-link" href={parsed.href} target="_blank" rel="noreferrer">
                        {parsed.label}
                      </a>
                    </>
                  )}
                  {parsed.after}
                </p>
              ) : (
                <p className="empty cve-small">
                  Microsoft Graph ne fournit pas de description de remédiation pour ce contrôle.
                </p>
              )}
              {rec.remediationImpact && (
                <div className="secure-score-detail-impact-callout">
                  <strong>Impact attendu</strong>
                  {rec.remediationImpact}
                </div>
              )}
              <div className="secure-score-detail-wip">
                <span className="secure-score-detail-wip-tag">Nouvelle capacité — pas encore branchée</span>
                <p className="secure-score-detail-wip-text">
                  <strong>Portée sur le parc :</strong> demanderait de croiser ce contrôle avec la
                  liste des appareils/comptes réellement concernés (comme "Conformité" le fait
                  déjà pour Intune) — Secure Score ne renvoie qu'un score agrégé côté Graph.
                </p>
              </div>
              {isSafeHttpUrl(rec.actionUrl) && (
                <a
                  className="secure-score-remediation-link secure-score-detail-action-link"
                  href={rec.actionUrl}
                  target="_blank"
                  rel="noreferrer"
                >
                  Ouvrir dans le centre d'administration Microsoft ↗
                </a>
              )}
            </div>
          </div>

          {rec.score != null && rec.maxScore != null && (
            <div className="secure-score-detail-score-footer">
              <span className="secure-score-detail-score-label">Score obtenu</span>
              <div className="secure-score-detail-score-track">
                <div className="secure-score-detail-score-fill" style={{ width: `${pct}%` }} />
              </div>
              <span className="secure-score-detail-score-value">
                {rec.score.toFixed(2)} / {rec.maxScore.toFixed(2)} pts
              </span>
            </div>
          )}

          <div className="secure-score-detail-wip">
            <span className="secure-score-detail-wip-tag">Nouvelle capacité — pas encore branchée</span>
            <p className="secure-score-detail-wip-text">
              <strong>Historique de ce contrôle :</strong> demanderait d'étendre l'instantané
              quotidien (aujourd'hui : score TOTAL seul) pour stocker le détail par contrôle
              chaque jour.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Une catégorie du référentiel complet (Identité/Données/Appareils/Apps/Infrastructure) —
 * v3 (2026-08-12, retour de Nicolas sur le rendu v2 : "ça fait bizarre" que la carte cliquée
 * s'agrandisse en place, même en pleine largeur — capture d'écran à l'appui montrant "Identité"
 * gonflée sous les 2 autres restées petites). Nicolas a demandé un modèle de sélection : les 4
 * cartes restent TOUJOURS identiques et compactes (plus aucune n'grandit jamais), cliquer
 * dessus les rend juste "actives" (contour ambre), et le détail des contrôles s'affiche dans
 * UNE zone dédiée fixe sous la grille entière — voir `CategoryDetailPanel` plus bas et son
 * usage dans `scoreContent`. Ce composant ne rend donc plus lui-même la liste de contrôles.
 * Icône teintée + %/barre de proportion colorés via `secureScoreLevel(donePct)` — même
 * sémantique que le médaillon et les carrés de catégorie du hero : vert = peu de travail
 * restant, rouge = beaucoup à corriger.
 */
function CategoryCard({ group, active, onSelect }) {
  const total = group.controls.length;
  const doneCount = total - group.toDoCount;
  const donePct = total > 0 ? Math.round((doneCount / total) * 100) : 0;
  const color = secureScoreLevel(donePct).color;
  const Icon = CATEGORY_ICON[group.category] || IconShield;
  const label = SECURE_SCORE_CATEGORY_LABEL_FR[group.category] || group.category;

  return (
    <div
      className={`card exposure-block secure-score-category-card${active ? " secure-score-category-card-active" : ""}`}
      style={{ "--os-color": color }}
    >
      <div className="exposure-block-top">
        <span className="exposure-block-icon" style={{ color }}>
          <Icon />
        </span>
        <div className="exposure-block-heading">
          <span className="exposure-block-label">{label}</span>
          <span className="card-note">
            {total} contrôle{total > 1 ? "s" : ""}
            {group.toDoCount > 0 ? ` · ${group.toDoCount} à corriger` : " · tous en place"}
          </span>
        </div>
      </div>
      <div className="exposure-block-bar-row">
        <span className="exposure-block-count" style={{ color }}>
          {donePct}%
        </span>
      </div>
      <div className="os-card-bar">
        <div className="os-card-bar-fill" style={{ width: `${Math.max(donePct, total > 0 ? 2 : 0)}%` }} />
      </div>

      <button type="button" className="exposure-block-toggle" onClick={onSelect} aria-pressed={active}>
        {active ? "Masquer les contrôles" : `Voir les ${total} contrôles`}
        <svg className="caret" viewBox="0 0 16 16" fill="none">
          <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
    </div>
  );
}

/**
 * Zone de détail FIXE sous la grille des 4 (ou 5) cartes catégorie (v3, 2026-08-12) — un seul
 * bloc qui affiche la liste des contrôles de la catégorie sélectionnée, plutôt qu'une carte
 * qui grandit en place. Les cartes ci-dessus restent donc toutes de la même taille en
 * permanence, seul le CONTENU de cette zone change quand on clique une carte différente —
 * plus de réagencement de grille surprenant à chaque clic.
 */
function CategoryDetailPanel({ group, onOpenControl }) {
  if (!group) {
    return (
      <div className="card secure-score-category-detail secure-score-category-detail-empty">
        <p className="empty">Clique une catégorie ci-dessus pour afficher ses contrôles ici.</p>
      </div>
    );
  }

  const total = group.controls.length;
  const label = SECURE_SCORE_CATEGORY_LABEL_FR[group.category] || group.category;
  const Icon = CATEGORY_ICON[group.category] || IconShield;

  return (
    <div className="card secure-score-category-detail">
      <div className="card-head">
        {/* Icône ajoutée devant le nom (2026-08-31, maquette validée par Nicolas : "sur le
            bloc du bas [...] mettre en plus le logo") — même glyphe que la carte sélecteur
            correspondante ci-dessus (CATEGORY_ICON, déjà partagé). `.secure-score-category-
            detail .card-head h2` passe en inline-flex pour l'accueillir (scopé à cette carte
            seule, même motif déjà établi par `.os-card .card-head h2` ailleurs dans ce
            fichier — jamais le `.card-head h2` global, qui reste un badge texte partout
            ailleurs dans le dashboard). */}
        <h2>
          <Icon />
          {label}
        </h2>
        <span className="card-note">
          {total} contrôle{total > 1 ? "s" : ""}
          {group.toDoCount > 0 ? ` · ${group.toDoCount} à corriger` : " · tous en place"}
        </span>
      </div>
      <ul className="reco-list secure-score-reco-list">
        {group.controls.map((rec) => (
          <RecommendationRow key={rec.controlName} rec={rec} onOpen={onOpenControl} />
        ))}
      </ul>
    </div>
  );
}

/**
 * Onglet "Secure Score" — sous-catégorie de Defender, à côté de "Conformité Intune" et
 * "Vulnérabilités" (voir Sidebar.jsx). A changé d'emplacement de navigation deux fois le
 * 2026-08-10 (sous-section de Conformité Intune, puis item de niveau 1 indépendant) avant
 * ce retour sous Defender, sur demande explicite de Nicolas à chaque étape.
 *
 * Distinct de l'Exposure Score MDE (onglet "Vue d'ensemble") : couvre tout le tenant M365
 * (Identité/Données/Appareils/Apps/Infrastructure), pas seulement les endpoints Defender —
 * son rattachement de navigation sous Defender est un choix d'organisation de l'utilisateur,
 * pas un reflet de sa portée fonctionnelle réelle.
 * Chargé à la demande (useSecureScore, même principe qu'useComplianceDetail) — jamais dans
 * useDashboardData, pour ne pas pénaliser le premier rendu des autres onglets.
 */
export default function SecureScoreTab({ data }) {
  // Sous-onglet "Par criticité" (2026-08-12, demande de Nicolas après validation du widget
  // "Répartition par niveau d'exposition" de l'onglet Widgets (test)) — vue indépendante du
  // score Microsoft Graph : ne dépend que de `data` (chargement global, déjà fait pour tous
  // les onglets) et de son propre hook lazy (useExposureVulnerableApps). Reste consultable
  // même si useSecureScore est en chargement/erreur (permission SecurityEvents.Read.All
  // manquante par ex.) — les deux vues n'ont aucune dépendance commune côté données.
  const [view, setView] = useState("score");
  const exposureApps = useExposureVulnerableApps();
  const deviceVulnApps = useDeviceVulnerableSoftware();

  const { loading, error, scoreHistory, controlProfiles } = useSecureScore(30);

  // Graph trie déjà secureScores du plus récent au plus ancien (voir docstring
  // intune/tools.py::get_secure_score) — le premier élément est le jour courant.
  const latest = scoreHistory[0] || null;
  const percentage =
    latest && typeof latest.currentScore === "number" && latest.maxScore
      ? Math.round((latest.currentScore / latest.maxScore) * 100)
      : null;

  // Série chronologique (plus ancien -> plus récent, pour un tracé de gauche à droite) —
  // sparkline affichée seulement au-delà d'un point, même règle que le skill
  // audit-exposure-score (une tendance à un seul point n'en est pas une).
  const trend = useMemo(
    () =>
      scoreHistory
        .filter((d) => typeof d.currentScore === "number" && d.maxScore)
        .map((d) => Math.round((d.currentScore / d.maxScore) * 100))
        .reverse(),
    [scoreHistory]
  );

  const quickWins = useMemo(
    () => computeSecureScoreQuickWins(latest?.controlScores, controlProfiles, { topN: 8 }),
    [latest, controlProfiles]
  );

  // Référentiel complet (2026-08-12, demande de Nicolas — page pensée comme une ressource de
  // bonnes pratiques cybersécurité, pas seulement une liste des 8 plus gros gains). Groupé par
  // catégorie, chaque contrôle du tenant apparaît, déjà en place ou non.
  const allControls = useMemo(
    () => computeSecureScoreAllControls(latest?.controlScores, controlProfiles),
    [latest, controlProfiles]
  );

  // Référentiel complet : une catégorie ouverte à la fois (accordéon, comme ComplianceOsGrid) —
  // choisit quelle liste de contrôles s'affiche dans CategoryDetailPanel, indépendant de la
  // popup de détail ci-dessous.
  const [openCategoryKey, setOpenCategoryKey] = useState(null);
  const toggleCategory = (key) => setOpenCategoryKey((prev) => (prev === key ? null : key));

  // Détail d'UN contrôle, affiché dans une popup — remplace l'accordéon en place de v2
  // (2026-09-01, "ça prend pas mal de place [...] pop-up") : un seul état partagé par les
  // deux listes ("Gains rapides" et "Référentiel complet"), qui portent toutes les deux le
  // même composant RecommendationRow — voir ControlDetailModal. Contient directement l'objet
  // `rec` (pas une clé à faire correspondre) : plus simple que l'ancien mécanisme par clé
  // (`controlName ?? index`), qui avait d'ailleurs été la source d'un bug le 2026-09-01 sur
  // le bouton "Meilleur gain" (clé posée sans son repli sur l'index).
  const [detailControl, setDetailControl] = useState(null);

  let scoreContent;

  if (loading) {
    scoreContent = (
      <div className="card">
        <div className="card-head">
          <h2>Secure score</h2>
        </div>
        <p className="empty">Interrogation de Microsoft Graph (security/secureScores)…</p>
      </div>
    );
  } else if (error) {
    scoreContent = (
      <div className="card">
        <div className="card-head">
          <h2>Secure score</h2>
        </div>
        <p className="error-note">
          {error}
          <br />
          Si l'erreur mentionne un statut 403 : vérifier que la permission Graph{" "}
          <code>SecurityEvents.Read.All</code> (Application) est bien accordée, avec
          consentement admin, sur l'app registration Intune — c'est un scope distinct de ceux
          déjà utilisés pour /deviceManagement et /users, à ajouter explicitement dans Entra.
        </p>
      </div>
    );
  } else if (!latest) {
    scoreContent = (
      <div className="card">
        <div className="card-head">
          <h2>Secure score</h2>
        </div>
        <p className="empty">Microsoft Graph n'a renvoyé aucune donnée pour ce tenant.</p>
      </div>
    );
  } else {
    const benchmarks = latest.averageComparativeScores || [];
    const industryBenchmark = benchmarks.find((b) => b.basis === "IndustryTypes");
    const industryBenchmarkPct =
      industryBenchmark && latest.maxScore ? Math.round((industryBenchmark.averageScore / latest.maxScore) * 100) : null;

    // Totaux dérivés du référentiel complet déjà calculé plus bas (allControls) — mêmes
    // chiffres que les cartes catégorie/`CategoryDetailPanel`, jamais une 2e source de vérité.
    const totalControls = allControls.reduce((sum, g) => sum + g.controls.length, 0);
    const todoControls = allControls.reduce((sum, g) => sum + g.toDoCount, 0);
    const doneControls = totalControls - todoControls;
    const doneControlsPct = totalControls > 0 ? Math.round((doneControls / totalControls) * 100) : null;
    const pointsToGain = Math.max(0, Math.round(latest.maxScore - latest.currentScore));
    // Delta vs le début de la fenêtre déjà chargée par useSecureScore(30) — pas un nouvel
    // appel, `trend` est déjà l'historique complet (le plus ancien en premier).
    const scoreDelta = trend.length > 1 ? percentage - trend[0] : null;
    // 300×80 — dimensions du rail (336px de large), pas la pleine largeur de la colonne
    // principale : voir le commentaire sur la carte "Tendance du score" plus bas, déplacée
    // dans le rail le 2026-09-01.
    const scoreTrendPath = buildScoreTrendPath(trend, 300, 80);
    const bestGain = quickWins[0] || null;

    scoreContent = (
      <div className="securescore-layout">
        <div className="securescore-main">
          {/* Refonte 2026-08-31 (maquette validée par Nicolas, "à l'identique") : le hero passe
              de 2 blocs (jauge + grille de 5 carrés catégorie) à 3 cartes — jauge/tendance,
              points à gagner, contrôles — la répartition par catégorie complète (carrés pleine
              taille) faisait doublon avec la grille "Référentiel complet" juste en dessous
              (retour explicite de Nicolas). Un rappel compact en pastilles avait été ajouté
              entre le hero et "Référentiel complet" le temps d'un aller-retour, puis retiré
              (2026-09-01, "tu peux enlever cette ligne ? Par catégorie...") : le détail par
              catégorie vit désormais UNIQUEMENT dans "Référentiel complet" plus bas, plus
              aucun rappel dans le hero. */}
          <section className="secure-score-hero-grid">
            <div className="card secure-score-hero secure-score-hero-compact">
              <MedallionGauge
                score={percentage}
                colorForScore={secureScoreLevel}
                suffix="%"
                ariaLabel={percentage != null ? `Secure score ${percentage} pourcent` : "Secure score indisponible"}
              />
              <div className="secure-score-hero-body">
                <p className="secure-score-kpi-label">Score actuel</p>
                <div className="secure-score-trend-row">
                  <ScoreTrendArrow delta={scoreDelta} />
                  <span className="secure-score-trend-period">vs il y a {trend.length} j</span>
                </div>
                <p className="secure-score-value">
                  {Math.round(latest.currentScore)}
                  <span> / {Math.round(latest.maxScore)} pts</span>
                </p>
                {benchmarks.length > 0 && (
                  <p className="secure-score-benchmark">
                    {benchmarks.map((b, i) => {
                      const pct = latest.maxScore ? Math.round((b.averageScore / latest.maxScore) * 100) : null;
                      return (
                        <span key={b.basis}>
                          {i > 0 ? " · " : ""}
                          {BASIS_LABEL_FR[b.basis] || b.basis} : {pct != null ? `${pct}%` : "—"}
                        </span>
                      );
                    })}
                  </p>
                )}
              </div>
            </div>

            <div className="card secure-score-kpi-card">
              <div className="secure-score-kpi-top">
                <div>
                  <p className="secure-score-kpi-label">Points à gagner</p>
                  <div className="secure-score-kpi-value">{pointsToGain}</div>
                </div>
                <span className="card-note secure-score-kpi-top-note">sur {Math.round(latest.maxScore)} pts</span>
              </div>
              <p className="secure-score-kpi-sub">
                {Math.round(latest.currentScore)} pts obtenus sur {Math.round(latest.maxScore)} au catalogue
              </p>
              <div className="secure-score-mini-bar">
                <span style={{ width: `${percentage ?? 0}%`, background: "var(--low)" }} />
                <span style={{ width: `${100 - (percentage ?? 0)}%`, background: "var(--high)" }} />
              </div>
              <p className="secure-score-mini-bar-legend">
                <span style={{ color: "var(--low)" }}>{Math.round(latest.currentScore)} pts acquis</span> ·{" "}
                <span style={{ color: "var(--high)" }}>{pointsToGain} pts restants</span>
              </p>
            </div>

            <div className="card secure-score-kpi-card">
              <div className="secure-score-kpi-top">
                <div>
                  <p className="secure-score-kpi-label">Contrôles</p>
                  <div className="secure-score-kpi-value">
                    {doneControls}
                    <span className="secure-score-kpi-value-total"> / {totalControls}</span>
                  </div>
                </div>
                <span className="card-note secure-score-kpi-top-note">en place</span>
              </div>
              {doneControlsPct != null && (
                <>
                  <p className="secure-score-kpi-sub">{doneControlsPct} % du référentiel appliqué</p>
                  <div className="secure-score-mini-bar">
                    <span style={{ width: `${doneControlsPct}%`, background: "var(--low)" }} />
                    <span style={{ width: `${100 - doneControlsPct}%`, background: "var(--high)" }} />
                  </div>
                  <p className="secure-score-mini-bar-legend">
                    <span style={{ color: "var(--low)" }}>{doneControls} en place</span> ·{" "}
                    <span style={{ color: "var(--high)" }}>{todoControls} à corriger</span>
                  </p>
                </>
              )}
            </div>
          </section>

          {/* Référentiel complet (2026-08-12, refonte "façon Par criticité" demandée par
              Nicolas, puis v3 sur son retour "ça fait bizarre" — voir doc de CategoryCard) :
              tous les contrôles du catalogue Graph rapprochés du score du jour, groupés par
              catégorie. Les 4/5 cartes restent toujours de la même taille (simples
              sélecteurs) ; le détail de la catégorie sélectionnée s'affiche dans
              `CategoryDetailPanel`, une zone fixe sous la grille — jamais une carte qui
              grandit en place. */}
          {allControls.length > 0 && (
            <>
              <p className="section-title">
                Référentiel complet — {allControls.reduce((sum, g) => sum + g.controls.length, 0)}{" "}
                contrôles Microsoft Secure Score, par catégorie
              </p>
              <div className="secure-score-category-grid">
                {allControls.map((group) => (
                  <CategoryCard
                    key={group.category}
                    group={group}
                    active={openCategoryKey === group.category}
                    onSelect={() => toggleCategory(group.category)}
                  />
                ))}
              </div>
              <CategoryDetailPanel
                group={allControls.find((g) => g.category === openCategoryKey) || null}
                onOpenControl={setDetailControl}
              />
            </>
          )}
        </div>

        {/* "Gains rapides" déplacé dans le rail (2026-08-20, même principe que la Vue
            d'ensemble/Conformité Intune, mockup validé par Nicolas) : c'est le même classement
            "top recommandations" que Vue d'ensemble (RecommendationsList, données Defender) —
            ce contenu est donc déjà secondaire par nature, exactement ce qu'un rail latéral de
            contexte doit porter. Toujours déplié ici (le repli en bannière n'avait de sens que
            quand ce bloc vivait dans le flux principal, pour ne pas y occuper une pleine carte)
            — un rail se lit déjà "en périphérie", donc masquer son propre contenu derrière un
            clic supplémentaire n'apporterait plus rien (ancien `quickWinsOpen`/bouton
            `secure-score-quickwins-toggle` retirés en conséquence). */}
        <aside className="securescore-rail">
          {/* "Meilleur gain" (2026-08-31, maquette validée par Nicolas) : met en avant LE
              contrôle le plus rentable (déjà en tête de `quickWins`, trié par écart de points
              décroissant) avant même la liste complète juste en dessous — même principe que
              "Correctif recommandé" sur la page Conformité. Cliquer ouvre directement la popup
              de détail sur ce contrôle (`setDetailControl(bestGain)`, même état partagé que le
              reste des listes — voir ControlDetailModal) plutôt que de scroller vers une table
              lointaine comme sur Conformité. */}
          {bestGain && (
            <>
              <p className="securescore-rail-title">Meilleur gain</p>
              <div className="card secure-score-bestgain-card">
                <div className="secure-score-bestgain-icon">
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M10 2.5v3M10 14.5v3M3.5 10h3M13.5 10h3M5.6 5.6l2.1 2.1M12.3 12.3l2.1 2.1M14.4 5.6l-2.1 2.1M7.7 12.3l-2.1 2.1" />
                    <circle cx="10" cy="10" r="2.3" />
                  </svg>
                </div>
                <p>
                  <strong>{bestGain.description}</strong>
                </p>
                <p className="secure-score-bestgain-impact">
                  +{bestGain.gap.toFixed(1)} pts
                  {bestGain.implementationCost ? ` · coût ${COST_LABEL_FR[bestGain.implementationCost] || bestGain.implementationCost}` : ""}
                  {bestGain.userImpact ? ` · impact ${COST_LABEL_FR[bestGain.userImpact] || bestGain.userImpact}` : ""}
                </p>
                <button
                  type="button"
                  className="secure-score-bestgain-link"
                  onClick={() => setDetailControl(bestGain)}
                >
                  Voir la marche à suivre
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M7 4l6 6-6 6" />
                  </svg>
                </button>
              </div>
            </>
          )}

          {/* "Tendance du score" déplacée dans le rail (2026-09-01, retour de Nicolas : "mettre
              le bloc sur la tendance du score à droite [...] le rendre moins grand plus adapté
              pour le format à droite") — restructurée en colonne unique (plus de chart+stats
              côte à côte, pas la place à 336px) : le tracé garde exactement les mêmes données
              (`scoreTrendPath`, `trend`), juste un viewBox plus étroit/plus bas
              (`buildScoreTrendPath(trend, 300, 80)` au lieu de 460×96) et les 2 statistiques
              latérales passées sous le graphique, côte à côte plutôt qu'empilées. */}
          {scoreTrendPath && (
            <>
              <p className="securescore-rail-title">Tendance du score</p>
              <div className="card secure-score-trend-card">
                <div className="secure-score-trend-chart-wrap">
                  <svg viewBox="0 0 300 80" preserveAspectRatio="none">
                    <defs>
                      <linearGradient id="scoreTrendFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="rgba(72,201,138,0.30)" />
                        <stop offset="100%" stopColor="rgba(72,201,138,0)" />
                      </linearGradient>
                    </defs>
                    <line x1="0" y1="20" x2="300" y2="20" stroke="var(--line)" strokeWidth="1" />
                    <line x1="0" y1="40" x2="300" y2="40" stroke="var(--line)" strokeWidth="1" />
                    <line x1="0" y1="60" x2="300" y2="60" stroke="var(--line)" strokeWidth="1" />
                    <path fill="url(#scoreTrendFill)" d={scoreTrendPath.area} />
                    <path fill="none" stroke="var(--low)" strokeWidth="2" d={scoreTrendPath.line} />
                  </svg>
                  <div className="secure-score-trend-legend">
                    <span>
                      {trend[0]} % il y a {trend.length} j
                    </span>
                    <span style={{ color: "var(--low)" }}>{percentage} % aujourd'hui</span>
                  </div>
                </div>
                <div className="secure-score-trend-stats">
                  <div className="secure-score-trend-stat">
                    Tendance
                    <strong className={scoreDelta > 0 ? "up" : scoreDelta < 0 ? "down" : ""}>
                      {scoreDelta != null ? `${scoreDelta > 0 ? "+" : ""}${scoreDelta} pt` : "—"}
                    </strong>
                  </div>
                  {industryBenchmarkPct != null && (
                    <div className="secure-score-trend-stat">
                      Moy. secteur
                      <strong>{industryBenchmarkPct} %</strong>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          <p className="securescore-rail-title">Gains rapides</p>
          <div className="card securescore-rail-card">
            <p className="card-note secure-score-quickwins-note">
              {quickWins.length} contrôle{quickWins.length > 1 ? "s" : ""} · déjà visibles dans Vue
              d'ensemble
            </p>
            {quickWins.length === 0 ? (
              <p className="empty">
                Aucun gain calculable pour l'instant — le catalogue des contrôles n'a pas pu être
                rapproché des scores du jour (voir l'avertissement de jointure dans
                selectors.js::computeSecureScoreQuickWins, à vérifier sur données réelles).
              </p>
            ) : (
              <>
                <p className="card-note secure-score-hint">
                  Clique une ligne pour voir la marche à suivre et les menaces couvertes.
                </p>
                <ul className="reco-list">
                  {quickWins.map((q, i) => (
                    <RecommendationRow key={q.controlName ?? i} rec={q} rank={i + 1} onOpen={setDetailControl} />
                  ))}
                </ul>
              </>
            )}
          </div>
        </aside>
      </div>
    );
  }

  return (
    <>
      <div className="secure-score-subtabs">
        <button
          type="button"
          className={`secure-score-subtab${view === "score" ? " active" : ""}`}
          onClick={() => setView("score")}
        >
          Score
        </button>
        <button
          type="button"
          className={`secure-score-subtab${view === "criticite" ? " active" : ""}`}
          onClick={() => setView("criticite")}
        >
          Par criticité
        </button>
      </div>
      {view === "score" ? scoreContent : (
        <CriticiteView data={data} exposureApps={exposureApps} deviceVulnApps={deviceVulnApps} />
      )}
      <ControlDetailModal rec={detailControl} onClose={() => setDetailControl(null)} />
    </>
  );
}

/** Pastille de niveau d'exposition (High/Medium/Low) — bordure/texte/point colorés par
 * EXPOSURE_LEVEL_COLORS, réutilisée par le classement logiciels ET la table de postes. */
function CriticiteLevelBadge({ level }) {
  if (!level) return null;
  const color = EXPOSURE_LEVEL_COLORS[level] || EXPOSURE_LEVEL_COLORS.Unknown;
  const label = EXPOSURE_LEVEL_LABEL_FR[level] || level;
  return (
    <span className="criticite-level-badge" style={{ borderColor: color, color }}>
      <span className="dot" style={{ background: color }} />
      {label}
    </span>
  );
}

/**
 * Sous-onglet "Par criticité". v3 (2026-09-01, maquette validée par Nicolas — même langage
 * que les refontes "Conformité"/"Secure Score" : hero + classement par impact + table
 * filtrable + rail avec correctif recommandé) — remplace les 3 blocs empilés High/Medium/Low
 * (chacun avec son propre accordéon, v2) par une vue transversale :
 *   1. Hero (3 cartes, réutilise `.secure-score-hero-*` du sous-onglet "Score" — même page,
 *      même langage visuel) : jauge "Score d'exposition maîtrisée" (synthèse DÉRIVÉE, pas un
 *      champ Graph/Defender — voir `masteredPct`), KPI "Exposition élevée", KPI "Logiciels
 *      vulnérables".
 *   2. "Top logiciels vulnérables — tous niveaux confondus" : fusionne les top-5 PAR NIVEAU
 *      déjà renvoyés par l'API (`get_top_vulnerable_apps_by_exposure`, `topN=5` — AUCUNE
 *      nouvelle route backend) — les 3 niveaux sont maintenant chargés au MONTAGE plutôt qu'au
 *      clic d'un bloc (v2), seul moyen de construire ce classement transversal ; reste bon
 *      marché (3 clés possibles au total, déjà documenté comme tel sur
 *      `useExposureVulnerableApps`). Classé par nombre total d'appareils, barre 3 segments
 *      (répartition High/Medium/Low). Clique une ligne → popup (chemins d'évidence + devices).
 *   3. Table de postes (tous niveaux), filtrable par recherche + niveau — remplace les 3
 *      listes de devices empilées, plus lisible sur un parc de plusieurs centaines de
 *      machines. Clique un poste → popup avec son détail par logiciel (chargé à la demande,
 *      `useDeviceVulnerableSoftware`, inchangé).
 *   4. Rail : résumé + donut (inchangés) + "Correctif recommandé" (réutilise
 *      `.secure-score-bestgain-*` — même carte que "Meilleur gain" côté sous-onglet "Score").
 *
 * ⚠️ "Logiciels vulnérables" (hero) ne compte QUE les logiciels apparus dans le top 5 d'AU
 * MOINS un des 3 niveaux (jusqu'à 15 avant dédoublonnage) — PAS l'inventaire complet du
 * tenant, que cet endpoint ne renvoie pas. Libellé explicite ("top 5 par niveau") pour ne
 * jamais laisser croire à un chiffre exhaustif.
 */
function CriticiteView({ data, exposureApps, deviceVulnApps }) {
  const defenderError = isErrorPayload(data.defenderSummary) ? data.defenderSummary : null;
  const machines = Array.isArray(data.machines) ? data.machines : [];
  const totalMachines =
    typeof data.defenderSummary?.totalMachines === "number" ? data.defenderSummary.totalMachines : null;

  useEffect(() => {
    for (const level of CRITICALITY_LEVELS) exposureApps.ensureLoaded(level);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const devicesByLevel = useMemo(() => {
    const map = {};
    for (const level of CRITICALITY_LEVELS) {
      map[level] = machines.filter((m) => !m?.error && m.exposureLevel === level);
    }
    return map;
  }, [machines]);

  const totalExposed = CRITICALITY_LEVELS.reduce((sum, level) => sum + devicesByLevel[level].length, 0);
  const highCount = devicesByLevel.High?.length || 0;
  const mediumCount = devicesByLevel.Medium?.length || 0;
  const lowCount = devicesByLevel.Low?.length || 0;
  // "Maîtrisée" = part du parc SANS exposition élevée ni moyenne — synthèse dérivée pour ce
  // dashboard, pas un pourcentage renvoyé tel quel par Defender (contrairement au Secure
  // Score/taux de conformité, qui eux sont des champs Graph directs).
  const masteredCount = totalMachines != null ? Math.max(0, totalMachines - highCount - mediumCount) : null;
  const masteredPct = totalMachines ? Math.round((masteredCount / totalMachines) * 100) : null;

  const softwareLoading = CRITICALITY_LEVELS.some((l) => !exposureApps.state[l] || exposureApps.state[l].loading);
  const softwareAllErrored = CRITICALITY_LEVELS.every((l) => exposureApps.state[l]?.error);
  const topSoftware = useMemo(() => {
    const map = new Map();
    for (const level of CRITICALITY_LEVELS) {
      const rows = exposureApps.state[level]?.data || [];
      for (const app of rows) {
        const key = `${app.software_vendor}::${app.software_name}`;
        const entry = map.get(key) || {
          software_vendor: app.software_vendor,
          software_name: app.software_name,
          cve_count: 0,
          byLevel: {},
          paths: new Set(),
          device_names: new Set(),
        };
        entry.cve_count = Math.max(entry.cve_count, app.cve_count || 0);
        entry.byLevel[level] = (entry.byLevel[level] || 0) + (app.device_count || 0);
        (app.paths || []).forEach((p) => entry.paths.add(p));
        (app.device_names || []).forEach((n) => entry.device_names.add(n));
        map.set(key, entry);
      }
    }
    return [...map.values()]
      .map((e) => ({
        ...e,
        totalDevices: Object.values(e.byLevel).reduce((s, n) => s + n, 0),
        dominantLevel: CRITICALITY_LEVELS.find((l) => e.byLevel[l] > 0) || null,
        paths: [...e.paths],
        device_names: [...e.device_names],
      }))
      .sort((a, b) => b.totalDevices - a.totalDevices);
  }, [exposureApps.state]);

  const [deviceSearch, setDeviceSearch] = useState("");
  const [deviceLevelFilter, setDeviceLevelFilter] = useState("all");
  const allDevices = useMemo(
    () => CRITICALITY_LEVELS.flatMap((level) => devicesByLevel[level].map((d) => ({ ...d, level }))),
    [devicesByLevel]
  );
  const filteredDevices = useMemo(() => {
    const q = deviceSearch.trim().toLowerCase();
    return allDevices.filter(
      (d) =>
        (deviceLevelFilter === "all" || d.level === deviceLevelFilter) &&
        (!q || (d.computerDnsName || "").toLowerCase().includes(q))
    );
  }, [allDevices, deviceSearch, deviceLevelFilter]);

  // Popup de détail, partagée logiciel/device — même motif que ControlDetailModal du
  // sous-onglet "Score" (chrome `.wizard-overlay`/`.wizard-shell` réutilisé tel quel).
  const [modal, setModal] = useState(null);

  function openDeviceModal(d) {
    const machineId = d.id ?? d.computerDnsName;
    deviceVulnApps.ensureLoaded(machineId);
    setModal({ kind: "device", device: d, machineId });
  }

  const bestSoftware = topSoftware[0] || null;

  return (
    <>
      <section className="secure-score-hero-grid">
        <div className="card secure-score-hero secure-score-hero-compact">
          <MedallionGauge
            score={masteredPct}
            colorForScore={secureScoreLevel}
            suffix="%"
            ariaLabel={masteredPct != null ? `Score d'exposition maîtrisée ${masteredPct} pourcent` : "Indisponible"}
          />
          <div className="secure-score-hero-body">
            <p className="secure-score-kpi-label">Score d'exposition maîtrisée</p>
            <p className="secure-score-value">
              {masteredCount ?? "—"}
              <span> / {totalMachines ?? "—"} appareils</span>
            </p>
            <div className="os-dots">
              <span className="os-dot-chip">
                <span className="dot" style={{ background: EXPOSURE_LEVEL_COLORS.High }} />
                {highCount} élevée
              </span>
              <span className="os-dot-chip">
                <span className="dot" style={{ background: EXPOSURE_LEVEL_COLORS.Medium }} />
                {mediumCount} moyenne
              </span>
              <span className="os-dot-chip">
                <span className="dot" style={{ background: EXPOSURE_LEVEL_COLORS.Low }} />
                {lowCount} faible
              </span>
            </div>
          </div>
        </div>

        <div className="card secure-score-kpi-card">
          <div className="secure-score-kpi-top">
            <div>
              <p className="secure-score-kpi-label">Exposition élevée</p>
              <div className="secure-score-kpi-value">{highCount}</div>
            </div>
            <span className="card-note secure-score-kpi-top-note">à traiter en priorité</span>
          </div>
          <p className="secure-score-kpi-sub">
            {totalExposed > 0 ? Math.round((highCount / totalExposed) * 100) : 0} % des {totalExposed} appareils
            exposés
          </p>
          <div className="secure-score-mini-bar">
            <span style={{ width: `${totalExposed > 0 ? (highCount / totalExposed) * 100 : 0}%`, background: "var(--high)" }} />
            <span style={{ width: `${totalExposed > 0 ? 100 - (highCount / totalExposed) * 100 : 100}%`, background: "var(--line)" }} />
          </div>
        </div>

        <div className="card secure-score-kpi-card">
          <div className="secure-score-kpi-top">
            <div>
              <p className="secure-score-kpi-label">Logiciels vulnérables</p>
              <div className="secure-score-kpi-value">{topSoftware.length}</div>
            </div>
            <span className="card-note secure-score-kpi-top-note">top 5 par niveau</span>
          </div>
          <p className="secure-score-kpi-sub">
            {bestSoftware
              ? `${bestSoftware.software_name} en tête (${bestSoftware.totalDevices} appareils)`
              : softwareLoading
              ? "Chargement…"
              : "Aucune donnée pour l'instant"}
          </p>
        </div>
      </section>

      <div className="criticite-layout">
        <div className="criticite-main">
          <div className="card">
            <div className="card-head">
              <h2>Top logiciels vulnérables — tous niveaux confondus</h2>
              <span className="card-note">
                {topSoftware.length} logiciel{topSoftware.length > 1 ? "s" : ""}
              </span>
            </div>
            {softwareLoading ? (
              <p className="card-note">Chargement…</p>
            ) : topSoftware.length === 0 ? (
              softwareAllErrored ? (
                <p className="error-note">Impossible de charger le classement (les 3 niveaux ont échoué).</p>
              ) : (
                <p className="empty">Aucun logiciel vulnérable détecté sur les 3 niveaux.</p>
              )
            ) : (
              <>
                <p className="card-note secure-score-hint">
                  Clique une ligne pour voir les chemins d'évidence et les appareils concernés.
                </p>
                <ul className="reco-list">
                  {topSoftware.map((s, i) => (
                    <li className="secure-score-reco-item" key={`${s.software_vendor}::${s.software_name}`}>
                      <button
                        type="button"
                        className="secure-score-reco-row"
                        onClick={() => setModal({ kind: "software", entry: s })}
                      >
                        <span className="reco-rank">{String(i + 1).padStart(2, "0")}</span>
                        <div className="reco-main">
                          <span className="reco-name">{s.software_name}</span>
                          <span className="reco-meta">
                            {s.software_vendor} · {s.cve_count} CVE
                          </span>
                          <span className="criticite-split-bar">
                            {CRITICALITY_LEVELS.map((level) => (
                              <span
                                key={level}
                                style={{
                                  width: `${s.totalDevices > 0 ? ((s.byLevel[level] || 0) / s.totalDevices) * 100 : 0}%`,
                                  background: EXPOSURE_LEVEL_COLORS[level],
                                }}
                              />
                            ))}
                          </span>
                        </div>
                        <span className="reco-impact" style={{ color: "var(--ink)" }}>
                          {s.totalDevices}
                        </span>
                        <CriticiteLevelBadge level={s.dominantLevel} />
                      </button>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>

          <div className="card">
            <div className="card-head">
              <h2>Postes par niveau d'exposition</h2>
              <span className="card-note">
                {filteredDevices.length} / {allDevices.length} affichés
              </span>
            </div>
            <div className="filter-bar">
              <input
                className="filter-input"
                type="text"
                placeholder="Rechercher un appareil…"
                value={deviceSearch}
                onChange={(e) => setDeviceSearch(e.target.value)}
              />
              <div className="criticite-level-filter">
                <button
                  type="button"
                  className={`criticite-level-chip${deviceLevelFilter === "all" ? " active" : ""}`}
                  onClick={() => setDeviceLevelFilter("all")}
                >
                  Tous
                </button>
                {CRITICALITY_LEVELS.map((level) => (
                  <button
                    key={level}
                    type="button"
                    className={`criticite-level-chip${deviceLevelFilter === level ? " active" : ""}`}
                    style={
                      deviceLevelFilter === level
                        ? {
                            borderColor: EXPOSURE_LEVEL_COLORS[level],
                            color: EXPOSURE_LEVEL_COLORS[level],
                            background: `color-mix(in srgb, ${EXPOSURE_LEVEL_COLORS[level]} 12%, transparent)`,
                          }
                        : undefined
                    }
                    onClick={() => setDeviceLevelFilter(level)}
                  >
                    <span className="dot" style={{ background: EXPOSURE_LEVEL_COLORS[level] }} />
                    {EXPOSURE_LEVEL_LABEL_FR[level]}
                  </button>
                ))}
              </div>
            </div>
            {allDevices.length === 0 ? (
              <p className="empty">Aucun appareil exposé.</p>
            ) : (
              <div className="criticite-device-table-wrap">
                <table className="criticite-device-table">
                  <thead>
                    <tr>
                      <th>Appareil</th>
                      <th>OS</th>
                      <th>Niveau</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredDevices.length === 0 ? (
                      <tr>
                        <td colSpan={3} className="empty">
                          Aucun appareil pour ce filtre.
                        </td>
                      </tr>
                    ) : (
                      filteredDevices.map((d, i) => (
                        <tr key={d.id ?? d.computerDnsName ?? i} onClick={() => openDeviceModal(d)}>
                          <td className="name">{d.computerDnsName ?? "Device inconnu"}</td>
                          <td className="os">{d.osPlatform ?? "—"}</td>
                          <td>
                            <CriticiteLevelBadge level={d.level} />
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        <aside className="criticite-rail">
          <p className="criticite-rail-title">Résumé</p>
          <div className="strip exposure-summary-strip">
            <SummaryCard
              icon={<IconAlertTriangle />}
              title="Exposition élevée"
              value={highCount}
              hint={`device${highCount > 1 ? "s" : ""} à traiter en priorité`}
              tone={highCount > 0 ? "danger" : "good"}
            />
            <SummaryCard
              icon={<IconLaptop />}
              title="Devices exposés"
              value={totalExposed}
              hint="exposition non nulle (Faible/Moyenne/Élevée)"
            />
          </div>

          {defenderError ? (
            <div className="card exposure-summary-donut">
              <div className="card-head">
                <h2>Répartition par niveau d'exposition</h2>
              </div>
              <p className="error-note">{defenderError.message}</p>
            </div>
          ) : (
            <div className="exposure-summary-donut">
              <Donut
                title="Répartition par niveau d'exposition"
                note="exposureLevel — /api/machines"
                data={data.defenderSummary?.byExposureLevel}
                colors={EXPOSURE_LEVEL_COLORS}
                labels={EXPOSURE_LEVEL_LABEL_FR}
              />
            </div>
          )}

          {bestSoftware && (
            <>
              <p className="criticite-rail-title">Correctif recommandé</p>
              <div className="card secure-score-bestgain-card">
                <div className="secure-score-bestgain-icon">
                  <svg
                    viewBox="0 0 20 20"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.7"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <path d="M10 2.5v3M10 14.5v3M3.5 10h3M13.5 10h3M5.6 5.6l2.1 2.1M12.3 12.3l2.1 2.1M14.4 5.6l-2.1 2.1M7.7 12.3l-2.1 2.1" />
                    <circle cx="10" cy="10" r="2.3" />
                  </svg>
                </div>
                <p>
                  <strong>{bestSoftware.software_name}</strong>
                </p>
                <p className="secure-score-bestgain-impact">
                  {bestSoftware.totalDevices} appareils · {bestSoftware.cve_count} CVE
                  {totalExposed > 0 ? ` · ${Math.round((bestSoftware.totalDevices / totalExposed) * 100)} % des exposés` : ""}
                </p>
                <button
                  type="button"
                  className="secure-score-bestgain-link"
                  onClick={() => setModal({ kind: "software", entry: bestSoftware })}
                >
                  Voir le détail
                  <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M7 4l6 6-6 6" />
                  </svg>
                </button>
              </div>
            </>
          )}
        </aside>
      </div>

      <CriticiteDetailModal modal={modal} onClose={() => setModal(null)} deviceVulnApps={deviceVulnApps} />
    </>
  );
}

/** Popup de détail (logiciel OU device) pour "Par criticité" — même chrome que
 * ControlDetailModal ci-dessus (`.wizard-overlay`/`.wizard-shell`), mêmes mécanismes
 * Échap/clic en dehors (dupliqué plutôt que partagé : contenu structurellement différent —
 * software vs device — pas la peine de généraliser pour 2 appelants). */
function CriticiteDetailModal({ modal, onClose, deviceVulnApps }) {
  const shellRef = useRef(null);

  useEffect(() => {
    if (!modal) return undefined;
    function handleKeyDown(e) {
      if (e.key === "Escape") onClose();
    }
    function handlePointerDown(e) {
      if (shellRef.current && !shellRef.current.contains(e.target)) onClose();
    }
    document.addEventListener("keydown", handleKeyDown);
    document.addEventListener("pointerdown", handlePointerDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("pointerdown", handlePointerDown);
    };
  }, [modal, onClose]);

  if (!modal) return null;

  const isDevice = modal.kind === "device";
  const title = isDevice ? modal.device.computerDnsName ?? "Device inconnu" : modal.entry.software_name;
  const deviceDetail = isDevice ? deviceVulnApps.state[modal.machineId] : null;

  return (
    <div className="wizard-overlay">
      <div className="wizard-shell" ref={shellRef} role="dialog" aria-modal="true" aria-label={title}>
        <div className="wizard-header">
          <span className="wizard-header-icon">{isDevice ? <IconLaptop /> : <IconAlertTriangle />}</span>
          <div className="wizard-header-text">
            <h2>{title}</h2>
            <p className="card-note">
              {isDevice ? (
                <>
                  {modal.device.osPlatform ?? "OS inconnu"} · <CriticiteLevelBadge level={modal.device.level} />
                </>
              ) : (
                <>
                  {modal.entry.software_vendor} · {modal.entry.cve_count} CVE · {modal.entry.totalDevices} appareils
                </>
              )}
            </p>
          </div>
          <button type="button" className="deployed-detail-close" onClick={onClose} aria-label="Fermer">
            <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </div>
        <div className="wizard-step-body">
          {isDevice ? (
            !deviceDetail || deviceDetail.loading ? (
              <p className="card-note">Chargement…</p>
            ) : deviceDetail.error ? (
              <p className="error-note">{deviceDetail.error}</p>
            ) : deviceDetail.data.length === 0 ? (
              <p className="empty">Aucun logiciel vulnérable détecté sur ce device.</p>
            ) : (
              deviceDetail.data.map((app, i) => (
                <div key={`${app.software_vendor}-${app.software_name}`} style={{ marginTop: i > 0 ? 16 : 0 }}>
                  <p className="secure-score-detail-section-title">{app.software_name}</p>
                  <p className="card-note" style={{ marginBottom: 6 }}>
                    {app.software_vendor} · {app.cve_count} CVE
                  </p>
                  {app.paths && app.paths.length > 0 ? (
                    <div className="vuln-path-list">
                      {app.paths.map((p, pi) => (
                        <div className="vuln-path-line" key={pi}>
                          {p}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="empty cve-small">Aucun chemin d'évidence retrouvé.</p>
                  )}
                </div>
              ))
            )
          ) : (
            <>
              <p className="secure-score-detail-section-title">Chemins d'évidence</p>
              {modal.entry.paths.length > 0 ? (
                <div className="vuln-path-list">
                  {modal.entry.paths.map((p, i) => (
                    <div className="vuln-path-line" key={i}>
                      {p}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="empty cve-small">Aucun chemin d'évidence retrouvé pour ce logiciel.</p>
              )}
              <p className="secure-score-detail-section-title">Appareils concernés ({modal.entry.device_names.length})</p>
              {modal.entry.device_names.length > 0 ? (
                <div className="vuln-device-list">
                  {modal.entry.device_names.map((n, i) => (
                    <span className="vuln-device-chip" key={i}>
                      {n}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="empty cve-small">Aucun device retrouvé pour ce logiciel.</p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

