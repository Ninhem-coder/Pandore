import { useId } from "react";

/**
 * Primitive SVG de camembert — port direct de build_donut_svg()/build_donut_segments_svg()
 * (scripts/build_exposure_html.py, spec DONUT_FULL : radius 68, stroke-width 22,
 * viewBox 168). Ne rend que le <svg> (piste + parts + texte central) ; la légende et
 * l'habillage carte sont assemblés par l'appelant (DonutCard.jsx, ComplianceOverview.jsx)
 * — même séparation que côté Python (build_donut_svg vs les fonctions build_*_html qui
 * l'appellent).
 */
/**
 * `size="sm"` reprend les dimensions du camembert compact utilisé par le panneau
 * "Conformité en un coup d'œil" de l'onglet Devices non conformes du skill (viewBox 124,
 * radius 46, stroke-width 16) — copié à l'identique plutôt que redérivé au pourcentage,
 * pour rester pixel-fidèle à la référence.
 *
 * Passe design du 2026-08-06 (inspirée de la référence transmise par Nicolas — anneaux en
 * dégradé, "qui se dessinent progressivement") : chaque segment a son propre
 * <linearGradient> (léger éclaircissement en fin de segment, plutôt qu'une couleur plate)
 * et se dessine via une animation CSS sur `stroke-dasharray` (0 → sa longueur finale),
 * avec un délai en cascade par segment (voir `.donut-segment` dans styles.css). `useId`
 * évite toute collision d'id de <linearGradient> entre plusieurs camemberts affichés sur
 * la même page (React 18).
 */
/** Tronque un libellé trop long pour le texte central (2026-08-27, voir plus bas) — le
 * centre d'un donut "sm" (124 de viewBox) n'a la place que pour quelques caractères ; la
 * légende juste en dessous affiche de toute façon le libellé complet, ce n'est jamais la
 * seule source de cette information. */
function truncateCenterLabel(label, maxLen) {
  if (!label || label.length <= maxLen) return label;
  return `${label.slice(0, maxLen - 1)}…`;
}

/**
 * `activeKey`/`onSegmentEnter`/`onSegmentLeave` (2026-08-27, demande de Nicolas sur les
 * tuiles Onboarding/OS : "si je vais dans une zone du graph ça me montre quel OS ça
 * référence") — tous optionnels, `null`/pas de handler par défaut : les appelants existants
 * qui ne les passent pas (WidgetsTestTab.jsx/IntuneTab.jsx/DefenderTab.jsx, qui utilisent
 * cette primitive directement) gardent un rendu et un comportement strictement identiques.
 * Survoler un segment : le texte central bascule temporairement du total vers le libellé +
 * la valeur DE CE segment (au lieu d'une bulle de tooltip flottante à positionner en
 * coordonnées SVG — plus simple, et déjà bien visible au centre du donut). Le segment survolé
 * s'éclaircit légèrement (`filter: brightness`), les autres s'atténuent — la "zone" devient
 * visuellement évidente, dans les deux sens de survol (graph→légende ET légende→graph, cette
 * dernière pilotée par `activeKey` posé depuis Donut.jsx quand une ligne de la légende est
 * survolée/cliquée).
 */
export default function DonutSvg({ entries, centerText, ariaLabel, size = "default", activeKey = null, onSegmentEnter = null, onSegmentLeave = null }) {
  const isSm = size === "sm";
  const radius = isSm ? 46 : 68;
  const strokeWidth = isSm ? 16 : 22;
  const cx = isSm ? 62 : 84;
  const cy = isSm ? 62 : 84;
  const viewBox = isSm ? 124 : 168;
  const circumference = 2 * Math.PI * radius;
  const gradientBase = useId();

  let cumulative = 0;
  const segments = entries.map((e, i) => {
    const dash = circumference * e.fraction;
    const gap = circumference - dash;
    const offset = -cumulative * circumference;
    cumulative += e.fraction;
    return { ...e, dash, gap, offset, gradientId: `${gradientBase}-seg-${i}` };
  });

  const activeEntry = activeKey ? entries.find((e) => e.key === activeKey) : null;
  const hasActive = Boolean(activeKey);

  return (
    <svg
      viewBox={`0 0 ${viewBox} ${viewBox}`}
      className={`donut${isSm ? " donut-sm" : ""}`}
      role="img"
      aria-label={ariaLabel}
    >
      <defs>
        {segments.map((s) => (
          <linearGradient key={s.gradientId} id={s.gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={s.color} stopOpacity="0.82" />
            <stop offset="100%" stopColor={s.color} stopOpacity="1" />
          </linearGradient>
        ))}
      </defs>
      <circle cx={cx} cy={cy} r={radius} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth={strokeWidth} />
      {segments.map((s, i) => {
        const isActive = s.key === activeKey;
        return (
          <circle
            key={s.key}
            cx={cx}
            cy={cy}
            r={radius}
            fill="none"
            stroke={`url(#${s.gradientId})`}
            strokeWidth={isActive ? strokeWidth + 3 : strokeWidth}
            strokeDasharray={`${s.dash.toFixed(2)} ${s.gap.toFixed(2)}`}
            strokeDashoffset={s.offset.toFixed(2)}
            transform={`rotate(-90 ${cx} ${cy})`}
            className={`donut-segment${isActive ? " donut-segment-active" : ""}${hasActive && !isActive ? " donut-segment-dim" : ""}`}
            style={{
              "--seg-dash": s.dash.toFixed(2),
              "--seg-gap": s.gap.toFixed(2),
              "--seg-circumference": circumference.toFixed(2),
              animationDelay: `${0.1 + i * 0.09}s`,
              cursor: onSegmentEnter ? "pointer" : undefined,
            }}
            onMouseEnter={onSegmentEnter ? () => onSegmentEnter(s.key) : undefined}
            onMouseLeave={onSegmentLeave || undefined}
          >
            {!onSegmentEnter && <title>{`${s.label} : ${s.value} (${(s.fraction * 100).toFixed(1)}%)`}</title>}
          </circle>
        );
      })}
      {activeEntry ? (
        <>
          <text x={cx} y={cy - (isSm ? 3 : 4)} className={`donut-center${isSm ? " donut-center-sm" : ""}`} textAnchor="middle">
            {activeEntry.value}
          </text>
          <text x={cx} y={cy + (isSm ? 12 : 16)} className={`donut-center-label${isSm ? " donut-center-label-sm" : ""}`} textAnchor="middle">
            {truncateCenterLabel(activeEntry.label, isSm ? 11 : 16)}
          </text>
        </>
      ) : (
        <text x={cx} y={cy + (isSm ? 4 : 5)} className={`donut-center${isSm ? " donut-center-sm" : ""}`} textAnchor="middle">
          {centerText}
        </text>
      )}
    </svg>
  );
}
