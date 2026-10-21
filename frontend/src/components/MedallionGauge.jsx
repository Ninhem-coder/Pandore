import { levelForScore } from "../theme.js";

/**
 * Version compacte de Gauge.jsx (voir Vue d'ensemble v2, 2026-08-10) : même logique de
 * couleur par seuil (theme.js::levelForScore) mais en médaillon (76x76) au lieu de la
 * grande jauge pleine carte — Nicolas trouvait le hero-panel d'origine trop imposant pour
 * ce qui est au fond un seul chiffre. Pas de graduations ni de glow prononcé : à cette
 * taille elles alourdiraient plus qu'elles n'informeraient.
 *
 * `colorForScore`/`suffix`/`ariaLabel` ajoutés pour l'onglet "Secure Score" (2026-08-10),
 * qui réutilise ce même médaillon mais avec une sémantique de couleur INVERSÉE (un score
 * haut y est bon, contrairement à l'Exposure Score) — voir theme.js::secureScoreLevel.
 * Valeurs par défaut inchangées : tous les appels existants (TopStrip.jsx, Exposure Score)
 * gardent exactement le même rendu.
 */
export default function MedallionGauge({ score, colorForScore = levelForScore, suffix = "/100", ariaLabel }) {
  const radius = 32;
  const cx = 38;
  const cy = 38;
  const circumference = 2 * Math.PI * radius;

  if (score == null) {
    return (
      <div className="medallion">
        <svg viewBox="0 0 76 76">
          <circle className="medallion-track" cx={cx} cy={cy} r={radius} fill="none" strokeWidth="6" />
        </svg>
        <div className="medallion-value">
          —<span>{suffix}</span>
        </div>
      </div>
    );
  }

  // Le chiffre affiché (texte + aria-label) est clampé comme l'arc dessiné — corrigé à la
  // revue de code du 2026-08-20 : avant ça, seul `fraction` (l'arc) était borné à [0,100] ;
  // une valeur backend hors bornes (ex. -5 ou 142, jamais censée arriver mais pas non plus
  // strictement garantie par l'API) affichait un texte contredisant l'arc dessiné (arc plein
  // ou vide, texte "142/100" ou "-5/100").
  const clampedScore = Math.max(0, Math.min(100, score));
  const fraction = clampedScore / 100;
  const dash = circumference * fraction;
  const gap = circumference - dash;
  const { color } = colorForScore(clampedScore);

  return (
    <div className="medallion">
      <svg viewBox="0 0 76 76" role="img" aria-label={ariaLabel ?? `Exposure score ${clampedScore.toFixed(1)} sur 100`}>
        <circle className="medallion-track" cx={cx} cy={cy} r={radius} fill="none" strokeWidth="6" />
        <circle
          className="medallion-arc"
          cx={cx}
          cy={cy}
          r={radius}
          fill="none"
          strokeWidth="6"
          stroke={color}
          strokeDasharray={`${dash.toFixed(2)} ${gap.toFixed(2)}`}
          transform={`rotate(-90 ${cx} ${cy})`}
        />
      </svg>
      <div className="medallion-value">
        {clampedScore.toFixed(0)}
        <span>{suffix}</span>
      </div>
    </div>
  );
}
