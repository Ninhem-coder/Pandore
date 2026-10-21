/**
 * Légende d'un camembert — port de la boucle legend_rows des fonctions build_*_donut_html.
 *
 * `activeKey`/`onItemEnter`/`onItemLeave`/`onItemClick` (2026-08-27, demande de Nicolas :
 * "si je clique sur l'os dans le détail en bas du graph ça me met la zone du graph") — tous
 * optionnels, `null`/pas de handler par défaut : les appelants qui ne les passent pas
 * (WidgetsTestTab.jsx/IntuneTab.jsx/DefenderTab.jsx) gardent des lignes de légende
 * statiques, comportement inchangé. Une ligne devient `<div role="button" tabIndex={0}>`
 * (pas `<button>` : certaines lignes ont un lien `<a>` imbriqué — même motif déjà en place
 * ailleurs dans ce dashboard pour du contenu interactif imbriqué, ex. `SignalCard`) UNIQUEMENT
 * quand `onItemClick` est fourni ; sinon la ligne reste un `<div>` simple comme avant. Le
 * survol d'une ligne (`onItemEnter`) est symétrique au survol d'un segment côté DonutSvg —
 * highlight transitoire ; le CLIC (`onItemClick`) laissé à l'appelant pour décider s'il
 * bascule une sélection PERSISTANTE (voir Donut.jsx).
 *
 * `isSafeHttpUrl` (revue de sécurité du 2026-09-02, même garde-fou que `AnssiCard.jsx`/
 * `VulnerabilitiesTab.jsx`/`SecureScoreTab.jsx`) — `e.href` n'est actuellement jamais posé par
 * aucun appelant (grep confirmé), mais ce composant est partagé par 4+ pages : le premier
 * appelant à y brancher une URL issue de Graph hérite silencieusement d'un `<a href>` sans
 * validation de schéma s'il n'y pense pas lui-même. Corrigé à la source plutôt qu'à réinstaurer
 * à chaque futur appelant.
 */
function isSafeHttpUrl(value) {
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

export default function DonutLegend({ entries, size = "default", activeKey = null, onItemEnter = null, onItemLeave = null, onItemClick = null }) {
  const isSm = size === "sm";
  const interactive = Boolean(onItemClick);

  function handleKeyDown(e, key) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onItemClick(key);
    }
  }

  return (
    <div className="compliance-legend">
      {entries.map((e) => (
        <div
          className={`compliance-item${isSm ? " compliance-item-sm" : ""}${interactive ? " compliance-item-interactive" : ""}${
            activeKey === e.key ? " active" : ""
          }`}
          key={e.key}
          role={interactive ? "button" : undefined}
          tabIndex={interactive ? 0 : undefined}
          onClick={interactive ? () => onItemClick(e.key) : undefined}
          onKeyDown={interactive ? (ev) => handleKeyDown(ev, e.key) : undefined}
          onMouseEnter={onItemEnter ? () => onItemEnter(e.key) : undefined}
          onMouseLeave={onItemLeave || undefined}
        >
          <span className="compliance-dot" style={{ background: e.color }} />
          {isSafeHttpUrl(e.href) ? (
            <a
              href={e.href}
              target="_blank"
              rel="noopener noreferrer"
              className="compliance-label policy-link"
              onClick={(ev) => ev.stopPropagation()}
            >
              {e.label}
            </a>
          ) : (
            <span className="compliance-label">{e.label}</span>
          )}
          <span className="compliance-value">
            {e.value} ({(e.fraction * 100).toFixed(1)}%)
          </span>
        </div>
      ))}
    </div>
  );
}
