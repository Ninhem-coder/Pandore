import { useEffect, useState } from "react";
import { api } from "../api.js";

// `m.url` vient de defender/anssi.py (toujours un `https://cert.ssi.gouv.fr/avis/...`
// construit côté backend, jamais un texte scrapé tel quel) — mais ce garde-fou évite de
// rendre un `<a href>` sur un schéma inattendu (`javascript:`, etc.) si ce champ change un
// jour de source sans que ce composant ne soit mis à jour en conséquence (revue de code du
// 2026-08-17). `rel="noreferrer"` (déjà en place) protège par ailleurs contre le reverse
// tabnabbing, un risque différent de celui couvert ici.
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
 * Bloc "CVE ANSSI / CERT-FR correspondant au parc logiciel" — fusionné dans l'onglet
 * "Vulnérabilités" (VulnerabilitiesTab.jsx) le 2026-08-12 à la demande de Nicolas, à la place
 * du placeholder d'origine ("Non couvert par cette V1", voir historique git). Rapprochement
 * RÉEL désormais : avis CERT-FR récents (fenêtre glissante) ↔ inventaire logiciel COMPLET du
 * tenant (defender/anssi.py::get_anssi_matches, ~12800 couples éditeur/logiciel distincts sur
 * le tenant de production, pas seulement le "top" habituel) — voir le skill audit-exposure-score,
 * Étape 6, pour la méthodologie de rapprochement reprise ici côté API locale.
 *
 * ⚠️ Le rapprochement reste approximatif par nature (titre d'avis ↔ nom de logiciel) — voir
 * le message de portée en bas de carte, et le docstring de defender/anssi.py pour la limite
 * de vérification propre à cette version (le scraping HTML de cert.ssi.gouv.fr n'a pas pu
 * être testé en conditions réelles avant cette implémentation, faute d'accès réseau à ce
 * domaine depuis l'environnement où elle a été écrite — si la liste reste vide en
 * production, vérifier d'abord les sélecteurs côté backend avant de conclure à une absence
 * réelle d'avis).
 *
 * Chaque avis retrouvé est cliquable : `onSelectMatch(match)` est fourni par
 * VulnerabilitiesTab.jsx, qui relance la MÊME recherche que le formulaire manuel (CVE isolée
 * si trouvée, sinon nom du logiciel rapproché) dans la zone de résultats commune — pas un
 * second tableau séparé, cohérent avec la demande de Nicolas ("la zone en bas").
 *
 * (2026-08-28) Chaque avis est un mini-bloc empilé (réf+date / titre / méta+badge), pas une
 * ligne unique compressée — voir styles.css pour le contexte (l'ancienne ligne ne tenait pas
 * dans les 336px du rail ajouté plus tôt le même jour, retour de Nicolas sur le formatage).
 */
export default function AnssiCard({ onSelectMatch, selectedRef }) {
  const [state, setState] = useState({ status: "loading", matches: [], error: null, windowDays: 14 });
  const [refreshing, setRefreshing] = useState(false);

  async function load(refresh) {
    if (refresh) setRefreshing(true);
    else setState((s) => ({ ...s, status: "loading" }));
    try {
      const result = await api.anssiMatches(14, refresh);
      const list = Array.isArray(result) ? result : [];
      // Même contrat d'erreur que le reste de l'app : une erreur backend (KQL invalide,
      // cert.ssi.gouv.fr injoignable, bs4 manquant…) est encodée en liste à un seul élément
      // {error: true, ...} par handle_tool_errors (voir VulnerabilitiesTab.jsx pour le même
      // pattern côté recherche manuelle).
      if (list.length === 1 && list[0]?.error) {
        setState({ status: "error", matches: [], error: list[0].message, windowDays: 14 });
      } else {
        setState({ status: "done", matches: list, error: null, windowDays: 14 });
      }
    } catch (err) {
      setState({ status: "error", matches: [], error: err.message, windowDays: 14 });
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    load(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="card anssi-panel">
      <div className="card-head">
        <h2>CVE ANSSI / CERT-FR correspondant au parc logiciel</h2>
        <button
          type="button"
          className="cve-watch-refresh"
          onClick={() => load(true)}
          disabled={refreshing || state.status === "loading"}
        >
          {refreshing ? "Vérification…" : "Rafraîchir"}
        </button>
      </div>

      {state.status === "loading" && (
        <p className="card-note">Recherche des avis CERT-FR récents et rapprochement avec l'inventaire logiciel du parc…</p>
      )}

      {state.status === "error" && <p className="error-note">{state.error}</p>}

      {state.status === "done" && state.matches.length === 0 && (
        <p className="empty">
          Aucun rapprochement plausible avec le parc logiciel sur les {state.windowDays} derniers jours d'avis CERT-FR.
        </p>
      )}

      {state.status === "done" && state.matches.length > 0 && (
        <div className="anssi-match-list">
          {state.matches.map((m) => (
            // `<div>` porteur, pas `<button>` : contient à la fois le bouton de sélection
            // (réf/titre/méta) ET un lien externe vers l'avis d'origine — imbriquer un <a>
            // dans un <button> est invalide en HTML (deux éléments interactifs), d'où cette
            // structure div > button + a plutôt qu'un seul élément cliquable.
            <div key={m.certfr_ref} className={`anssi-match-row${selectedRef === m.certfr_ref ? " active" : ""}`}>
              <button
                type="button"
                className="anssi-match-select"
                onClick={() => onSelectMatch(m)}
                aria-pressed={selectedRef === m.certfr_ref}
              >
                <div className="anssi-match-top">
                  <span className="anssi-match-ref cve-mono">{m.certfr_ref}</span>
                  {m.published && <span className="anssi-match-date">publié le {m.published}</span>}
                </div>
                <span className="anssi-match-title">{m.title}</span>
                <div className="anssi-match-bottom">
                  <span className="anssi-match-software">
                    {m.matched_software} · {m.matched_device_count ?? "?"} device
                    {(m.matched_device_count ?? 0) > 1 ? "s" : ""} du parc
                  </span>
                  {m.cve && m.cve.length > 0 ? (
                    <span className="badge high">{m.cve.length} CVE</span>
                  ) : (
                    <span className="cve-small">pas de CVE isolée</span>
                  )}
                </div>
              </button>
              {isSafeHttpUrl(m.url) && (
                <a href={m.url} target="_blank" rel="noreferrer" className="anssi-match-link">
                  Voir l'avis d'origine ↗
                </a>
              )}
            </div>
          ))}
        </div>
      )}

      <p className="scope-note">
        Rapprochement approximatif par nature (titre d'avis ↔ inventaire logiciel) — toujours vérifier chaque
        correspondance avant action, via le lien de l'avis d'origine ci-dessous.
      </p>
    </div>
  );
}
