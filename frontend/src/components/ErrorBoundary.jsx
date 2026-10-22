import { Component } from "react";
import { tr } from "../i18n/core.js";

/**
 * Error Boundary React — ajouté suite à la revue de code du 2026-08-17 : avant ce composant,
 * AUCUN Error Boundary n'existait nulle part dans l'application. Une exception de rendu dans
 * n'importe quel composant (ex. accès à un champ non garanti sur une réponse API — voir le
 * correctif sur `app.paths` dans SecureScoreTab.jsx, trouvé par la même revue) faisait
 * disparaître TOUT le dashboard en écran blanc, sans aucun message, plutôt que de casser
 * seulement l'onglet fautif.
 *
 * Volontairement une classe (React n'offre pas encore de hook équivalent à
 * `componentDidCatch`/`getDerivedStateFromError`) — le seul composant de classe de ce
 * frontend, tout le reste étant en composants fonctionnels.
 *
 * Utilisation : enveloppe le rendu de l'onglet actif dans Dashboard.jsx, pas l'app entière —
 * pour qu'un crash dans un onglet laisse la Sidebar utilisable et permette de revenir à un
 * autre onglet sans recharger toute la page.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Loggé en console pour le diagnostic local (voir `python api_server.py` déjà utilisé
    // comme référence de debug ailleurs dans ce fichier) — jamais avalé silencieusement.
    console.error("Erreur de rendu capturée par ErrorBoundary :", error, info?.componentStack);
  }

  componentDidUpdate(prevProps) {
    // Réinitialise l'état d'erreur si l'appelant change de `resetKey` (ex. changement
    // d'onglet actif côté Dashboard.jsx) : sans ça, revenir sur le même onglet après en avoir
    // changé afficherait à nouveau le message d'erreur alors que le composant est remonté.
    if (this.props.resetKey !== prevProps.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="fatal-error-panel">
          <p>{tr("errorBoundary.message")}</p>
          <p className="hint">Détail technique : {this.state.error.message || String(this.state.error)}</p>
          <p className="hint">{tr("errorBoundary.hint")}</p>
        </div>
      );
    }
    return this.props.children;
  }
}
