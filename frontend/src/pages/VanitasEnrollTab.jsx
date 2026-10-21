import { useEffect, useState } from "react";
import { api } from "../api.js";
import CopyButton from "../components/CopyButton.jsx";
import { isErrorPayload } from "../hooks/useDashboardData.js";

const STORAGE_KEY = "vanitasAgentServerUrl";

function buildInstallCommand(token, serverUrl) {
  const url = (serverUrl || "").trim();
  if (!token || !url) return null;
  return `msiexec /i EndpointAgent.msi ENROLLMENTTOKEN=${token} SERVERURL=${url} /qn`;
}

/** 🔧 Bug réel signalé par Nicolas (2026-09-11) : le champ a été rempli avec l'adresse DE CE
 * DASHBOARD (`http://localhost:5173`, le port du frontend Vite) plutôt que celle du SERVEUR
 * VANITAS (port 8443, un process entièrement différent même si elle tourne sur le même poste
 * physique). Ce garde-fou compare l'origine saisie à `window.location.origin` (l'adresse
 * RÉELLE de cette page) et avertit avant même de générer quoi que ce soit. */
function looksLikeThisDashboard(serverUrl) {
  const trimmed = (serverUrl || "").trim();
  if (!trimmed) return false;
  try {
    return new URL(trimmed).origin === window.location.origin;
  } catch {
    return false;
  }
}

/** Le serveur Vanitas n'accepte QUE du HTTPS (mTLS) — une adresse `http://` échouera toujours
 * la connexion, autre trace concrète du même incident du 2026-09-11 (le champ, à ce moment-là,
 * contenait aussi `http://`, pas seulement le mauvais port). */
function looksLikeHttpMismatch(serverUrl) {
  return /^http:\/\//i.test((serverUrl || "").trim());
}

/**
 * "Vanitas" > Administration > "Ajouter un poste" (2026-09-11, demande de Nicolas — "un truc
 * pour que se soit plus simple à mettre en place via une page sur Vanitas directement").
 *
 * Périmètre tranché explicitement avec Nicolas (`AskUserQuestion`, une seule option retenue
 * sur trois proposées) : SEULEMENT générer un token d'enrôlement et afficher la commande
 * `msiexec` prête à copier — pas de téléchargement du MSI depuis cette page, pas de suivi des
 * tokens en attente. Remplace `scripts/create_enrollment_token.py` pour l'usage courant (le
 * script reste utilisable en ligne de commande, ex. hors réseau).
 *
 * Historique des correctifs sur cette page, tous issus d'un VRAI parcours d'installation testé
 * en direct avec Nicolas (pas de bugs hypothétiques) :
 * 1. L'URL du serveur est devenue un champ ÉDITABLE de la page (mémorisé en `localStorage`),
 *    plutôt que de dépendre uniquement de `VANITAS_AGENT_SERVER_URL` côté backend — sinon la
 *    commande n'apparaissait jamais sans configuration fichier préalable.
 * 2. Le champ, resté VIDE tant qu'aucun token n'avait encore été généré, a été rempli par
 *    erreur avec l'adresse DE CE DASHBOARD (`http://localhost:5173`) — Nicolas a confondu
 *    "l'adresse par laquelle un poste te joint" avec l'URL de la page qu'il regardait. Corrigé
 *    par DEUX garde-fous (`looksLikeThisDashboard`/`looksLikeHttpMismatch`) ET un
 *    PRÉ-REMPLISSAGE dès le montage de la page (`enrollmentDefaults`, pas seulement après un
 *    premier "Générer") avec `same_machine_url` (= `VANITAS_SERVER_URL` côté backend, TOUJOURS
 *    connue — `https://localhost:8443` par défaut) : la valeur correcte pour le cas de loin le
 *    plus fréquent, installer sur cette même machine, est maintenant déjà dans le champ à
 *    l'ouverture, jamais à deviner.
 * 3. Le MSI lui-même n'existait pas encore sur le poste de Nicolas (jamais buildé dans cette
 *    session) — la commande d'installation échouait donc avec `1619` (fichier introuvable),
 *    une erreur invisible sous `/qn`. La carte "Reste du processus" ci-dessous donne maintenant
 *    les commandes de build exactes plutôt que de supposer le MSI déjà présent.
 * 4. `ENROLLMENTTOKEN=<TOKEN>` envoyé littéralement (un gabarit de dépannage collé sans
 *    substitution) → 401 "Token d'enrôlement invalide" côté serveur, alors même que
 *    l'installation MSI avait réussi. Pas un bug de cette page (le token qu'elle affiche est
 *    TOUJOURS la vraie valeur, jamais un gabarit) — mais le rappel "copie-le depuis CETTE
 *    page, jamais retapé à la main" est maintenant explicite dans l'avertissement du token.
 *
 * Cette page NE COUVRE TOUJOURS PAS tout le processus (voir `endpoint-agent/MILESTONES.fr.md`, jalon
 * 5) — build/signature du MSI restent des commandes à lancer soi-même, données ci-dessous en
 * référence plutôt qu'automatisées depuis cette page (portée volontairement limitée, voir
 * point 1 plus haut).
 */
export default function VanitasEnrollTab({ onNavigateVanitas }) {
  const [serverUrl, setServerUrl] = useState(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) || "";
    } catch {
      return "";
    }
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  function handleServerUrlChange(value) {
    setServerUrl(value);
    try {
      if (value.trim()) localStorage.setItem(STORAGE_KEY, value.trim());
      else localStorage.removeItem(STORAGE_KEY);
    } catch {
      // localStorage indisponible (navigateur restreint) — juste pas mémorisé d'une visite à
      // l'autre, pas bloquant pour l'usage immédiat.
    }
  }

  // Pré-remplissage DÈS L'OUVERTURE de la page (pas seulement après un premier "Générer",
  // contrairement au premier jet) — voir point 2 du commentaire d'en-tête. Ne touche JAMAIS une
  // valeur déjà mémorisée/saisie.
  useEffect(() => {
    if (serverUrl.trim()) return;
    let cancelled = false;
    api.vanitas
      .enrollmentDefaults()
      .then((defaults) => {
        if (cancelled) return;
        const suggestion = defaults?.server_url || defaults?.same_machine_url;
        if (!suggestion) return;
        // Updater FONCTIONNEL : on réévalue la valeur COURANTE au moment d'appliquer, pas celle
        // capturée au montage (deps `[]`). Sinon une saisie de l'utilisateur pendant que la
        // requête est en vol serait écrasée — le check `serverUrl.trim()` fermé sur la valeur
        // du montage (vide) ne la verrait pas. On NE persiste PAS cette suggestion dans
        // localStorage (défaut de confort, pas un choix explicite de l'utilisateur) : seule une
        // vraie saisie via handleServerUrlChange mémorise.
        setServerUrl((prev) => (prev.trim() ? prev : suggestion));
      })
      .catch(() => {
        // Suggestion de confort seulement — un échec laisse simplement le champ vide, jamais
        // bloquant pour le reste de la page.
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleGenerate() {
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.createEnrollmentToken();
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        setResult(payload);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const installCommand = result ? buildInstallCommand(result.token, serverUrl) : null;
  const urlLooksLikeDashboard = looksLikeThisDashboard(serverUrl);
  const urlLooksLikeHttp = !urlLooksLikeDashboard && looksLikeHttpMismatch(serverUrl);

  return (
    <div className="vanitas-hud">
      <p className="vanitas-enroll-intro">
        Génère un token d'enrôlement à usage unique pour un nouveau poste, et construit la
        commande d'installation correspondante. Le token est consommé dès le premier
        démarrage réel de l'agent — un poste qui ne s'enrôle jamais avec lui n'a rien
        d'autre à faire, générer un nouveau token n'a aucun effet sur les postes déjà
        enrôlés.
      </p>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>Nouveau poste</h2>
        </div>

        <div style={{ padding: "16px" }}>
          <div className="vanitas-enroll-field">
            <span className="vanitas-enroll-label">
              URL du SERVEUR VANITAS, port 8443 — PAS l'adresse de ce dashboard
            </span>
            <input
              type="text"
              className="filter-input"
              style={{ width: "100%" }}
              placeholder="https://localhost:8443 (ou l'adresse réseau du serveur pour un autre poste)"
              value={serverUrl}
              onChange={(e) => handleServerUrlChange(e.target.value)}
            />
            {urlLooksLikeDashboard && (
              <p className="vanitas-enroll-hint tone-warn">
                ⚠️ Cette adresse ({window.location.origin}) est celle de ce dashboard, pas du
                serveur Vanitas — pour installer sur cette même machine, utilise{" "}
                <code>https://localhost:8443</code>.
              </p>
            )}
            {urlLooksLikeHttp && (
              <p className="vanitas-enroll-hint tone-warn">
                ⚠️ Le serveur Vanitas parle uniquement HTTPS (mTLS) — une adresse{" "}
                <code>http://</code> ne se connectera jamais, utilise <code>https://</code>.
              </p>
            )}
          </div>

          <button type="button" className="vanitas-wiz-primary-btn" onClick={handleGenerate} disabled={busy}>
            {busy ? "Génération…" : "Générer un token d'enrôlement"}
          </button>

          {error && <p className="vanitas-hud-error" style={{ marginTop: "14px" }}>{error}</p>}

          {result && (
            <div style={{ marginTop: "18px" }}>
              <div className="vanitas-enroll-callout tone-warn">
                Ce token n'est affiché qu'ici, une seule fois — copie-le maintenant AVEC LE
                BOUTON ci-dessous (jamais retapé à la main : un gabarit collé par erreur, même
                un seul caractère de différence, se solde par un 401 "Token invalide" alors que
                le reste de l'installation a réussi). Il devient inutilisable dès qu'un poste
                s'en sert (usage unique).
              </div>

              <div className="vanitas-enroll-field">
                <span className="vanitas-enroll-label">Token d'enrôlement</span>
                <div className="vanitas-enroll-code-row">
                  <code>{result.token}</code>
                  <CopyButton className="vanitas-enroll-copy-btn" text={result.token} />
                </div>
              </div>

              {installCommand ? (
                <div className="vanitas-enroll-field">
                  <span className="vanitas-enroll-label">Commande d'installation (sur le poste, en administrateur)</span>
                  <div className="vanitas-enroll-code-row">
                    <code>{installCommand}</code>
                    <CopyButton className="vanitas-enroll-copy-btn" text={installCommand} />
                  </div>
                </div>
              ) : (
                <div className="vanitas-enroll-callout tone-accent">
                  Renseigne l'URL du serveur ci-dessus pour obtenir la commande complète — elle
                  se construit immédiatement, pas besoin de régénérer un token.
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame" style={{ marginTop: "16px" }}>
        <div className="vanitas-hud-card-head">
          <h2>Reste du processus</h2>
          <span className="vanitas-hud-card-note">build, signature, vérification</span>
        </div>
        <div style={{ padding: "16px" }}>
          <p className="vanitas-hud-empty-note" style={{ padding: 0, marginBottom: "6px" }}>
            <strong>1. Builder le MSI</strong> (une fois par version, cette page ne le fait
            pas) — depuis <code>endpoint-agent/agent/</code> :
          </p>
          <div className="vanitas-enroll-code-row" style={{ marginBottom: "10px" }}>
            <code style={{ fontSize: "11px" }}>
              cd EndpointAgent && dotnet publish -c Release -r win-x64 -p:SelfContained=true
              -p:PublishSingleFile=true -o publish && cd ../Installer && dotnet build
            </code>
            <CopyButton className="vanitas-enroll-copy-btn" text="cd EndpointAgent && dotnet publish -c Release -r win-x64 -p:SelfContained=true -p:PublishSingleFile=true -o publish && cd ../Installer && dotnet build" />
          </div>
          <p className="vanitas-hud-empty-note" style={{ padding: 0, marginBottom: "10px" }}>
            Le fichier atterrit dans{" "}
            <code>endpoint-agent/agent/Installer/bin/x64/Debug/EndpointAgent.msi</code>.
          </p>

          <p className="vanitas-hud-empty-note" style={{ padding: 0, marginBottom: "10px" }}>
            <strong>2. Certificat de signature</strong> — optionnel pour un test sur cette
            machine (Windows installe un MSI non signé sans broncher en local), nécessaire
            seulement pour un déploiement plus large (Intune/GPO). S'il est signé, le
            certificat public doit être importé sur le poste cible dans{" "}
            <code>Cert:\LocalMachine\Root</code> <strong>et</strong>{" "}
            <code>Cert:\LocalMachine\TrustedPublisher</code>.
          </p>

          <p className="vanitas-hud-empty-note" style={{ padding: 0, marginBottom: "10px" }}>
            <strong>3. Lancer la commande</strong> ci-dessus DEPUIS le dossier contenant{" "}
            <code>EndpointAgent.msi</code> (ou remplace son nom par le chemin complet) — sinon
            l'installation échoue en silence avec le code <code>1619</code>. Terminal en{" "}
            <strong>administrateur</strong> obligatoire (service LocalSystem).
          </p>

          <p className="vanitas-hud-empty-note" style={{ padding: 0 }}>
            <strong>4. Vérifier</strong> — <code>/qn</code> installe en silence, aucune fenêtre
            même en cas de succès :{" "}
            <code>Get-Service EndpointAgent</code> doit exister et tourner ; ajoute{" "}
            <code>/l*v install.log</code> à la fin de la commande pour voir le détail en cas
            d'échec (code retour ≠ 0).
          </p>

          {onNavigateVanitas && (
            <button
              type="button"
              className="vanitas-ghost-btn"
              style={{ marginTop: "14px" }}
              onClick={() => onNavigateVanitas("vanitas-docs")}
            >
              Voir la documentation →
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
