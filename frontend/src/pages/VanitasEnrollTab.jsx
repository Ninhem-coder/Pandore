import { useEffect, useState } from "react";
import { api } from "../api.js";
import CopyButton from "../components/CopyButton.jsx";
import { isErrorPayload } from "../hooks/useDashboardData.js";
import { tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

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
        {tr("ven.intro")}
      </p>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>{tr("ven.newEndpoint")}</h2>
        </div>

        <div style={{ padding: "16px" }}>
          <div className="vanitas-enroll-field">
            <span className="vanitas-enroll-label">
              {tr("ven.urlLabel")}
            </span>
            <input
              type="text"
              className="filter-input"
              style={{ width: "100%" }}
              placeholder={tr("ven.urlPlaceholder")}
              value={serverUrl}
              onChange={(e) => handleServerUrlChange(e.target.value)}
            />
            {urlLooksLikeDashboard && (
              <p className="vanitas-enroll-hint tone-warn">
                {trRich("ven.warnDashboard", { origin: window.location.origin, url: <code>https://localhost:8443</code> })}
              </p>
            )}
            {urlLooksLikeHttp && (
              <p className="vanitas-enroll-hint tone-warn">
                {trRich("ven.warnHttp", { http: <code>http://</code>, https: <code>https://</code> })}
              </p>
            )}
          </div>

          <button type="button" className="vanitas-wiz-primary-btn" onClick={handleGenerate} disabled={busy}>
            {busy ? tr("ven.generating") : tr("ven.generate")}
          </button>

          {error && <p className="vanitas-hud-error" style={{ marginTop: "14px" }}>{error}</p>}

          {result && (
            <div style={{ marginTop: "18px" }}>
              <div className="vanitas-enroll-callout tone-warn">
                {tr("ven.tokenOnce")}
              </div>

              <div className="vanitas-enroll-field">
                <span className="vanitas-enroll-label">{tr("ven.token")}</span>
                <div className="vanitas-enroll-code-row">
                  <code>{result.token}</code>
                  <CopyButton className="vanitas-enroll-copy-btn" text={result.token} />
                </div>
              </div>

              {installCommand ? (
                <div className="vanitas-enroll-field">
                  <span className="vanitas-enroll-label">{tr("ven.command")}</span>
                  <div className="vanitas-enroll-code-row">
                    <code>{installCommand}</code>
                    <CopyButton className="vanitas-enroll-copy-btn" text={installCommand} />
                  </div>
                </div>
              ) : (
                <div className="vanitas-enroll-callout tone-accent">
                  {tr("ven.fillUrl")}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame" style={{ marginTop: "16px" }}>
        <div className="vanitas-hud-card-head">
          <h2>{tr("ven.rest")}</h2>
          <span className="vanitas-hud-card-note">{tr("ven.restNote")}</span>
        </div>
        <div style={{ padding: "16px" }}>
          <p className="vanitas-hud-empty-note" style={{ padding: 0, marginBottom: "6px" }}>
            {trRich("ven.step1", { title: <strong>{tr("ven.step1.title")}</strong>, dir: <code>endpoint-agent/agent/</code> })}
          </p>
          <div className="vanitas-enroll-code-row" style={{ marginBottom: "10px" }}>
            <code style={{ fontSize: "11px" }}>
              cd EndpointAgent && dotnet publish -c Release -r win-x64 -p:SelfContained=true
              -p:PublishSingleFile=true -o publish && cd ../Installer && dotnet build
            </code>
            <CopyButton className="vanitas-enroll-copy-btn" text="cd EndpointAgent && dotnet publish -c Release -r win-x64 -p:SelfContained=true -p:PublishSingleFile=true -o publish && cd ../Installer && dotnet build" />
          </div>
          <p className="vanitas-hud-empty-note" style={{ padding: 0, marginBottom: "10px" }}>
            {trRich("ven.step1.out", { path: <code>endpoint-agent/agent/Installer/bin/x64/Debug/EndpointAgent.msi</code> })}
          </p>

          <p className="vanitas-hud-empty-note" style={{ padding: 0, marginBottom: "10px" }}>
            {trRich("ven.step2", {
              title: <strong>{tr("ven.step2.title")}</strong>,
              root: <code>Cert:\LocalMachine\Root</code>,
              and: <strong>{tr("ven.and")}</strong>,
              publisher: <code>Cert:\LocalMachine\TrustedPublisher</code>,
            })}
          </p>

          <p className="vanitas-hud-empty-note" style={{ padding: 0, marginBottom: "10px" }}>
            {trRich("ven.step3", {
              title: <strong>{tr("ven.step3.title")}</strong>,
              msi: <code>EndpointAgent.msi</code>,
              code: <code>1619</code>,
              admin: <strong>{tr("ven.admin")}</strong>,
            })}
          </p>

          <p className="vanitas-hud-empty-note" style={{ padding: 0 }}>
            {trRich("ven.step4", {
              title: <strong>{tr("ven.step4.title")}</strong>,
              qn: <code>/qn</code>,
              svc: <code>Get-Service EndpointAgent</code>,
              log: <code>/l*v install.log</code>,
            })}
          </p>

          {onNavigateVanitas && (
            <button
              type="button"
              className="vanitas-ghost-btn"
              style={{ marginTop: "14px" }}
              onClick={() => onNavigateVanitas("vanitas-docs")}
            >
              {tr("ven.docs")}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
