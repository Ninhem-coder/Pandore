import { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import CopyButton from "../components/CopyButton.jsx";
import { isErrorPayload, useVanitasAgents } from "../hooks/useDashboardData.js";
import { fmtRelative } from "./vanitasShared.jsx";
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

const BUILD_COMMAND =
  "cd EndpointAgent && dotnet publish -c Release -r win-x64 -p:SelfContained=true -p:PublishSingleFile=true -o publish && cd ../Installer && dotnet build";
const WATCH_INTERVAL_MS = 10_000;
// Marge sur l'heure d'enrôlement : horloges navigateur / serveur pas forcément synchrones.
const CLOCK_SKEW_MS = 60_000;

function StepNum({ state, n }) {
  return (
    <span className={`ven-num ${state}`} aria-hidden="true">
      {state === "done" ? "✓" : n}
    </span>
  );
}

/**
 * "Vanitas" > Administration > "Ajouter un poste" (2026-09-11, demande de Nicolas — "un truc
 * pour que se soit plus simple à mettre en place via une page sur Vanitas directement").
 *
 * Périmètre tranché avec Nicolas (`AskUserQuestion`) : SEULEMENT générer un token d'enrôlement et
 * afficher la commande `msiexec` prête à copier — pas de téléchargement du MSI depuis cette page.
 *
 * Historique des correctifs, tous issus d'un VRAI parcours d'installation testé avec Nicolas :
 * 1. L'URL du serveur est un champ ÉDITABLE (mémorisé en `localStorage`), pas seulement
 *    `VANITAS_AGENT_SERVER_URL` côté backend.
 * 2. Le champ a été rempli avec l'adresse DE CE DASHBOARD (`http://localhost:5173`) — deux
 *    garde-fous (`looksLikeThisDashboard`/`looksLikeHttpMismatch`) + pré-remplissage dès le
 *    montage (`enrollmentDefaults`, `same_machine_url`).
 * 3. MSI jamais buildé → `1619` invisible sous `/qn` : la commande de build est donnée dans les
 *    prérequis.
 * 4. `ENROLLMENTTOKEN=<TOKEN>` collé littéralement → 401 : rappel "copie-le depuis CETTE page".
 *
 * Refonte en parcours (2026-10-24, maquette canvas validée par Nicolas) : 3 étapes numérotées
 * (adresse → token → installation, variante silencieuse / avec journal), dépannage repliable
 * (1619/1603/401 — les codes réellement rencontrés), prérequis en aide-mémoire à cocher (non
 * persistés) et carte "Suivi" : après génération, la liste des postes est rafraîchie toutes les
 * 10 s jusqu'à l'arrivée d'un poste enrôlé APRÈS la génération. La route `/enrollment-tokens` ne
 * relie pas un token à son poste côté dashboard — tout poste enrôlé depuis la génération est
 * affiché (deux enrôlements simultanés apparaîtraient tous les deux). Classes `.ven-*`.
 */
export default function VanitasEnrollTab({ onNavigateVanitas }) {
  const agents = useVanitasAgents();
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
  const [generatedAt, setGeneratedAt] = useState(null);
  const [withLog, setWithLog] = useState(false);
  const [checks, setChecks] = useState([false, false, false]);

  function handleServerUrlChange(value) {
    setServerUrl(value);
    try {
      if (value.trim()) localStorage.setItem(STORAGE_KEY, value.trim());
      else localStorage.removeItem(STORAGE_KEY);
    } catch {
      // localStorage indisponible — juste pas mémorisé d'une visite à l'autre.
    }
  }

  // Pré-remplissage DÈS L'OUVERTURE (voir point 2) — ne touche jamais une valeur déjà saisie.
  useEffect(() => {
    if (serverUrl.trim()) return undefined;
    let cancelled = false;
    api.vanitas
      .enrollmentDefaults()
      .then((defaults) => {
        if (cancelled) return;
        const suggestion = defaults?.server_url || defaults?.same_machine_url;
        if (!suggestion) return;
        // Updater fonctionnel : une saisie faite pendant la requête n'est jamais écrasée. La
        // suggestion n'est PAS persistée (défaut de confort, pas un choix de l'utilisateur).
        setServerUrl((prev) => (prev.trim() ? prev : suggestion));
      })
      .catch(() => {
        // Suggestion de confort seulement — jamais bloquant.
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    agents.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const newAgents = useMemo(() => {
    if (!generatedAt) return [];
    return (agents.state.data ?? [])
      .filter((a) => a.enrolled_at && new Date(a.enrolled_at).getTime() >= generatedAt - CLOCK_SKEW_MS)
      .sort((a, b) => new Date(b.enrolled_at) - new Date(a.enrolled_at));
  }, [agents.state.data, generatedAt]);

  // Suivi : rafraîchit la liste des postes tant qu'aucun poste n'est arrivé depuis la génération.
  const waiting = Boolean(generatedAt) && newAgents.length === 0;
  useEffect(() => {
    if (!waiting) return undefined;
    const id = setInterval(() => agents.refresh(), WATCH_INTERVAL_MS);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [waiting]);

  async function handleGenerate() {
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.createEnrollmentToken();
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        setResult(payload);
        setGeneratedAt(Date.now());
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    setResult(null);
    setGeneratedAt(null);
    setError(null);
  }

  const baseCommand = result ? buildInstallCommand(result.token, serverUrl) : null;
  const installCommand = baseCommand && withLog ? `${baseCommand} /l*v install.log` : baseCommand;
  const urlLooksLikeDashboard = looksLikeThisDashboard(serverUrl);
  const urlLooksLikeHttp = !urlLooksLikeDashboard && looksLikeHttpMismatch(serverUrl);
  const urlOk = !urlLooksLikeDashboard && !urlLooksLikeHttp && /^https:\/\//i.test(serverUrl.trim());

  const prereqs = [
    { title: tr("ven.pre.msi"), text: trRich("ven.pre.msiText", { dir: <code>endpoint-agent/agent/</code> }), code: BUILD_COMMAND },
    {
      title: tr("ven.pre.cert"),
      text: trRich("ven.pre.certText", { root: <code>Cert:\LocalMachine\Root</code>, publisher: <code>Cert:\LocalMachine\TrustedPublisher</code> }),
    },
    { title: tr("ven.pre.admin"), text: tr("ven.pre.adminText") },
  ];

  return (
    <div className="vanitas-hud ven">
      <div className="ven-split">
        <section className="ven-card" aria-label={tr("ven.flowAria")}>
          <div className="ven-head">
            <h2 className="ven-h2">{tr("ven.flowTitle")}</h2>
            <span className="ven-sub ven-small">{tr("ven.flowSub")}</span>
          </div>
          <p className="ven-sub ven-intro">{tr("ven.intro")}</p>

          <div className="ven-step">
            <StepNum state={urlOk ? "done" : "on"} n={1} />
            <h3>{tr("ven.s1")}</h3>
            <div className="ven-body">
              <span className="ven-sub">{tr("ven.s1Hint")}</span>
              <input
                type="text"
                className="ven-input"
                placeholder={tr("ven.urlPlaceholder")}
                aria-label={tr("ven.s1")}
                value={serverUrl}
                onChange={(e) => handleServerUrlChange(e.target.value)}
                autoComplete="off"
                spellCheck={false}
              />
              {urlLooksLikeDashboard && (
                <p className="ven-hint warn">{trRich("ven.warnDashboard", { origin: window.location.origin, url: <code>https://localhost:8443</code> })}</p>
              )}
              {urlLooksLikeHttp && <p className="ven-hint warn">{trRich("ven.warnHttp", { http: <code>http://</code>, https: <code>https://</code> })}</p>}
              {urlOk && <span className="ven-sub ven-small ven-ok">{tr("ven.urlOk")}</span>}
            </div>
          </div>

          <div className="ven-step">
            <StepNum state={result ? "done" : "on"} n={2} />
            <h3>{tr("ven.token")}</h3>
            <div className="ven-body">
              {result ? (
                <>
                  <div className="ven-code">
                    <code>{result.token}</code>
                    <CopyButton className="vanitas-enroll-copy-btn" text={result.token} />
                  </div>
                  <p className="ven-hint warn">{tr("ven.tokenOnce")}</p>
                </>
              ) : (
                <>
                  <span className="ven-sub">{tr("ven.s2Hint")}</span>
                  <button type="button" className="vanitas-wiz-primary-btn ven-self-start" onClick={handleGenerate} disabled={busy}>
                    {busy ? tr("ven.generating") : tr("ven.generate")}
                  </button>
                </>
              )}
              {error && <p className="vanitas-hud-error" style={{ margin: 0 }}>{error}</p>}
            </div>
          </div>

          <div className="ven-step">
            <StepNum state={!result ? "" : newAgents.length ? "done" : "on"} n={3} />
            <h3>{tr("ven.s3")}</h3>
            <div className="ven-body">
              <span className="ven-sub">{trRich("ven.s3Hint", { admin: <b>{tr("ven.admin")}</b>, msi: <code>EndpointAgent.msi</code> })}</span>
              <span className="ven-seg" role="group" aria-label={tr("ven.variantAria")}>
                <button type="button" className={withLog ? "" : "on"} aria-pressed={!withLog} onClick={() => setWithLog(false)}>
                  {tr("ven.quiet")}
                </button>
                <button type="button" className={withLog ? "on" : ""} aria-pressed={withLog} onClick={() => setWithLog(true)}>
                  {tr("ven.withLog")}
                </button>
              </span>
              {!result ? (
                <span className="ven-sub ven-italic">{tr("ven.cmdAfterToken")}</span>
              ) : installCommand ? (
                <div className="ven-code">
                  <code>{installCommand}</code>
                  <CopyButton className="vanitas-enroll-copy-btn" text={installCommand} />
                </div>
              ) : (
                <p className="ven-hint accent">{tr("ven.fillUrl")}</p>
              )}
              <details className="ven-help">
                <summary>{tr("ven.trouble")}</summary>
                <ul>
                  <li>{trRich("ven.t1619", { code: <b>1619</b> })}</li>
                  <li>{trRich("ven.t1603", { code: <b>1603</b> })}</li>
                  <li>{trRich("ven.t401", { code: <b>401</b> })}</li>
                  <li>{trRich("ven.tService", { svc: <code>Get-Service EndpointAgent</code>, log: <code>install.log</code> })}</li>
                </ul>
              </details>
            </div>
          </div>
        </section>

        <div className="ven-side">
          <section className="ven-card ven-watch-card" aria-label={tr("ven.watchTitle")} aria-live="polite">
            <h2 className="ven-h2">{tr("ven.watchTitle")}</h2>
            {!generatedAt ? (
              <span className="ven-sub">{tr("ven.watchIdle")}</span>
            ) : newAgents.length === 0 ? (
              <div className="ven-watch">
                <div className="ven-watch-head">
                  <span className="ven-pulse" aria-hidden="true" />
                  <b>{tr("ven.watching")}</b>
                </div>
                <span className="ven-sub">{tr("ven.watchingHint")}</span>
              </div>
            ) : (
              <>
                {newAgents.map((a) => (
                  <div key={a.id} className="ven-new">
                    <span className="ven-dot" />
                    <span className="ven-new-host">{a.hostname}</span>
                    <span className="ven-pill">{tr("ven.enrolled")}</span>
                    <span className="ven-sub ven-small ven-new-meta">
                      {fmtRelative(a.enrolled_at)}
                      {a.agent_version ? ` · agent v${a.agent_version}` : ""}
                    </span>
                    <button type="button" className="vanitas-queue-btn ven-new-open" onClick={() => onNavigateVanitas?.("vanitas-devices", { selectAgentId: a.id })}>
                      {tr("ven.openDevice")}
                    </button>
                  </div>
                ))}
                {newAgents.length > 1 && <span className="ven-sub ven-small">{tr("ven.severalNote")}</span>}
                <button type="button" className="vanitas-ghost-btn ven-self-start" onClick={reset}>
                  {tr("ven.another")}
                </button>
              </>
            )}
          </section>

          <section className="ven-card" aria-label={tr("ven.preTitle")}>
            <div className="ven-head">
              <h2 className="ven-h2">{tr("ven.preTitle")}</h2>
              <span className="ven-sub ven-small">{tr("ven.preCount", { done: checks.filter(Boolean).length, count: prereqs.length })}</span>
            </div>
            {prereqs.map((p, i) => (
              <div key={i} className="ven-check">
                <button
                  type="button"
                  role="checkbox"
                  aria-checked={checks[i]}
                  aria-label={p.title}
                  className={`ven-box${checks[i] ? " on" : ""}`}
                  onClick={() => setChecks((c) => c.map((v, j) => (j === i ? !v : v)))}
                >
                  {checks[i] ? "✓" : ""}
                </button>
                <span className="ven-check-title">{p.title}</span>
                <span className="ven-sub ven-check-text">{p.text}</span>
                {p.code && (
                  <div className="ven-code ven-check-code">
                    <code>{p.code}</code>
                    <CopyButton className="vanitas-enroll-copy-btn" text={p.code} />
                  </div>
                )}
              </div>
            ))}
            {onNavigateVanitas && (
              <button type="button" className="vanitas-ghost-btn ven-docs" onClick={() => onNavigateVanitas("vanitas-docs")}>
                {tr("ven.docs")}
              </button>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
