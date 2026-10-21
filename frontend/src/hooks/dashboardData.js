import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { cachedCall, invalidateCache } from "../cache.js";
import { computeSecureScoreByCategory } from "../selectors.js";
import { isErrorPayload, listPayloadError } from "./shared.js";

/**
 * Données socle du dashboard Pandore (Defender/Intune) — voir `useDashboardData.js` (barrel)
 * pour la vue d'ensemble du découpage par domaine (2026-09-12).
 *
 * Centralise les appels à l'API locale (backend/api_server.py) — extrait de Dashboard.jsx pour
 * que les données soient chargées une seule fois au niveau de l'application, puis partagées
 * entre les onglets de la barre latérale plutôt que refaites à chaque changement d'onglet.
 *
 * Ne charge PAS `complianceDetail` : cet appel reste plus coûteux que le reste du dashboard —
 * méthode "policy-first" (voir intune/compliance_detail.py::get_compliance_detail, V3) : un
 * appel Graph par politique EN ÉCHEC (quelques-unes) + un unique `list_devices()` pour
 * résoudre l'OS. Reste sensiblement plus lent que le reste du dashboard (plusieurs appels
 * séquentiels par politique), donc toujours chargé à la demande plutôt qu'ici : le charger ici
 * pénaliserait le premier rendu de TOUS les onglets, même ceux qui ne l'affichent jamais. Il
 * est chargé à la demande par IntuneTab.jsx via `useComplianceDetail` ci-dessous.
 */
export function useDashboardData() {
  const [state, setState] = useState({
    loading: true,
    // Bouton "Rafraîchir" (2026-08-28, demande de Nicolas — au-dessus de l'horodatage
    // "généré le" du masthead, Dashboard.jsx) : distinct de `loading` (premier chargement,
    // écran vide) — `refreshing` garde les données déjà affichées à l'écran pendant qu'un
    // nouvel appel est en vol, seul le bouton reflète l'état (libellé "Rafraîchissement…",
    // désactivé), même esprit que `refreshing` dans AnssiCard.jsx.
    refreshing: false,
    error: null,
    defenderSummary: null,
    exposureScore: null,
    recommendations: [],
    nonOnboarded: [],
    machines: [],
    alerts: [],
    intuneSummary: null,
    policySummary: null,
  });
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Extrait en fonction nommée (2026-08-28) — appelée à la fois par le `useEffect` de montage
  // ci-dessous ET par `refresh()` (retournée par ce hook, câblée sur le bouton du masthead) :
  // MÊME logique de chargement dans les deux cas, `isRefresh` ne change que l'invalidation du
  // cache en amont et l'indicateur d'état utilisé pendant l'appel.
  async function load(isRefresh) {
    if (isRefresh) {
      // Invalide le cache partagé (cache.js, TTL 2h) — sans ça `cachedCall` ci-dessous
      // renverrait la même promesse déjà résolue tant que le TTL n'est pas expiré, et le
      // bouton "Rafraîchir" ne déclencherait jamais de VRAI nouvel appel réseau.
      invalidateCache("dashboardData");
      setState((s) => ({ ...s, refreshing: true }));
    }
    try {
      // Les 8 appels n'ont aucune dépendance entre eux — paralléliser via Promise.all divise
      // le temps avant que le premier onglet ne soit utilisable par un facteur proche du nombre
      // d'appels. CHAQUE appel a son propre .catch() : un échec réseau/HTTP isolé sur UN SEUL
      // endpoint ne fait pas passer TOUT le dashboard en état d'erreur (le fallback null/[]
      // correspond dans chaque cas à l'état initial du hook). `cachedCall` sert aussi de
      // garde-fou pour `refresh()` : deux clics rapprochés partagent la même requête en vol.
      const [defenderSummary, exposureScore, recommendations, nonOnboarded, machines, alerts, intuneSummary, policySummary] =
        await cachedCall("dashboardData", () =>
          Promise.all([
            api.defenderSummary().catch(() => null),
            api.exposureScore().catch(() => null),
            api.recommendations(20).catch(() => []),
            api.nonOnboarded().catch(() => []),
            api.defenderMachines().catch(() => []),
            api.defenderAlerts().catch(() => []),
            api.intuneSummary().catch(() => null),
            api.compliancePolicySummary().catch(() => null),
          ])
        );

      if (!mountedRef.current) return;
      // Chaque champ passe par `isErrorPayload` (dicts) ou `listPayloadError` (list[dict])
      // avant d'être stocké — sans ça, un payload `{error:true,...}` (ou `[{error:true,...}]`)
      // renvoyé en HTTP 200 par `handle_tool_errors` s'afficherait comme une vraie donnée.
      setState({
        loading: false,
        refreshing: false,
        error: null,
        defenderSummary: isErrorPayload(defenderSummary) ? null : defenderSummary,
        exposureScore: isErrorPayload(exposureScore) ? null : exposureScore,
        recommendations: listPayloadError(recommendations) ? [] : Array.isArray(recommendations) ? recommendations : [],
        nonOnboarded: listPayloadError(nonOnboarded) ? [] : Array.isArray(nonOnboarded) ? nonOnboarded : [],
        machines: listPayloadError(machines) ? [] : Array.isArray(machines) ? machines : [],
        alerts: listPayloadError(alerts) ? [] : Array.isArray(alerts) ? alerts : [],
        intuneSummary: isErrorPayload(intuneSummary) ? null : intuneSummary,
        policySummary: listPayloadError(policySummary) ? null : Array.isArray(policySummary) ? policySummary : null,
      });
    } catch (err) {
      if (!mountedRef.current) return;
      setState((s) => ({ ...s, loading: false, refreshing: false, error: err.message }));
    }
  }

  useEffect(() => {
    load(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return { ...state, refresh: () => load(true) };
}

/**
 * Chargement à la demande de GET /api/intune/compliance-detail — utilisé uniquement par
 * l'onglet "Conformité Intune" (voir commentaire ci-dessus sur le coût de cet appel).
 *
 * Passe par `cachedCall` depuis le 2026-08-27 (demande de Nicolas : "les chargements sont
 * longs entre les pages... un cache avec un TTL de 2h"). Une erreur métier détectée
 * (`complianceDetail?.error`) invalide quand même l'entrée pour qu'une prochaine visite retente
 * plutôt que de re-servir la même erreur pendant tout le TTL.
 */
export function useComplianceDetail() {
  const [state, setState] = useState({ loading: true, error: null, complianceDetail: null });

  useEffect(() => {
    let cancelled = false;

    cachedCall("complianceDetail", () => api.complianceDetail())
      .then((complianceDetail) => {
        if (cancelled) return;
        if (complianceDetail?.error) {
          invalidateCache("complianceDetail");
          setState({ loading: false, error: complianceDetail.message, complianceDetail: null });
        } else {
          setState({ loading: false, error: null, complianceDetail });
        }
      })
      .catch((err) => {
        if (!cancelled) setState({ loading: false, error: err.message, complianceDetail: null });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}

/**
 * Chargement à la demande pour l'onglet "Secure Score" (indépendant, 2026-08-10) — même
 * raison qu'useComplianceDetail : pas dans useDashboardData pour ne pas pénaliser le
 * premier rendu des autres onglets qui ne l'affichent jamais.
 *
 * `get_secure_score`/`list_secure_score_control_profiles` sont annotés `list[dict]` côté
 * backend : `handle_tool_errors` y renvoie `[error]`, jamais un objet `{error: true}` nu. On
 * distingue explicitement ce cas parce qu'ici la cause la plus probable est une permission
 * Graph manquante (SecurityEvents.Read.All) — un onglet vide sans explication laisserait croire
 * à un tenant sans marge de progression au lieu d'un scope non consenti.
 *
 * Passe par `cachedCall`, clé incluant `days` (7 jours ici et 30 via useOverviewSignals/
 * SecureScoreTab ont chacune leur propre entrée, jamais confondues).
 */
export function useSecureScore(days = 30) {
  const [state, setState] = useState({ loading: true, error: null, scoreHistory: [], controlProfiles: [] });

  useEffect(() => {
    let cancelled = false;
    const cacheKey = `secureScore:${days}`;

    cachedCall(cacheKey, () => Promise.all([api.secureScore(days), api.secureScoreControlProfiles()]))
      .then(([scoreHistory, controlProfiles]) => {
        if (cancelled) return;
        const scoreErr = listPayloadError(scoreHistory);
        if (scoreErr) {
          invalidateCache(cacheKey);
          setState({ loading: false, error: scoreErr.message, scoreHistory: [], controlProfiles: [] });
          return;
        }
        // Le catalogue des contrôles n'est nécessaire QUE pour les gains rapides/la
        // répartition par catégorie : s'il échoue seul, on affiche quand même le score.
        const profilesErr = listPayloadError(controlProfiles);
        setState({
          loading: false,
          error: null,
          scoreHistory: Array.isArray(scoreHistory) ? scoreHistory : [],
          controlProfiles: profilesErr ? [] : Array.isArray(controlProfiles) ? controlProfiles : [],
        });
      })
      .catch((err) => {
        if (!cancelled) setState({ loading: false, error: err.message, scoreHistory: [], controlProfiles: [] });
      });

    return () => {
      cancelled = true;
    };
  }, [days]);

  return state;
}

/**
 * Chargement à la demande pour l'onglet "Alertes Defender" (2026-08-17, V42) — un seul appel à
 * /api/defender/alerts (sans filtre serveur, jusqu'à 200 alertes) ; les répartitions par
 * statut/sévérité/classification et le filtrage sont calculés côté client (WidgetsTestTab.jsx)
 * pour permettre de cliquer d'un statut à l'autre sans re-fetch.
 */
export function useDefenderAlerts() {
  const [state, setState] = useState({ loading: true, alerts: [], error: null });

  useEffect(() => {
    let cancelled = false;

    cachedCall("defenderAlerts", () => api.defenderAlerts(200))
      .then((payload) => {
        if (cancelled) return;
        const err = listPayloadError(payload);
        if (err) invalidateCache("defenderAlerts");
        setState({ loading: false, alerts: err ? [] : payload, error: err?.message ?? null });
      })
      .catch((err) => {
        if (!cancelled) setState({ loading: false, alerts: [], error: err.message });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}

/**
 * "Signaux" de la Vue d'ensemble (refonte 2026-08-12) : un aperçu de trois fonctionnalités qui
 * vivent ailleurs dans la nav — Secure Score, Suivi CVE, ANSSI/CERT-FR — juste de quoi savoir
 * s'il faut y aller. Chargé à la demande (pas dans useDashboardData).
 *
 * `.catch()` posé sur CHAQUE appel individuel : un widget (ANSSI, scraping cert.ssi.gouv.fr)
 * ne doit pas faire disparaître le Secure Score et le Suivi CVE si lui seul échoue au niveau
 * réseau. `secureScore(7)` plutôt que (30) : la Vue d'ensemble n'affiche qu'un chiffre + une
 * sparkline courte. `secureScoreControlProfiles` ajouté au même `Promise.all` (2026-08-27) —
 * `useOverviewSignals` est déjà le SEUL consommateur de ces données pour Vue d'ensemble ; son
 * échec n'invalide PAS le cache (même tolérance que useSecureScore).
 */
export function useOverviewSignals() {
  const [state, setState] = useState({
    loading: true,
    secureScorePct: null,
    secureScoreTrend: [],
    secureScoreCategories: [],
    watchedCves: [],
    anssiMatches: [],
    errors: { secureScore: null, watchedCves: null, anssiMatches: null },
  });

  useEffect(() => {
    let cancelled = false;

    // Les 4 appels ont chacun leur `.catch()` qui convertit un échec réseau en payload
    // d'erreur RÉSOLU plutôt que de rejeter — la promesse mise en cache par `cachedCall` se
    // résout donc toujours avec succès. Il faut donc invalider explicitement en cas d'erreur
    // (métier OU réseau convertie) ci-dessous.
    cachedCall("overviewSignals", () =>
      Promise.all([
        api.secureScore(7).catch((err) => [{ error: true, message: err.message }]),
        api.watchedCves().catch((err) => [{ error: true, message: err.message }]),
        api.anssiMatches(14).catch((err) => [{ error: true, message: err.message }]),
        api.secureScoreControlProfiles().catch(() => [{ error: true, message: "control profiles indisponibles" }]),
      ])
    ).then(([scoreHistory, watchedCves, anssiMatches, controlProfiles]) => {
      if (cancelled) return;

      const scoreErr = listPayloadError(scoreHistory);
      const watchedErr = listPayloadError(watchedCves);
      const anssiErr = listPayloadError(anssiMatches);
      if (scoreErr || watchedErr || anssiErr) invalidateCache("overviewSignals");

      // Même dérivation que SecureScoreTab.jsx (scoreHistory[0] = aujourd'hui, Graph trie
      // du plus récent au plus ancien) — dupliquée ici plutôt que partagée, comme le reste
      // de ces hooks (chaque hook reste autonome).
      const history = scoreErr ? [] : Array.isArray(scoreHistory) ? scoreHistory : [];
      const pctByDay = history
        .filter((d) => typeof d.currentScore === "number" && d.maxScore)
        .map((d) => Math.round((d.currentScore / d.maxScore) * 100));

      const profilesErr = listPayloadError(controlProfiles);
      const categories = computeSecureScoreByCategory(
        history[0]?.controlScores,
        profilesErr ? [] : Array.isArray(controlProfiles) ? controlProfiles : []
      );

      setState({
        loading: false,
        secureScorePct: pctByDay.length > 0 ? pctByDay[0] : null,
        secureScoreTrend: pctByDay.slice().reverse(),
        secureScoreCategories: categories,
        watchedCves: watchedErr ? [] : Array.isArray(watchedCves) ? watchedCves : [],
        anssiMatches: anssiErr ? [] : Array.isArray(anssiMatches) ? anssiMatches : [],
        errors: {
          secureScore: scoreErr?.message ?? null,
          watchedCves: watchedErr?.message ?? null,
          anssiMatches: anssiErr?.message ?? null,
        },
      });
    });

    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}

/**
 * Historique quotidien (conformité Intune, exposure score Defender) — carte "Tendance" de
 * la Vue d'ensemble (2026-08-18). `points` est renvoyé TEL QUEL (déjà trié du plus ancien au
 * plus récent côté backend) — la dérivation (delta vs 7j/30j, coordonnées de sparkline) reste
 * dans OverviewTab.jsx.
 */
export function useHistoryTrend() {
  const [state, setState] = useState({ loading: true, error: null, points: [] });

  useEffect(() => {
    let cancelled = false;

    cachedCall("historyTrend", () => api.history())
      .then((payload) => {
        if (cancelled) return;
        const err = listPayloadError(payload);
        if (err) invalidateCache("historyTrend");
        setState({
          loading: false,
          error: err?.message ?? null,
          points: err ? [] : Array.isArray(payload) ? payload : [],
        });
      })
      .catch((err) => {
        if (!cancelled) setState({ loading: false, error: err.message, points: [] });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
