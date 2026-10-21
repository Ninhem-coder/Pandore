import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { cachedCall, invalidateCache } from "../cache.js";
import { isErrorPayload, listPayloadError, useKeyedFetch } from "./shared.js";

/**
 * Hooks Vanitas (2026-09-04, jalon 5 ; découpage 2026-09-12, voir le barrel
 * `useDashboardData.js`) — projet personnel séparé `endpoint-agent/`, proxifié par
 * `backend/vanitas/client.py`. Nommé "Vanitas" côté dashboard pour ne pas se confondre avec
 * "Pandore", le nom/la marque du dashboard lui-même.
 *
 * Liste fleet-wide des agents — singleton chargé une fois, même motif que
 * `useVulnerabilityInventory`/`useDeviceInventory`.
 */
export function useVanitasAgents() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasAgents", () => api.vanitas.agents()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasAgents");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  /** Jalon 7 ("Retirer de l'inventaire") — après suppression d'un agent, la liste mise en
   * cache (2h) resterait périmée sans ça. Invalide le cache puis redéclenche un chargement,
   * `startedRef` remis à `false` pour que `ensureLoaded()` accepte de repartir. */
  function refresh() {
    invalidateCache("vanitasAgents");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Tendance quotidienne du parc Vanitas (jalon "tendances Vanitas", 2026-09-17) — `[{date,
 * vanitas:{...}}]`, singleton mis en cache, même motif que `useVanitasAgents` ci-dessus. Alimente
 * la section "Tendances" de la Vue d'ensemble Vanitas. Un point `vanitas` peut être `null` pour
 * les jours antérieurs au jalon (trou en début de courbe, géré par le sélecteur).
 */
export function useVanitasHistory() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasHistory", () => api.vanitas.history()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasHistory");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  function refresh() {
    invalidateCache("vanitasHistory");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Historique de commandes fleet-wide — même motif singleton que `useVanitasAgents`, clé de
 * cache distincte.
 */
export function useVanitasCommands() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasCommands", () => api.vanitas.commands()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasCommands");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  return { state, ensureLoaded };
}

/**
 * Top 5 CVE les plus répandues sur le parc (jalon HUD 2026-09-06) — même motif singleton,
 * fleet-wide (pas de clé par agent, contrairement à `useVanitasAgentVulnerabilities`).
 */
export function useVanitasTopVulnerabilities(limit = 5) {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasTopVulnerabilities", () => api.vanitas.topVulnerabilities(limit)).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasTopVulnerabilities");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  return { state, ensureLoaded };
}

/**
 * Conformité (jalon 11, redesign 2026-08-31) — trois hooks singleton fleet-wide.
 * `useVanitasComplianceRules` (catalogue COMPLET, `script_content` inclus — chargé
 * paresseusement seulement quand un admin clique "Modifier") est DISTINCT de
 * `useVanitasComplianceRulesSummary` (id/nom/état seulement, sans le script).
 */
export function useVanitasComplianceSummary() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasComplianceSummary", () => api.vanitas.complianceSummary()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasComplianceSummary");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  return { state, ensureLoaded };
}

export function useVanitasComplianceRulesSummary() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasComplianceRulesSummary", () => api.vanitas.complianceRulesSummary()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasComplianceRulesSummary");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  // `refresh` (2026-09-09) — pour `CreateRuleWizard` : sans lui, une règle fraîchement créée
  // n'apparaissait qu'après un rechargement complet (cache partagé servant la réponse en mémoire
  // jusqu'à expiration du TTL).
  function refresh() {
    invalidateCache("vanitasComplianceRulesSummary");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

export function useVanitasComplianceRules() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasComplianceRules", () => api.vanitas.complianceRules()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasComplianceRules");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  // Pas de cache PARTAGÉ souhaité pour les mutations (créer/éditer/supprimer une règle change
  // le catalogue) — `refresh()` invalide le cache puis relance.
  function refresh() {
    invalidateCache("vanitasComplianceRules");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Groupes de postes (2026-09-08) — copie exacte du motif `useVanitasComplianceRules` (liste +
 * `refresh()` après une mutation créer/renommer/supprimer).
 */
export function useVanitasGroups() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasGroups", () => api.vanitas.groups()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasGroups");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  function refresh() {
    invalidateCache("vanitasGroups");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Mises à jour Windows — jalon "Mises à jour Vanitas" (2026-09-17) — copie exacte du motif
 * `useVanitasGroups` (liste fleet-wide + `refresh()`, statut déjà calculé côté serveur).
 */
export function useVanitasPatchStatus() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasPatchStatus", () => api.vanitas.patchStatus()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasPatchStatus");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  function refresh() {
    invalidateCache("vanitasPatchStatus");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Membres d'un groupe (2026-09-08, many-to-many + groupes dynamiques) — `useKeyedFetch`
 * générique, clé = `group_id`, valeur = `list[str]` (hostnames), calcul statique/dynamique
 * fait UNE SEULE FOIS côté serveur Vanitas (`GET /groups/{id}/members`).
 */
export function useVanitasGroupMembers() {
  return useKeyedFetch(api.vanitas.groupMembers, listPayloadError, [], "vanitasGroupMembers");
}

/**
 * Catalogue d'installeurs applicatifs (2026-09-08) — copie exacte du motif `useVanitasGroups`
 * (liste + `refresh()` après une mutation upload/suppression).
 */
export function useVanitasInstallers() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasInstallers", () => api.vanitas.installers()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasInstallers");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  function refresh() {
    invalidateCache("vanitasInstallers");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Paquets de mise à jour de l'agent Vanitas lui-même (2026-09-11) — copie exacte du motif
 * liste+`refresh()`, sur `api.vanitas.agentPackages()`. Le plus récent (`data[0]`, trié par
 * `uploaded_at` décroissant côté serveur) fait foi comme version "courante" à déployer.
 */
export function useVanitasAgentPackages() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasAgentPackages", () => api.vanitas.agentPackages()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasAgentPackages");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  function refresh() {
    invalidateCache("vanitasAgentPackages");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * "Applications déployées" (2026-09-10) — copie exacte du motif liste+`refresh()`, sur
 * `api.vanitas.installerDeployments()` (un élément par installeur déjà poussé au moins une fois).
 */
export function useVanitasInstallerDeployments() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasInstallerDeployments", () => api.vanitas.installerDeployments()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasInstallerDeployments");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  function refresh() {
    invalidateCache("vanitasInstallerDeployments");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Profils Vanitas (2026-09-10) — copie exacte du motif `useVanitasGroups`/`useVanitasInstallers`
 * (liste + `refresh()`). Admin-only côté serveur — la page qui la consomme est masquée pour un
 * compte non-admin (VanitasSidebar.jsx).
 */
export function useVanitasProfiles() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasProfiles", () => api.vanitas.profiles()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasProfiles");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  function refresh() {
    invalidateCache("vanitasProfiles");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Journal d'activité unifié (2026-09-09) — copie exacte du motif `useVanitasGroups` (liste +
 * `refresh()`). Fusionne déjà côté serveur Vanitas (`GET /activity-log`) les commandes envoyées
 * aux postes ET les mutations admin sur les catalogues — un seul appel.
 */
export function useVanitasActivityLog() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vanitasActivityLog", () => api.vanitas.activityLog()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vanitasActivityLog");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: [], error: err.message });
      }
    );
  }

  function refresh() {
    invalidateCache("vanitasActivityLog");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Détail par agent (`VanitasDevicesTab.jsx`, rail de droite) — TROIS hooks indépendants
 * (inventaire/CVE/commandes) plutôt qu'un seul combiné : un échec isolé (ex. le rapprochement
 * CVE) ne doit jamais empêcher d'afficher le reste du rail. Chacun est un `useKeyedFetch`
 * classique, clé = agent_id.
 */
export function useVanitasAgentInventory() {
  return useKeyedFetch(
    api.vanitas.agentDetail,
    (payload) => (isErrorPayload(payload) ? payload : null),
    null,
    "vanitasAgentInventory"
  );
}

/**
 * Logiciels/OS obsolètes (EOL, 2026-09-08) — un `useKeyedFetch` par agent (pas de route
 * fleet-wide côté serveur Vanitas).
 */
export function useVanitasAgentEol() {
  return useKeyedFetch(api.vanitas.agentEol, listPayloadError, [], "vanitasAgentEol");
}

/**
 * "Description & plan d'action (CERT-FR)" par CVE (2026-09-10). Payload = un OBJET (avis) ou
 * `null` (aucun avis trouvé, résultat légitime) plutôt qu'une liste — `isErrorPayload` (contrat
 * dict) ; `isErrorPayload(null)` est déjà sans risque.
 */
export function useVanitasCveAvis() {
  return useKeyedFetch(api.vanitas.cveAvis, isErrorPayload, null, "vanitasCveAvis");
}

/**
 * Journal des alertes Vanitas (agent silencieux / nouvelle vuln critique / nouvel échec de
 * conformité, 2026-09-08) — même motif singleton, mais payload en DICT
 * (`{recent, stale_threshold_hours}`) : le seuil d'alerte voyage avec le journal pour que la
 * tuile "Postes silencieux" de "Vue d'ensemble" reste alignée sur la boucle de fond — d'où
 * `isErrorPayload` (contrat `dict`) plutôt que `listPayloadError`.
 */
export function useVanitasRecentAlerts(limit = 20) {
  const [state, setState] = useState({ status: "idle", recent: [], staleThresholdHours: null, error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", recent: [], staleThresholdHours: null, error: null });
    cachedCall("vanitasRecentAlerts", () => api.vanitas.recentAlerts(limit)).then(
      (payload) => {
        const err = isErrorPayload(payload) ? payload : null;
        if (err) {
          invalidateCache("vanitasRecentAlerts");
          startedRef.current = false;
        }
        setState({
          status: err ? "error" : "done",
          recent: err ? [] : payload.recent ?? [],
          staleThresholdHours: err ? null : payload.stale_threshold_hours ?? null,
          error: err?.message ?? null,
        });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", recent: [], staleThresholdHours: null, error: err.message });
      }
    );
  }

  return { state, ensureLoaded };
}

export function useVanitasAgentVulnerabilities() {
  return useKeyedFetch(api.vanitas.agentVulnerabilities, listPayloadError, [], "vanitasAgentVulnerabilities");
}

export function useVanitasAgentCommands() {
  return useKeyedFetch(api.vanitas.agentCommands, listPayloadError, [], "vanitasAgentCommands");
}

/** Conformité d'UN agent (jalon 11) — payload en dict (`{agent_id, hostname, collected_at,
 * results}`), pas une liste : même contrat d'erreur que `useVanitasAgentInventory`. */
export function useVanitasAgentCompliance() {
  return useKeyedFetch(
    api.vanitas.agentCompliance,
    (payload) => (isErrorPayload(payload) ? payload : null),
    null,
    "vanitasAgentCompliance"
  );
}

/**
 * Activités suspectes (jalon "détection d'activités suspectes sur les postes") — liste
 * fleet-wide (ou filtrée par poste, voir `VanitasDeviceDetail.jsx`), volontairement SANS
 * `cachedCall`/le cache partagé de 2h (`cache.js`) : un onglet de triage doit rester frais à
 * chaque ouverture/changement de filtre, même motif que `useShellSession` (hooks/useShellSession.js)
 * plutôt que le TTL long pensé pour des données qui bougent peu (inventaire, conformité...).
 * `filters` = `{agentId, signalType, severity, status, since}` (voir `api.vanitas.suspiciousEvents`) —
 * un changement de filtre redéclenche automatiquement un fetch, pas besoin d'un `ensureLoaded()`
 * explicite côté appelant (contrairement aux hooks singleton ci-dessus). `refresh()` reste exposé
 * pour recharger après une mutation de triage (Accuser réception/Faux positif/Escalader) sans
 * attendre un changement de filtre.
 */
export function useVanitasSuspiciousEvents(filters = {}) {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  // Sérialisé pour servir de clé de dépendance stable à l'effet ci-dessous — un objet littéral
  // recréé à chaque rendu par l'appelant ne doit PAS redéclencher un fetch s'il décrit les mêmes
  // filtres.
  const filtersKey = JSON.stringify(filters ?? {});
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setState((prev) => ({ status: "loading", data: prev.data, error: null }));
    api.vanitas.suspiciousEvents(JSON.parse(filtersKey)).then(
      (payload) => {
        if (cancelled) return;
        const err = listPayloadError(payload);
        setState({ status: err ? "error" : "done", data: err ? [] : payload, error: err?.message ?? null });
      },
      (err) => {
        if (cancelled) return;
        setState({ status: "error", data: [], error: err.message });
      }
    );
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filtersKey, reloadToken]);

  function refresh() {
    setReloadToken((t) => t + 1);
  }

  return { state, refresh };
}

/**
 * Bandeau KPI (`{by_severity, by_status}`) de l'onglet "Activités suspectes" — singleton
 * fleet-wide classique (motif `useVanitasComplianceSummary`), avec `refresh()` (2026-09-14)
 * pour se remettre à jour après une transition de statut (Accuser réception/Faux positif/
 * Escalader change `by_status` immédiatement, pas seulement à la prochaine ouverture d'onglet).
 */
export function useVanitasSuspiciousEventsSummary() {
  const [state, setState] = useState({ status: "idle", data: null, error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: null, error: null });
    cachedCall("vanitasSuspiciousEventsSummary", () => api.vanitas.suspiciousEventsSummary()).then(
      (payload) => {
        const err = isErrorPayload(payload) ? payload : null;
        if (err) {
          invalidateCache("vanitasSuspiciousEventsSummary");
          startedRef.current = false;
        }
        setState({ status: err ? "error" : "done", data: err ? null : payload, error: err?.message ?? null });
      },
      (err) => {
        startedRef.current = false;
        setState({ status: "error", data: null, error: err.message });
      }
    );
  }

  function refresh() {
    invalidateCache("vanitasSuspiciousEventsSummary");
    startedRef.current = false;
    ensureLoaded();
  }

  return { state, ensureLoaded, refresh };
}

/**
 * Corrélation Defender d'UN événement suspect — chargée en LAZY à l'ouverture du panneau de
 * détail (jamais au chargement de la liste), `useKeyedFetch` par `event_id`, même motif que
 * `useVanitasAgentCompliance`/`useVanitasAgentEol` (payload en dict, `isErrorPayload`).
 */
export function useVanitasSuspiciousEventCorrelation() {
  return useKeyedFetch(
    api.vanitas.suspiciousEventCorrelation,
    (payload) => (isErrorPayload(payload) ? payload : null),
    null,
    "vanitasSuspiciousEventCorrelation"
  );
}
