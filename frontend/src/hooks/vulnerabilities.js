import { useRef, useState } from "react";
import { api } from "../api.js";
import { cachedCall, invalidateCache } from "../cache.js";
import { isErrorPayload, listPayloadError, useKeyedFetch } from "./shared.js";

/**
 * Hooks vulnérabilités/inventaires/ANSSI (découpage 2026-09-12, voir le barrel
 * `useDashboardData.js`).
 *
 * Détail d'alerte à la demande (2026-08-17, V43). `ensureLoaded(alertId)` est à appeler quand
 * une ligne de la liste des alertes est dépliée (WidgetsTestTab.jsx) — ne charge JAMAIS les
 * 200 détails d'un coup (limite documentée de 100 appels/minute sur /api/alerts/{id}).
 */
export function useAlertDetails() {
  const { state, ensureLoaded } = useKeyedFetch(
    api.defenderAlertDetail,
    (payload) => (isErrorPayload(payload) ? payload : null),
    null,
    "alertDetails"
  );
  return { cache: state, ensureLoaded };
}

/**
 * Cache par niveau d'exposition (High/Medium/Low) pour "Secure Score" > "Par criticité"
 * (2026-08-12) — chaque bloc charge son détail (top logiciels vulnérables + chemins) une seule
 * fois, au premier clic. Pas de chargement automatique au montage : `ensureLoaded(level)` est à
 * appeler depuis le gestionnaire de clic du bloc.
 */
export function useExposureVulnerableApps() {
  return useKeyedFetch((level) => api.exposureVulnerableApps(level, 5), listPayloadError, [], "exposureVulnerableApps");
}

/**
 * Même principe qu'useExposureVulnerableApps, mais cache par DEVICE ("Par criticité" v2,
 * 2026-08-12) — clic sur un device précis pour voir ce qui l'expose spécifiquement. Clé =
 * machine_id (`d.id` de /api/defender/machines), pas le niveau de criticité.
 */
export function useDeviceVulnerableSoftware() {
  return useKeyedFetch((machineId) => api.deviceVulnerableSoftware(machineId, 5), listPayloadError, [], "deviceVulnerableSoftware");
}

/**
 * Inventaire COMPLET des CVE du parc — colonne principale de l'onglet "Vulnérabilités" depuis
 * la refonte v3 (2026-09-01). Un SEUL `summarize` Advanced Hunting, SANS AUCUN paramètre `top`
 * (14 898 CVE distinctes mesurées, un seul appel), sans enrichissement catalogue par CVE.
 * Contrairement à `useExposureVulnerableApps`/`useDeviceVulnerableSoftware` (plusieurs clés),
 * une seule ressource ici — pas de `useKeyedFetch`, juste un `ensureLoaded()` sans argument
 * avec la même garde `startedRef` (éviter un double appel avant le premier re-render).
 */
export function useVulnerabilityInventory() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("vulnerabilityInventory", () => api.vulnerabilityInventory()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("vulnerabilityInventory");
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
 * Inventaire fleet-wide (2026-09-02) — singleton chargé une fois, même motif que
 * `useVulnerabilityInventory`. Fusionne `list_devices`/`list_machines` côté backend
 * (device_overview.py::get_device_inventory), un seul appel réseau côté frontend.
 */
export function useDeviceInventory() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("deviceInventory", () => api.deviceInventory()).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("deviceInventory");
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
 * Avis CERT-FR/ANSSI rapprochés du parc (2026-09-02) — hook DÉDIÉ pour le bloc "Renseignement
 * externe" de la popup de détail CVE (VulnerabilitiesTab.jsx), qui cherche pour UNE CVE donnée
 * si un avis la cite. `AnssiCard.jsx` gère son propre fetch en interne — cette fonction fait un
 * 2e appel indépendant, quasi toujours servi depuis le cache serveur (30 min) puis le cache
 * frontend partagé (2h).
 */
export function useAnssiMatches() {
  const [state, setState] = useState({ status: "idle", data: [], error: null });
  const startedRef = useRef(false);

  function ensureLoaded() {
    if (startedRef.current) return;
    startedRef.current = true;
    setState({ status: "loading", data: [], error: null });
    cachedCall("anssiMatches", () => api.anssiMatches(14)).then(
      (payload) => {
        const err = listPayloadError(payload);
        if (err) {
          invalidateCache("anssiMatches");
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
