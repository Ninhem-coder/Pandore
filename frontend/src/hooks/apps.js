import { useEffect, useState } from "react";
import { api } from "../api.js";
import { cachedCall, invalidateCache } from "../cache.js";
import { isErrorPayload, listPayloadError, useKeyedFetch } from "./shared.js";

/**
 * Hooks "Application déployée" Intune (découpage 2026-09-12, voir le barrel
 * `useDashboardData.js`).
 *
 * Charge la liste des applications DÉPLOYÉES via Intune FUSIONNÉE avec les "discovered apps"
 * détectées sur le parc (2026-09-02) — voir intune/apps.py::get_apps_catalog pour le
 * rapprochement (approximatif, par nom) et le dédoublonnage. `get_apps_catalog` est annotée
 * `list[dict]` : contrat d'erreur `[error]` (listPayloadError), pas un objet `{error:true}` nu.
 */
export function useDeployedApps() {
  const [state, setState] = useState({ loading: true, error: null, apps: [] });

  useEffect(() => {
    let cancelled = false;

    cachedCall("deployedApps", () => api.appsCatalog())
      .then((payload) => {
        if (cancelled) return;
        const err = listPayloadError(payload);
        if (err) invalidateCache("deployedApps");
        setState({ loading: false, error: err?.message ?? null, apps: err ? [] : Array.isArray(payload) ? payload : [] });
      })
      .catch((err) => {
        if (!cancelled) setState({ loading: false, error: err.message, apps: [] });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}

/**
 * Cache par app (clé = id Intune de l'app déployée) pour l'accordéon "état d'installation" de
 * l'onglet "Application déployée", sur /api/intune/apps/{id}/install-status.
 */
export function useAppInstallStatus() {
  return useKeyedFetch(api.appInstallStatus, (payload) => (isErrorPayload(payload) ? payload : null), null, "appInstallStatus");
}

/**
 * Cache par app (clé = id Intune) pour les groupes d'assignation (Requises/Disponibles/
 * Exclues) — chargé uniquement quand le panneau détail est "agrandi" (2026-09-02), jamais au
 * simple clic sur une ligne. Même motif useKeyedFetch que useAppInstallStatus.
 */
export function useAppAssignments() {
  return useKeyedFetch(api.appAssignments, (payload) => (isErrorPayload(payload) ? payload : null), null, "appAssignments");
}

/**
 * Devices détectés pour UNE version d'un logiciel détecté (2026-09-02) — clé = une liste d'ids
 * Graph bruts joints par virgule (une version peut porter plusieurs ids bruts) : un appel PAR
 * id, fusionnés ici (dédupliqués par `deviceId`, repli `deviceName`). Réutilise
 * `get_discovered_app_devices` tel quel. Un id qui échoue n'empêche pas les autres ; l'échec
 * n'est signalé que si TOUS ont échoué.
 */
export function useDiscoveredVersionDevices() {
  async function fetchByIds(idsKey) {
    const ids = idsKey.split(",");
    const results = await Promise.allSettled(ids.map((id) => api.discoveredAppDevices(id)));
    const merged = [];
    const seen = new Set();
    let anyOk = false;
    let lastError = null;
    for (const r of results) {
      if (r.status === "rejected") {
        lastError = r.reason?.message;
        continue;
      }
      if (isErrorPayload(r.value)) {
        lastError = r.value.message;
        continue;
      }
      anyOk = true;
      for (const d of r.value.devices || []) {
        const key = d.deviceId || d.deviceName;
        if (key) {
          if (seen.has(key)) continue;
          seen.add(key);
        }
        merged.push(d);
      }
    }
    if (!anyOk && lastError) return { error: true, message: lastError };
    return { devices: merged };
  }

  return useKeyedFetch(fetchByIds, (payload) => (isErrorPayload(payload) ? payload : null), null, "discoveredVersionDevices");
}

/**
 * Bandeau KPI "Taux d'installation moyen"/"Échecs d'installation" de l'onglet "Application
 * déployée" (2026-08-25). Agrégat GLOBAL affiché en haut de page dès l'ouverture de l'onglet,
 * chargé automatiquement au montage. C'est un appel Graph par app (~40 appels), plus coûteux
 * que `list_apps`, donc dans son propre hook (la liste s'affiche dès que useDeployedApps
 * répond, sans attendre ce KPI). `get_apps_install_summary` est annotée `-> dict` : erreur
 * encodée `{error:true,...}` nu (isErrorPayload), pas `[error]`.
 */
export function useAppInstallSummary() {
  const [state, setState] = useState({ loading: true, error: null, summary: null });

  useEffect(() => {
    let cancelled = false;

    cachedCall("appInstallSummary", () => api.appInstallSummary())
      .then((payload) => {
        if (cancelled) return;
        if (isErrorPayload(payload)) {
          invalidateCache("appInstallSummary");
          setState({ loading: false, error: payload.message, summary: null });
        } else {
          setState({ loading: false, error: null, summary: payload });
        }
      })
      .catch((err) => {
        if (!cancelled) setState({ loading: false, error: err.message, summary: null });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
