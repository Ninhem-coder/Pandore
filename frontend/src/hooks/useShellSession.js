import { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { isErrorPayload } from "./useDashboardData.js";

/**
 * Terminal PowerShell interactif (jalon 9) — hook DÉDIÉ, PAS `cache.js`/`useKeyedFetch` : ces
 * derniers sont pensés pour un TTL de 2h (voir cache.js), inadapté à un flux qui doit se
 * rafraîchir toutes les ~1s tant qu'une session est active. Aucun mécanisme de rafraîchissement
 * périodique n'existe ailleurs dans ce dashboard — brique neuve, pas une réutilisation.
 *
 * `sessionId` peut être `null` (avant que l'agent n'ait effectivement démarré la session,
 * jusqu'à ~5 min après la mise en file de "start_shell_session" — même délai que n'importe
 * quelle commande existante) : le hook reste alors inactif, ne poll rien.
 */
export function useShellSession(sessionId) {
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState("waiting"); // waiting | active | closed | timed_out | stale | error
  const [error, setError] = useState(null);
  const lastIdRef = useRef(0);

  useEffect(() => {
    lastIdRef.current = 0;
    setEvents([]);
    setError(null);
    setStatus(sessionId ? "active" : "waiting");

    if (!sessionId) return undefined;

    let cancelled = false;

    async function tick() {
      try {
        const [sessionPayload, eventsPayload] = await Promise.all([
          api.vanitas.shellSession(sessionId),
          api.vanitas.shellSessionEvents(sessionId, lastIdRef.current),
        ]);
        if (cancelled) return;

        if (isErrorPayload(sessionPayload)) {
          setError(sessionPayload.message);
          return;
        }
        if (!isErrorPayload(eventsPayload) && eventsPayload.length > 0) {
          lastIdRef.current = eventsPayload[eventsPayload.length - 1].id;
          setEvents((prev) => [...prev, ...eventsPayload]);
        }

        if (sessionPayload.is_stale) {
          setStatus("stale");
        } else {
          setStatus(sessionPayload.status);
        }
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    }

    tick();
    const interval = setInterval(() => {
      // S'arrête tout seul dès que la session n'est plus active — pas la peine de continuer à
      // sonder un terminal fermé/probablement mort.
      setStatus((s) => {
        if (s === "closed" || s === "timed_out" || s === "stale") {
          clearInterval(interval);
        } else {
          tick();
        }
        return s;
      });
    }, 1000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [sessionId]);

  async function sendLine(line) {
    if (!sessionId || !line.trim()) return;
    try {
      // Pas d'affichage optimiste : la ligne tapée réapparaît dans le défilement au plus tard
      // au prochain `tick()` (~1s, l'événement `direction="input"` vient d'être créé côté
      // serveur au moment même de cet appel) — assez rapide pour ne pas justifier un état
      // local en plus.
      const payload = await api.vanitas.sendShellInput(sessionId, line);
      if (isErrorPayload(payload)) {
        setError(payload.message);
      }
    } catch (err) {
      // Revue de sécurité du 2026-09-07 : seul endroit de ce hook sans try/catch autour d'un
      // appel `api.vanitas.*` — postJSON lève sur tout HTTP non-2xx (ex. 401 si la session de
      // 7 jours a expiré pendant qu'un terminal restait ouvert), jamais rattrapé par
      // `isErrorPayload` (réservé au contrat {error:true,...} en HTTP 200) : sans ce filet,
      // rejet de promesse non intercepté au lieu du message d'erreur affiché partout ailleurs.
      setError(err.message);
    }
  }

  async function stop() {
    if (!sessionId) return;
    try {
      const payload = await api.vanitas.stopShellSession(sessionId);
      if (isErrorPayload(payload)) {
        setError(payload.message);
      }
    } catch (err) {
      setError(err.message);
    }
  }

  return { events, status, error, sendLine, stop };
}
