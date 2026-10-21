"""
Authentification MSAL partagée — deux stratégies, sélectionnées par AUTH_MODE
(common.config) :

  - get_token_client_credentials — app-only (ConfidentialClientApplication), avec
    secret d'application. C'est le mode par défaut de ce projet : il réutilise le même
    principe que les MCP existants côté Claude Desktop (Project DSI/Defender MCP,
    Project DSI/Intune MCP), qui tournent déjà en client credentials en prod. Pas
    d'interaction utilisateur — adapté à un usage local run-and-forget.

  - get_token_interactive — flux délégué (public client), popup navigateur avec
    fallback device code. Gardé disponible si besoin de restreindre l'accès aux droits
    d'un utilisateur connecté plutôt qu'à ceux de l'application (AUTH_MODE=interactive).
"""
import threading
import time

import msal

from common.atomic_io import atomic_write_text
from common.config import TOKEN_CACHE_DIR

_cc_lock = threading.Lock()
_cc_token_cache: dict = {}  # (tenant, client, scopes) -> {"access_token", "expires_at"}

_ic_lock = threading.Lock()
_ic_apps: dict[str, tuple] = {}


# ── Mode "client_credentials" (par défaut) ──────────────────────────────────────────

def get_token_client_credentials(tenant_id: str, client_id: str, client_secret: str, scopes: list[str]) -> str:
    """
    Retourne un Bearer token app-only pour les `scopes` demandés, en cache mémoire
    (renouvelé automatiquement 5 min avant expiration — même marge que l'auth.py
    d'origine du MCP Defender).
    """
    key = (tenant_id, client_id, tuple(scopes))
    # `time.monotonic()` plutôt que `time.time()` (revue de code du 2026-08-20) : un
    # changement d'horloge système (resync NTP, changement manuel, reprise après veille d'une
    # VM) peut faire reculer `time.time()`, ce qui ferait paraître valide un token déjà expiré
    # jusqu'à ce que l'horloge rattrape le retard — `time.monotonic()` ne recule jamais et
    # n'est comparé qu'à lui-même (jamais persisté/affiché), donc insensible à ce cas.
    now = time.monotonic()
    cached = _cc_token_cache.get(key)
    if cached and cached["expires_at"] - 300 > now:
        return cached["access_token"]

    with _cc_lock:
        cached = _cc_token_cache.get(key)
        if cached and cached["expires_at"] - 300 > now:
            return cached["access_token"]

        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
        )
        result = app.acquire_token_for_client(scopes=scopes)

        if "access_token" not in result:
            error = result.get("error", "unknown")
            desc = result.get("error_description", "")
            raise RuntimeError(
                f"Echec d'authentification client credentials ({', '.join(scopes)}) : {error} — {desc}"
            )

        _cc_token_cache[key] = {
            "access_token": result["access_token"],
            "expires_at": now + result.get("expires_in", 3600),
        }
        return result["access_token"]


# ── Mode "interactive" (optionnel, AUTH_MODE=interactive) ───────────────────────────

def _cache_path(client_id: str, tenant_id: str):
    return TOKEN_CACHE_DIR / f"{tenant_id}-{client_id}.bin"


def _get_interactive_app(client_id: str, tenant_id: str):
    """Appelée uniquement depuis `get_token_interactive`, toujours sous `_ic_lock` (revue de
    code du 2026-08-20 — avant ça, le `if key in _ic_apps` se faisait hors verrou : deux appels
    concurrents pour le même tenant/client, plausible avec deux onglets du dashboard ouverts
    en même temps en `AUTH_MODE=interactive`, pouvaient chacun ne pas trouver la clé et créer
    DEUX `PublicClientApplication`/`SerializableTokenCache` séparés, puis écrire chacun leur
    tour dans le même fichier `.bin` — la seconde écriture écrasant silencieusement l'état de
    la première session)."""
    key = f"{tenant_id}:{client_id}"
    if key in _ic_apps:
        return _ic_apps[key]

    cache = msal.SerializableTokenCache()
    path = _cache_path(client_id, tenant_id)
    if path.exists():
        cache.deserialize(path.read_text(encoding="utf-8"))

    app = msal.PublicClientApplication(
        client_id=client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        token_cache=cache,
    )
    _ic_apps[key] = (app, cache, path)
    return _ic_apps[key]


def _persist_if_changed(cache: msal.SerializableTokenCache, path) -> None:
    if cache.has_state_changed:
        # Écriture atomique (fichier temporaire + renommage, voir common/atomic_io.py) ET
        # permissions restreintes au propriétaire (`0o600`) — revue de code du 2026-08-20 :
        # ce fichier contient un refresh token MSAL en clair ; sans restriction explicite, un
        # autre compte OS local sur le même poste partagé pourrait le lire et réutiliser la
        # session sans jamais se ré-authentifier.
        atomic_write_text(path, cache.serialize(), mode=0o600)


def get_token_interactive(scopes: list[str], client_id: str, tenant_id: str) -> str:
    """Popup navigateur (fallback device code) — voir common.config.AUTH_MODE.

    Tout le corps (recherche de compte, acquisition silencieuse/interactive, persistance)
    tourne sous `_ic_lock` depuis la revue de code du 2026-08-20 : la version précédente ne
    verrouillait que la branche interactive, avec un chemin "silencieux rapide" hors verrou —
    `cache` étant un objet MUTABLE PARTAGÉ entre tous les appels pour un même tenant/client
    (stocké dans `_ic_apps`), lire `cache.has_state_changed`/le sérialiser pendant qu'un AUTRE
    appel le modifiait concurremment (acquire_token_silent/interactive) restait racy quel que
    soit l'endroit où `_persist_if_changed` était appelé. Le mode interactif est optionnel et
    mono-utilisateur local : sérialiser entièrement ses appels coûte peu et supprime la
    course d'un coup.
    """
    with _ic_lock:
        app, cache, path = _get_interactive_app(client_id, tenant_id)

        accounts = app.get_accounts()
        result = None
        if accounts:
            result = app.acquire_token_silent(scopes, account=accounts[0])

        if not result:
            try:
                result = app.acquire_token_interactive(scopes=scopes)
            except Exception as exc:  # navigateur indisponible, machine headless...
                print(f"[auth] Connexion interactive impossible ({exc}), "
                      f"bascule sur le device code flow.")
                flow = app.initiate_device_flow(scopes=scopes)
                if "user_code" not in flow:
                    raise RuntimeError(f"Impossible d'initier le device code flow : {flow}")
                print(flow["message"])
                result = app.acquire_token_by_device_flow(flow)

        _persist_if_changed(cache, path)

    if not result or "access_token" not in result:
        error = (result or {}).get("error", "unknown")
        desc = (result or {}).get("error_description", "")
        raise RuntimeError(f"Echec d'authentification interactive ({', '.join(scopes)}) : {error} — {desc}")

    return result["access_token"]
