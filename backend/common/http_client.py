"""
Client HTTP OData générique (pagination @odata.nextLink, retry sur 429/502/503/504,
échappement de filtres, validation de format des ID interpolés dans un chemin d'URL) —
mutualisé entre les sous-modules `defender/*.py` et `intune/*.py` pour éviter que les
implémentations divergent silencieusement, comme c'était déjà documenté entre le MCP
Defender (Python) et le MCP Intune (Node.js) d'origine.
"""
import functools
import random
import re
import time
import typing
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

MAX_RETRIES = 5

# 502/503/504 s'ajoutent au 429 : ce sont des échecs transitoires côté Graph/MDE (maintenance,
# pic de charge), pas des échecs définitifs — jusqu'ici seul get_policy_device_statuses
# (intune/compliance_detail.py::_fetch_policy_statuses) avait un retry ad hoc sur ces codes ;
# tous les autres appels remontaient une erreur définitive à l'utilisateur pour un problème
# qui aurait pu réussir une seconde plus tard (revue de code du 2026-08-17).
_RETRYABLE_STATUS_CODES = {429, 502, 503, 504}

# Format des ID Graph/MDE rencontrés dans ce backend (GUID Intune, hash 40 caractères
# Defender) : alphanumériques + tiret/underscore. Partagé entre api_server.py (validation
# Pydantic sur les routes REST) et validate_graph_id ci-dessous (appelée directement dans
# les sous-modules defender/*.py et intune/*.py) — les DEUX doivent valider, parce que ces
# fonctions "nues" sont aussi exposées sans passer par FastAPI via les serveurs MCP stdio
# (defender/mcp_server.py, intune/mcp_server.py, utilisés par Claude Desktop), qui ne
# bénéficient d'aucune validation Pydantic. Sans ce garde-fou côté fonction, un ID contenant
# "/", ".." ou "%" reçu par ce chemin MCP pourrait changer la ressource Graph/MDE réellement
# interrogée une fois interpolée dans un chemin d'URL.
GRAPH_ID_PATTERN = r"^[A-Za-z0-9_-]{1,128}$"
_GRAPH_ID_RE = re.compile(GRAPH_ID_PATTERN)


def _parse_retry_after(raw: str | None) -> int:
    """Parse l'en-tête `Retry-After`, qui peut être soit un nombre de secondes, soit (RFC 7231)
    une date HTTP (`Retry-After: Wed, 21 Oct 2026 07:28:00 GMT`) — corrigé à la revue de code du
    2026-08-20 : la version précédente faisait `int(...)` directement, ce qui levait `ValueError`
    sur une valeur au format date. Cette exception n'était rattrapée que par le filet générique
    `except Exception` de `handle_tool_errors`, transformant un simple 429 throttlé (plausible
    en rafale sur un tenant à 800+ appareils) en échec dur immédiat au lieu d'un nouveau backoff.
    Renvoie 0 (repli sur le backoff exponentiel de l'appelant) si la valeur est absente ou dans
    un format qu'on ne reconnaît pas — jamais d'exception."""
    if not raw:
        return 0
    raw = raw.strip()
    if raw.isdigit():
        return int(raw)
    try:
        dt = parsedate_to_datetime(raw)
        if dt is None:
            return 0
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(0, int(delta))
    except (TypeError, ValueError):
        return 0


def validate_graph_id(value: str, param_name: str = "id") -> str:
    """Valide qu'un identifiant destiné à être interpolé dans un chemin d'URL Graph/MDE
    respecte GRAPH_ID_PATTERN. Lève ValueError (capturée par handle_tool_errors, qui la
    renvoie comme {"error": true, "type": "ValueError", ...}) plutôt qu'un dict d'erreur
    construit à la main, pour rester utilisable dans les fonctions qui ne sont pas encore
    décorées à l'endroit de l'appel."""
    if not value or not _GRAPH_ID_RE.match(value):
        raise ValueError(
            f"« {value} » n'est pas un identifiant valide pour {param_name} "
            "(attendu : caractères alphanumériques, tiret ou underscore uniquement)."
        )
    return value


class ODataClient:
    """Client pour une base d'API donnée (Defender ou Graph), avec sa propre fonction
    de récupération de headers (dépend de la ressource/scope MSAL utilisée).

    Le client httpx sous-jacent est créé une seule fois et réutilisé pour tous les
    appels (`self._client`), plutôt que d'utiliser la fonction de convenance
    `httpx.request(...)`, qui ouvre et referme un `httpx.Client` — donc une nouvelle
    connexion TCP/TLS — À CHAQUE appel. Ça ne se voyait pas tant que chaque outil ne
    faisait que quelques requêtes, mais `get_compliance_detail` (méthode "device-first",
    un appel Graph par device non conforme) peut en faire des centaines : sans réutilisation
    de connexion, chacune payait un handshake complet. `httpx.Client` gère un pool de
    connexions et est thread-safe pour un usage concurrent, donc compatible avec le
    `ThreadPoolExecutor` utilisé côté intune/compliance_detail.py."""

    def __init__(self, base_url: str, get_headers: typing.Callable[[], dict]):
        self.base_url = base_url.rstrip("/")
        self.get_headers = get_headers
        self._client = httpx.Client(timeout=60)

    def _request(self, method: str, url: str, params: dict | None = None, json_body: dict | None = None) -> dict:
        attempt = 0
        while True:
            resp = self._client.request(
                method, url, headers=self.get_headers(), params=params, json=json_body,
            )
            if resp.status_code in _RETRYABLE_STATUS_CODES and attempt < MAX_RETRIES:
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                # + jitter aléatoire : avec ~12 threads concurrents (get_compliance_detail),
                # un backoff exponentiel non-jitté synchronise les retries de tous les
                # threads sur les mêmes instants, recréant une rafale de requêtes qui
                # retape du 429 au lieu d'étaler la charge. Retry-After n'est en pratique
                # présent que sur 429 ; sur 502/503/504 on retombe sur le backoff exponentiel.
                wait_s = (retry_after if retry_after > 0 else 2 ** attempt) + random.uniform(0, 1)
                time.sleep(wait_s)
                attempt += 1
                continue
            resp.raise_for_status()
            return resp.json() if resp.content else {}

    def get(self, path: str, params: dict | None = None) -> dict:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        return self._request("GET", url, params=params)

    def post(self, path: str, body: dict) -> dict:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        return self._request("POST", url, json_body=body)

    def get_all_pages(self, path: str, params: dict | None = None) -> list:
        """Parcourt toutes les pages OData (@odata.nextLink) et retourne la liste complète."""
        results: list = []
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        while url:
            data = self._request("GET", url, params=params)
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            params = None  # nextLink contient déjà les paramètres
        return results


def escape_odata_string(value: str) -> str:
    """
    Échappe une valeur littérale destinée à un filtre OData ($filter) : une quote simple
    contenue dans la valeur doit être doublée pour ne pas être interprétée comme la fin
    de la chaîne (sinon une valeur peut casser hors du littéral et injecter une clause
    OData arbitraire). À ne PAS utiliser sur un filtre déjà complet passé tel quel par
    l'appelant (ex: paramètre `filter` de list_machines/list_devices).
    """
    return str(value).replace("'", "''")


def escape_odata_search(value: str) -> str:
    """Même principe que escape_odata_string, mais pour $search (délimiteur guillemet double).

    Échappe en doublant le backslash puis en préfixant le guillemet d'un backslash (`\\"`) —
    corrigé à la revue de code du 2026-08-20 : la version précédente doublait le guillemet
    (`""`), qui est la convention `$filter` (OData classique), pas celle de `$search`. La
    grammaire `$search` de Microsoft Graph attend un échappement par barre oblique inverse pour
    une phrase entre guillemets ; doubler produisait une requête malformée (ou une recherche
    tronquée/silencieusement vide) pour une valeur contenant un guillemet littéral, ex. un nom
    d'utilisateur comme `Jean "Jojo" Martin`."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def tool_error(message: str, error_type: str = "ToolError") -> dict:
    """
    Construit un dict d'erreur au SEUL format que le reste de l'app (et le frontend) doit
    pouvoir attendre : `error` toujours booléen (jamais un message directement dedans),
    `message` toujours une chaîne. Avant cette fonction, quelques retours manuels
    (get_machine/get_device côté defender/intune) renvoyaient `{"error": "un message"}` —
    un frontend qui teste `error === true` (comme le fait handle_tool_errors plus bas)
    manquait alors silencieusement ces erreurs-là. À utiliser pour tout retour d'erreur
    "métier" (device introuvable, paramètre manquant...) construit à la main, au lieu
    d'un dict ad hoc.
    """
    return {"error": True, "type": error_type, "message": message}


def _wants_list(func) -> bool:
    """Détecte si la fonction décorée est annotée pour retourner une liste — nécessaire
    pour que handle_tool_errors renvoie une erreur sous une forme compatible avec le
    schéma de sortie déclaré à FastMCP (sinon une erreur HTTP masquée par une violation
    de schéma générique, cf. incident documenté sur list_recommendations)."""
    annotation = typing.get_type_hints(func).get("return")
    if annotation is None:
        return False
    origin = typing.get_origin(annotation)
    return annotation is list or origin is list


def handle_tool_errors(func):
    """Décorateur pour les fonctions outils exposées en MCP/API : transforme toute
    exception réseau/auth en un dict structuré {"error": True, ...} plutôt que de
    laisser remonter une exception brute."""
    returns_list = _wants_list(func)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            path = e.request.url.path if e.request else "?"
            error = {
                "error": True,
                "type": "HTTPStatusError",
                "message": f"L'API a répondu {status} sur {path}. Détail : {e.response.text[:300]}",
            }
        except httpx.RequestError as e:
            error = {
                "error": True,
                "type": "RequestError",
                "message": f"Impossible de contacter l'API ({e.__class__.__name__}) : {e}",
            }
        except RuntimeError as e:
            # Levée par common.auth.get_token() en cas d'échec MSAL
            error = {"error": True, "type": "AuthError", "message": str(e)}
        except Exception as e:
            # Filet de dernier recours : sans lui, une exception "inattendue" (KeyError sur
            # un champ Graph absent, TypeError sur une réponse de forme différente de celle
            # prévue — plausible vu la variabilité des réponses Graph dans
            # intune/compliance_detail.py::_compute_compliance_detail) remonte en 500 FastAPI brute,
            # cassant le contrat "toute fonction outil renvoie un dict structuré en cas
            # d'erreur" que le frontend suppose partout (isErrorPayload côté React). Loggée
            # ici (utile en debug local) plutôt que silencieusement avalée.
            import logging

            logging.getLogger(__name__).exception("Erreur inattendue dans %s", func.__name__)
            error = {"error": True, "type": e.__class__.__name__, "message": str(e) or "Erreur inattendue"}
        return [error] if returns_list else error

    return wrapper
