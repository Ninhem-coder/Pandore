"""Client Graph — instancie deux ODataClient (v1.0 et beta) avec la stratégie d'auth active."""
from common.auth import get_token_client_credentials, get_token_interactive
from common.config import AUTH_MODE
from common.config import AZURE_CLIENT_ID as INTERACTIVE_CLIENT_ID
from common.config import AZURE_TENANT_ID as INTERACTIVE_TENANT_ID
from common.config import GRAPH_API_BASE, GRAPH_API_BETA, GRAPH_SCOPES
from common.http_client import ODataClient
from intune.config import AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID


def _get_token() -> str:
    if AUTH_MODE == "client_credentials":
        return get_token_client_credentials(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, GRAPH_SCOPES)
    return get_token_interactive(GRAPH_SCOPES, INTERACTIVE_CLIENT_ID, INTERACTIVE_TENANT_ID)


def _get_headers() -> dict:
    return {
        "Authorization": f"Bearer {_get_token()}",
        "Content-Type": "application/json",
    }


def _get_headers_search() -> dict:
    # ConsistencyLevel: eventual requis par Graph pour les requêtes $search sur /users
    headers = _get_headers()
    headers["ConsistencyLevel"] = "eventual"
    return headers


client = ODataClient(base_url=GRAPH_API_BASE, get_headers=_get_headers)
client_search = ODataClient(base_url=GRAPH_API_BASE, get_headers=_get_headers_search)
client_beta = ODataClient(base_url=GRAPH_API_BETA, get_headers=_get_headers)
