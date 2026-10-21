"""Client Defender — instancie l'ODataClient générique avec la stratégie d'auth active."""
from common.auth import get_token_client_credentials, get_token_interactive
from common.config import AUTH_MODE, AZURE_CLIENT_ID, AZURE_TENANT_ID, MDE_API_BASE, MDE_SCOPES
from common.http_client import ODataClient
from defender.config import MDE_CLIENT_ID, MDE_CLIENT_SECRET, MDE_TENANT_ID


def _get_headers() -> dict:
    if AUTH_MODE == "client_credentials":
        token = get_token_client_credentials(MDE_TENANT_ID, MDE_CLIENT_ID, MDE_CLIENT_SECRET, MDE_SCOPES)
    else:
        token = get_token_interactive(MDE_SCOPES, AZURE_CLIENT_ID, AZURE_TENANT_ID)
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


client = ODataClient(base_url=MDE_API_BASE, get_headers=_get_headers)
