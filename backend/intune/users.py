"""
Utilisateurs Entra ID — extrait de `intune/tools.py` (1373 lignes) à la revue
d'architecture du 2026-08-17, deuxième passe (découpage par domaine : `intune/devices.py`,
`intune/compliance.py`, `intune/compliance_detail.py`, `intune/apps.py`, ce fichier,
`intune/secure_score.py`).

Comme le reste des modules issus de ce découpage : fonctions "nues" réutilisées à la fois
par le serveur MCP (`intune/mcp_server.py`) et par l'API REST du dashboard (`api_server.py`).
"""
from common.http_client import escape_odata_search, handle_tool_errors
from intune.client import client, client_search


@handle_tool_errors
def list_users(search: str | None = None) -> list[dict]:
    """Utilisateurs Entra ID, avec recherche optionnelle par nom ou email."""
    params: dict = {"$select": "id,displayName,userPrincipalName,mail,jobTitle,department"}
    if search:
        safe = escape_odata_search(search)
        params["$search"] = f'"displayName:{safe}" OR "mail:{safe}"'
        return client_search.get_all_pages("/users", params=params)
    return client.get_all_pages("/users", params=params)
