"""
Identifiants Intune/Graph — mêmes noms de variables que Project DSI/Intune MCP/.env
d'origine (AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET), pour copier-coller
directement les valeurs déjà utilisées par ce MCP en prod.
Uniquement requis en AUTH_MODE=client_credentials (défaut) ; ignoré en interactive
(dans ce cas, common.config.AZURE_TENANT_ID/AZURE_CLIENT_ID — app "public client" —
sont utilisés à la place, voir README §1bis).
"""
from common.config import AUTH_MODE, require_env

if AUTH_MODE == "client_credentials":
    AZURE_TENANT_ID = require_env("AZURE_TENANT_ID")
    AZURE_CLIENT_ID = require_env("AZURE_CLIENT_ID")
    AZURE_CLIENT_SECRET = require_env("AZURE_CLIENT_SECRET")
else:
    AZURE_TENANT_ID = AZURE_CLIENT_ID = AZURE_CLIENT_SECRET = None
