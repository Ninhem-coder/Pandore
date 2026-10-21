"""
Identifiants Defender — mêmes noms de variables que Project DSI/Defender MCP/config.py
d'origine, pour pouvoir copier-coller directement les valeurs du .env existant.
Uniquement requis en AUTH_MODE=client_credentials (défaut) ; ignoré en interactive.
"""
from common.config import AUTH_MODE, require_env

if AUTH_MODE == "client_credentials":
    MDE_TENANT_ID = require_env("MDE_TENANT_ID")
    MDE_CLIENT_ID = require_env("MDE_CLIENT_ID")
    MDE_CLIENT_SECRET = require_env("MDE_CLIENT_SECRET")
else:
    MDE_TENANT_ID = MDE_CLIENT_ID = MDE_CLIENT_SECRET = None
