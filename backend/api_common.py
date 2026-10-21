"""Symboles partagés entre `api_server.py` (middleware, boucles de fond) et les routers de
domaine (`backend/routers/*.py`) — extraits ici (2026-09-12, découpage de l'ex-`api_server.py`
monolithique de 2050 lignes / 128 routes en routers par domaine) pour éviter un import
circulaire : un router ne peut pas importer `api_server`, qui l'inclut via `include_router`.
"""
import os

from fastapi import Path

from common.http_client import GRAPH_ID_PATTERN

# Cookie de session — lu par le middleware d'auth (api_server) ET posé/supprimé par les routes
# /api/auth/login|logout (routers/auth.py).
SESSION_COOKIE_NAME = "session_token"

# Tous les ID Graph/MDE (GUID Intune, hash 40 caractères Defender) sont alphanumériques +
# tirets. Contraindre le format en entrée de route évite qu'une valeur contenant "/", ".." ou
# "%" ne change la ressource Graph réellement appelée une fois interpolée dans un chemin d'URL
# par les sous-modules defender/*.py ou intune/*.py. Réutilise `GRAPH_ID_PATTERN`
# (common/http_client.py) — une seule source de vérité.
_ID_PATTERN = GRAPH_ID_PATTERN


def IdPath(description: str):
    return Path(..., pattern=_ID_PATTERN, description=description)


# Seuil "poste silencieux" (heures) — partagé entre la boucle de fond
# `_vanitas_agent_health_loop` (api_server) et la route `GET /api/vanitas/alerts/recent`
# (routers/vanitas.py), qui renvoie ce seuil avec le journal pour que la tuile "Postes
# silencieux" de la Vue d'ensemble reste alignée sur la boucle sans dupliquer la valeur.
VANITAS_ALERT_STALE_HOURS = int(os.environ.get("VANITAS_ALERT_STALE_HOURS", "12"))
