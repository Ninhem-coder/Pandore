"""
Authentification multi-comptes de Pandore (2026-09-07, demande de Nicolas) — jusqu'ici ce
dashboard n'avait AUCUN concept de compte/session, `api_server.py` supposait un usage
strictement local mono-utilisateur (voir le commentaire au-dessus de `uvicorn.run(...)`).

Convention de persistance : fichiers JSON + verrou (`store.py`), PAS de base de données —
même choix que `defender/watchlist.py`/`intune/app_library.py`, le volume ici (quelques
comptes, quelques sessions actives) ne justifie aucune nouvelle technologie de persistance
dans ce backend.

`require_admin` (ci-dessous) est le pendant, au niveau Pandore, de
`endpoint-agent/server/app/security.py::require_shell_token` : Vanitas permet d'exécuter du
PowerShell en SYSTEM sur tout le parc enrôlé (terminal interactif jalon 9, catalogue de règles
de conformité jalon 11) — toutes les capacités qui touchent à ce contenu-là (pas juste sa
LECTURE résumée) sont réservées au rôle "admin", jamais un compte "viewer" par défaut.
"""
from fastapi import HTTPException, Request, status

from . import vanitas_profiles


def require_admin(request: Request) -> None:
    """Dépendance FastAPI posée en plus du middleware d'auth global sur les quelques routes
    Vanitas les plus sensibles (terminal, gestion du catalogue de règles de conformité) —
    voir la liste exacte dans `api_server.py`. `request.state.user` est déjà posé par le
    middleware (`api_server.py::_auth_middleware`) au moment où cette dépendance s'exécute :
    si on arrive ici sans session valide, le middleware aurait déjà renvoyé 401 avant que la
    route elle-même ne soit atteinte — un `getattr` défensif reste utilisé pour ne jamais lever
    une AttributeError si ce n'est plus vrai un jour (ex. route ajoutée à l'allowlist par
    erreur). `detail` en simple chaîne (pas un dict) — même convention que les `HTTPException`
    déjà en place ailleurs dans `api_server.py` (ex. `packaging_download`)."""
    user = getattr(request.state, "user", None)
    if user is None or user.get("role") != "admin":
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Cette action est réservée aux comptes administrateur.",
        )


# ── Profils Vanitas (2026-09-10) ────────────────────────────────────────────────────────────
# Trois dépendances, toutes avec le même bypass admin ("Admin reste un super-rôle", décision de
# cadrage confirmée par Nicolas) — sinon un compte admin sans profil assigné (jamais nécessaire
# pour lui) se retrouverait bloqué par erreur. Un compte NON-admin sans profil (`profile_id`
# absent) est refusé PARTOUT sous Vanitas — refus par défaut, demande explicite de Nicolas
# ("si pas de profil, aucun accès à rien").


def require_vanitas_read(module: str):
    """Fabrique de dépendance FastAPI — `Depends(require_vanitas_read("postes"))` etc. Une
    permission "write" satisfait aussi une exigence "read" (voir `vanitas_profiles.has_access`)."""

    def _dep(request: Request) -> None:
        user = getattr(request.state, "user", None)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentification requise.")
        if user.get("role") == "admin":
            return
        if not vanitas_profiles.has_access(user.get("profile_id"), module, "read"):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Ton profil Vanitas ne donne pas accès à cette fonctionnalité.",
            )

    return _dep


def require_vanitas_write(module: str):
    def _dep(request: Request) -> None:
        user = getattr(request.state, "user", None)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentification requise.")
        if user.get("role") == "admin":
            return
        if not vanitas_profiles.has_access(user.get("profile_id"), module, "write"):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Ton profil Vanitas ne permet pas de modifier cette fonctionnalité.",
            )

    return _dep


def require_vanitas_any(request: Request) -> None:
    """Gate posée sur les pages d'observation fleet-wide qui ne correspondent à aucun module
    précis (Vue d'ensemble, Journal, Vulnérabilités, Logiciels obsolètes) — exige seulement
    qu'UN profil quelconque soit assigné (peu importe ce qu'il accorde), pas une permission par
    module : ce sont des agrégats qui recoupent tous les modules à la fois."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentification requise.")
    if user.get("role") == "admin":
        return
    if not user.get("profile_id"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Aucun profil Vanitas assigné à ce compte.")
