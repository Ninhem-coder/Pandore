"""Routes d'authentification et de gestion des comptes/profils — /api/auth/* (self-service +
admin) et /api/vanitas/profiles/* (catalogue de profils Vanitas, admin-only : définir/assigner
un profil est une action d'administration Pandore, pas une capacité Vanitas parmi d'autres).
Déplacé de api_server.py le 2026-09-12. Le middleware d'auth lui-même reste dans api_server.py."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from api_common import IdPath, SESSION_COOKIE_NAME
from auth import require_admin
from auth import store as auth_store
from auth import throttle as login_throttle
from auth import vanitas_profiles
from auth.passwords import DUMMY_HASH, hash_password, verify_password
from common.config import SESSION_COOKIE_SECURE

router = APIRouter()

_MIN_PASSWORD_LENGTH = 8


class LoginBody(BaseModel):
    username: str
    password: str


def _public_user(user: dict) -> dict:
    """Forme envoyée au frontend pour `/api/auth/login`/`/api/auth/me` — `vanitas_perms` est la
    matrice EFFECTIVE (pas le profil brut) : ce qui permet à `VanitasSidebar.jsx`/
    `VanitasDeviceDetail.jsx` de savoir quoi afficher sans dupliquer la logique de résolution
    profil→permissions côté frontend."""
    role = user["role"]
    perms = (
        {m: "write" for m in vanitas_profiles.MODULES}
        if role == "admin"
        else vanitas_profiles.resolved_perms(user.get("profile_id"))
    )
    return {
        "username": user["username"],
        "role": role,
        "profile_id": user.get("profile_id"),
        "vanitas_perms": perms,
    }


@router.post("/api/auth/login")
def auth_login(body: LoginBody, request: Request, response: Response):
    # Anti-bruteforce (2026-09-12) — throttle par IP source, voir auth/throttle.py. Vérifié AVANT
    # le hachage argon2 : une IP verrouillée ne fait même pas travailler le CPU.
    client_ip = request.client.host if request.client else "unknown"
    retry_after = login_throttle.check(client_ip)
    if retry_after is not None:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Trop de tentatives de connexion échouées. Réessaie dans quelques minutes.",
            headers={"Retry-After": str(int(retry_after) + 1)},
        )
    user = auth_store.find_user_by_username(body.username)
    # Toujours faire tourner argon2 (contre DUMMY_HASH si l'identifiant n'existe pas) — sinon un
    # court-circuit Python créerait un canal de timing distinguant "identifiant inconnu" (quasi
    # instantané) de "identifiant connu, mauvais mot de passe" (temps de hachage argon2 complet).
    password_ok = verify_password(body.password, user["password_hash"] if user else DUMMY_HASH)
    if not user or not password_ok:
        login_throttle.record_failure(client_ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiant ou mot de passe incorrect.")
    login_throttle.reset(client_ip)
    token = auth_store.create_session(user["id"])
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=SESSION_COOKIE_SECURE,
        max_age=auth_store.SESSION_TTL_HOURS * 3600,
    )
    return _public_user(user)


@router.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        auth_store.delete_session(token)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"ok": True}


@router.get("/api/auth/me")
def auth_me(request: Request):
    # request.state.user est déjà posé par le middleware d'auth (sinon 401 avant d'arriver ici) —
    # point d'interrogation explicite pour le frontend au boot.
    return _public_user(request.state.user)


# ── Page "Paramètres" (2026-09-08) — self-service (identifiant/mot de passe de SON PROPRE
# compte, tout rôle) + gestion des comptes réservée admin (créer/supprimer/changer le rôle d'un
# AUTRE compte, réinitialiser son mot de passe). Remplace la friction du CLI `manage_users.py`
# pour l'usage courant (qui reste disponible pour une intervention hors-ligne).
class UpdateMeBody(BaseModel):
    current_password: str
    new_username: str | None = None
    new_password: str | None = None


@router.put("/api/auth/me")
def auth_update_me(body: UpdateMeBody, request: Request):
    current = request.state.user
    user = auth_store.get_user(current["id"])
    if user is None or not verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Mot de passe actuel incorrect.")

    username = user["username"]
    if body.new_password:
        if len(body.new_password) < _MIN_PASSWORD_LENGTH:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Le mot de passe doit faire au moins {_MIN_PASSWORD_LENGTH} caractères.",
            )
        auth_store.set_password(username, hash_password(body.new_password))
        # Déconnecte les AUTRES sessions actives du compte (autre onglet/appareil) — jamais celle
        # qui vient de faire le changement, sinon l'utilisateur s'éjecterait de sa propre page.
        current_token = request.cookies.get(SESSION_COOKIE_NAME)
        auth_store.delete_sessions_except(user["id"], keep_token=current_token)

    if body.new_username and body.new_username.strip().lower() != username.lower():
        try:
            updated = auth_store.rename_user(username, body.new_username)
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
        username = updated["username"]

    return {"username": username, "role": user["role"]}


@router.get("/api/auth/users")
def auth_list_users(_admin: None = Depends(require_admin)):
    return auth_store.list_users()


class CreateUserBody(BaseModel):
    username: str
    password: str
    role: str
    # Profils Vanitas (2026-09-10) — ignoré si `role == "admin"`. `None` = aucun accès Vanitas
    # tant qu'un profil n'est pas assigné explicitement (refus par défaut).
    profile_id: str | None = None


@router.post("/api/auth/users")
def auth_create_user(body: CreateUserBody, _admin: None = Depends(require_admin)):
    if len(body.password) < _MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Le mot de passe doit faire au moins {_MIN_PASSWORD_LENGTH} caractères.",
        )
    if body.profile_id and not vanitas_profiles.get_profile(body.profile_id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Profil Vanitas introuvable.")
    try:
        user = auth_store.create_user(
            body.username, hash_password(body.password), body.role, profile_id=body.profile_id
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return {k: v for k, v in user.items() if k != "password_hash"}


class UpdateUserBody(BaseModel):
    role: str | None = None
    new_password: str | None = None
    # Convention "3 états" (comme `remove_icon`/`icon` de app_library) — `None` est ici une vraie
    # valeur métier ("aucun accès"), pas "ne touche pas au profil". `profile_id` fourni remplace ;
    # `clear_profile=true` retire tout accès (jamais les deux en même temps).
    profile_id: str | None = None
    clear_profile: bool = False


@router.put("/api/auth/users/{username}")
def auth_update_user(username: str, body: UpdateUserBody, _admin: None = Depends(require_admin)):
    # Réinitialisation par un admin — ne demande jamais le mot de passe ACTUEL du compte ciblé
    # (l'admin agit sur un AUTRE compte).
    try:
        if body.new_password is not None:
            if len(body.new_password) < _MIN_PASSWORD_LENGTH:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    f"Le mot de passe doit faire au moins {_MIN_PASSWORD_LENGTH} caractères.",
                )
            auth_store.set_password(username, hash_password(body.new_password))
        if body.role is not None:
            auth_store.set_role(username, body.role)
        if body.clear_profile:
            auth_store.set_profile(username, None)
        elif body.profile_id is not None:
            if not vanitas_profiles.get_profile(body.profile_id):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Profil Vanitas introuvable.")
            auth_store.set_profile(username, body.profile_id)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return {"ok": True}


@router.delete("/api/auth/users/{username}")
def auth_delete_user(username: str, request: Request, _admin: None = Depends(require_admin)):
    # Auto-suppression refusée ICI (le garde-fou "dernier admin" de store.py ne protégerait pas
    # un admin non-unique qui se supprimerait par erreur) — possible uniquement via
    # `manage_users.py delete` en accès direct au serveur, jamais un clic accidentel dans l'UI.
    if username.strip().lower() == request.state.user["username"].lower():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Tu ne peux pas supprimer ton propre compte depuis cette page — "
            "utilise manage_users.py directement sur le serveur si nécessaire.",
        )
    try:
        auth_store.delete_user(username)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return {"ok": True}


# ── Profils Vanitas (2026-09-10) — gestion du catalogue de matrices lecture/écriture, admin-only.
# Vit sous /api/vanitas/* parce que la page "Profils" est rangée sous Vanitas > Administration.
class ProfilePermsBody(BaseModel):
    postes: str | None = None
    terminal: str | None = None
    applications: str | None = None
    conformite: str | None = None
    groupes: str | None = None

    def as_dict(self) -> dict:
        return {m: getattr(self, m) for m in vanitas_profiles.MODULES}


class CreateProfileBody(BaseModel):
    name: str
    perms: ProfilePermsBody = ProfilePermsBody()


class UpdateProfileBody(BaseModel):
    name: str | None = None
    perms: ProfilePermsBody | None = None


@router.get("/api/vanitas/profiles")
def vanitas_list_profiles(_admin: None = Depends(require_admin)):
    return vanitas_profiles.list_profiles()


@router.post("/api/vanitas/profiles")
def vanitas_create_profile(body: CreateProfileBody, _admin: None = Depends(require_admin)):
    try:
        return vanitas_profiles.create_profile(body.name, body.perms.as_dict())
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e


@router.put("/api/vanitas/profiles/{profile_id}")
def vanitas_update_profile(
    body: UpdateProfileBody,
    profile_id: str = IdPath("Identifiant du profil"),
    _admin: None = Depends(require_admin),
):
    try:
        return vanitas_profiles.update_profile(
            profile_id, name=body.name, perms=body.perms.as_dict() if body.perms is not None else None
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e


@router.delete("/api/vanitas/profiles/{profile_id}")
def vanitas_delete_profile(profile_id: str = IdPath("Identifiant du profil"), _admin: None = Depends(require_admin)):
    assigned = auth_store.count_users_with_profile(profile_id)
    try:
        vanitas_profiles.delete_profile(profile_id, assigned_count=assigned)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return {"ok": True}
