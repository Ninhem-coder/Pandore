"""
Persistance des comptes/sessions — deux fichiers JSON gitignorés (contrairement à
`app_library.json`, ceux-ci portent un secret : le hash de mot de passe) sous `backend/data/`,
même motif que `intune/app_library.py` (verrou + `atomic_write_text`), sans base de données.

🔧 Bug réel corrigé le 2026-09-07 : la première version de ce module chargeait `_users`/
`_sessions` UNE SEULE FOIS à l'import, en supposant à tort un seul process. Mais
`manage_users.py` (gestion des comptes) tourne dans un PROCESS SÉPARÉ de `api_server.py` (le
serveur long-vivant qui gate le dashboard) — un compte créé/modifié via
`manage_users.py create|passwd|delete` met à jour le FICHIER, mais le serveur déjà démarré
gardait son ancien dict en mémoire indéfiniment : Nicolas créait un compte, essayait de se
connecter, et le serveur validait contre une copie périmée (voire une entrée déjà supprimée)
plutôt que le fichier réel. Corrigé par une invalidation basée sur `mtime` du fichier
(`_ensure_users_fresh`/`_ensure_sessions_fresh`, appelées avant toute lecture) : un simple
`stat()` (quasi gratuit) avant chaque lecture, un rechargement complet SEULEMENT si le fichier
a changé depuis la dernière lecture de CE process — la validation de session sur chaque requête
HTTP reste donc bon marché (pas un `json.loads` à chaque fois), tout en restant correcte face à
un autre process qui modifie les fichiers entre-temps.
"""
import json
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone

from common.atomic_io import atomic_write_text
from common.config import BACKEND_DIR

USERS_FILE = BACKEND_DIR / "data" / "auth_users.json"
SESSIONS_FILE = BACKEND_DIR / "data" / "auth_sessions.json"
USERS_FILE.parent.mkdir(exist_ok=True)

# Durée de vie FIXE d'une session depuis sa création (pas de fenêtre glissante — une session
# active depuis 7 jours redevient invalide même en cas d'usage continu, il faut se
# reconnecter). Choisi comme un compromis raisonnable pour un outil interne à quelques comptes
# plutôt que d'imposer une reconnexion quotidienne ; trivialement ajustable si Nicolas la juge
# trop longue/courte à l'usage. Volontairement PAS de limitation de tentatives de connexion en
# v1 (outil interne, non exposé sur Internet, argon2 ralentit déjà nativement le brute-force).
SESSION_TTL_HOURS = 24 * 7

_lock = threading.Lock()
VALID_ROLES = ("admin", "viewer")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _read_json(path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Fichier corrompu/tronqué — repartir vide plutôt que de faire planter tout le
        # dashboard au démarrage (même choix que defender/watchlist.py::_read_raw) ; un
        # fichier de comptes vide oblige juste à relancer `manage_users.py create`.
        return {}


def _write_json(path, data: dict) -> None:
    # mode=0o600 (revue de sécurité du 2026-09-09) : ces deux fichiers contiennent des hashs
    # argon2 de mot de passe et des jetons de session en clair (`secrets.token_urlsafe(32)`,
    # équivalent d'un mot de passe temporaire) — sans restriction, tout autre compte OS local
    # ayant accès à `backend/data/` pourrait les lire et usurper n'importe quelle session
    # active, y compris admin. Même raisonnement déjà appliqué au cache de token MSAL
    # (`common/auth.py::_persist_if_changed`).
    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2), mode=0o600)


def _mtime(path) -> float:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return -1


def _load_users() -> None:
    global _users, _users_mtime
    users = _read_json(USERS_FILE).get("users_by_id", {})
    # Profils Vanitas (2026-09-10) — les comptes créés avant ce jalon n'ont pas ce champ dans
    # le fichier ; backfill EN MÉMOIRE seulement (pas de réécriture forcée du fichier) pour que
    # `profile_id` soit toujours présent dans la forme renvoyée par `list_users()`/`get_session`.
    for user in users.values():
        user.setdefault("profile_id", None)
    _users = users
    _users_mtime = _mtime(USERS_FILE)


def _load_sessions() -> None:
    global _sessions, _sessions_mtime
    _sessions = _read_json(SESSIONS_FILE).get("sessions_by_token", {})
    _sessions_mtime = _mtime(SESSIONS_FILE)


def _ensure_users_fresh() -> None:
    """Recharge `_users` depuis le disque UNIQUEMENT si le fichier a changé depuis la dernière
    lecture par CE process (`manage_users.py`, un process séparé, a pu le modifier entre-temps)
    — un simple `stat()` sinon, pas un `json.loads` à chaque appel."""
    if _mtime(USERS_FILE) != _users_mtime:
        _load_users()


def _ensure_sessions_fresh() -> None:
    if _mtime(SESSIONS_FILE) != _sessions_mtime:
        _load_sessions()


_users: dict[str, dict] = {}
_sessions: dict[str, dict] = {}
_users_mtime: float = -2  # jamais égal à _mtime() au premier appel -> force le 1er chargement
_sessions_mtime: float = -2
_load_users()
_load_sessions()


def _save_users() -> None:
    global _users_mtime
    _write_json(USERS_FILE, {"users_by_id": _users})
    _users_mtime = _mtime(USERS_FILE)


def _save_sessions() -> None:
    global _sessions_mtime
    _write_json(SESSIONS_FILE, {"sessions_by_token": _sessions})
    _sessions_mtime = _mtime(SESSIONS_FILE)


def _normalize_username(username: str) -> str:
    return username.strip().lower()


# ── Comptes ──────────────────────────────────────────────────────────────────────────────

def find_user_by_username(username: str) -> dict | None:
    _ensure_users_fresh()
    needle = _normalize_username(username)
    for user in _users.values():
        if user["username_lower"] == needle:
            return user
    return None


def get_user(user_id: str) -> dict | None:
    _ensure_users_fresh()
    return _users.get(user_id)


def list_users() -> list[dict]:
    """Sans `password_hash` — alimente `manage_users.py list` ET `GET /api/auth/users` (page
    Paramètres > Gestion des comptes, admin uniquement, depuis le 2026-09-08)."""
    _ensure_users_fresh()
    return [
        {k: v for k, v in user.items() if k != "password_hash"}
        for user in sorted(_users.values(), key=lambda u: u["username"])
    ]


def create_user(username: str, password_hash: str, role: str, profile_id: str | None = None) -> dict:
    if role not in VALID_ROLES:
        raise ValueError(f"Rôle invalide : {role!r} (attendu : {'/'.join(VALID_ROLES)}).")
    # Un admin n'a jamais besoin/le droit d'avoir un profil Vanitas — même garde-fou que
    # `set_profile` ci-dessous, appliqué ICI aussi pour qu'un admin créé avec un `profile_id`
    # (bug d'appelant) ne se retrouve jamais dans un état incohérent.
    if role == "admin":
        profile_id = None
    # Vérification de doublon DANS le verrou (revue de sécurité du 2026-09-07) — faite avant à
    # l'extérieur, elle laissait une fenêtre de course entre deux `create_user` concurrents pour
    # le même identifiant (deux appels passent tous les deux la vérification avant qu'aucun des
    # deux n'ait encore inséré), créant 2 comptes de même identifiant dont un devient
    # invisible à `find_user_by_username` (qui ne renvoie que le premier trouvé) — appel sans
    # risque de deadlock, `find_user_by_username` ne prend pas `_lock` lui-même.
    with _lock:
        if find_user_by_username(username):
            raise ValueError(f"Le compte « {username} » existe déjà.")
        user_id = uuid.uuid4().hex
        user = {
            "id": user_id,
            "username": username.strip(),
            "username_lower": _normalize_username(username),
            "password_hash": password_hash,
            "role": role,
            "profile_id": profile_id,
            "created_at": _now().isoformat(),
        }
        _users[user_id] = user
        _save_users()
        return user


def set_password(username: str, password_hash: str) -> None:
    user = find_user_by_username(username)
    if not user:
        raise ValueError(f"Compte « {username} » introuvable.")
    with _lock:
        user["password_hash"] = password_hash
        _save_users()


def rename_user(username: str, new_username: str) -> dict:
    """Changement d'identifiant en self-service (page Paramètres, 2026-09-08) — conserve le
    même `id` (les sessions référencent `user_id`, jamais le nom, donc renommer ne déconnecte
    personne). Vérification de doublon DANS le verrou, même raisonnement que `create_user`."""
    user = find_user_by_username(username)
    if not user:
        raise ValueError(f"Compte « {username} » introuvable.")
    new_username = new_username.strip()
    if not new_username:
        raise ValueError("Le nouvel identifiant ne peut pas être vide.")
    new_lower = _normalize_username(new_username)
    with _lock:
        if new_lower != user["username_lower"] and find_user_by_username(new_username):
            raise ValueError(f"Le compte « {new_username} » existe déjà.")
        user["username"] = new_username
        user["username_lower"] = new_lower
        _save_users()
        return user


def _count_admins(exclude_user_id: str | None = None) -> int:
    return sum(1 for u in _users.values() if u["role"] == "admin" and u["id"] != exclude_user_id)


def set_role(username: str, role: str) -> None:
    """Changement de rôle par un admin (page Paramètres > Gestion des comptes, 2026-09-08) —
    `create_user` fige le rôle à la création, mais rien ne permettait jusqu'ici de le changer
    pour un compte EXISTANT sans le supprimer/recréer. Refuse de rétrograder le DERNIER compte
    admin (sans quoi plus personne ne pourrait gérer les comptes ni les capacités Vanitas les
    plus sensibles — un lockout total, uniquement rattrapable en éditant `auth_users.json` à la
    main sur le serveur)."""
    if role not in VALID_ROLES:
        raise ValueError(f"Rôle invalide : {role!r} (attendu : {'/'.join(VALID_ROLES)}).")
    user = find_user_by_username(username)
    if not user:
        raise ValueError(f"Compte « {username} » introuvable.")
    with _lock:
        if user["role"] == "admin" and role != "admin" and _count_admins(exclude_user_id=user["id"]) == 0:
            raise ValueError("Impossible de rétrograder le dernier compte administrateur.")
        user["role"] = role
        if role == "admin":
            # Un admin a un accès total automatique — le profil éventuellement encore assigné
            # avant la promotion n'a plus de sens et deviendrait fantôme (jamais lu tant que le
            # compte reste admin, mais réapparaîtrait si on le rétrograde plus tard) ; effacé
            # explicitement plutôt que laissé traîner.
            user["profile_id"] = None
        _save_users()


def set_profile(username: str, profile_id: str | None) -> None:
    """Assignation/retrait d'un profil Vanitas (page "Profils", 2026-09-10) — `profile_id=None`
    EST une valeur métier valide ("aucun accès"), pas un "ne pas toucher" : voir
    `api_server.py::UpdateUserBody` pour la distinction à 3 états (inchangé / mis à None /
    remplacé) côté route, cette fonction-ci applique toujours la valeur reçue telle quelle."""
    user = find_user_by_username(username)
    if not user:
        raise ValueError(f"Compte « {username} » introuvable.")
    if user["role"] == "admin" and profile_id:
        raise ValueError("Un compte administrateur n'a pas besoin de profil — il a déjà un accès total.")
    with _lock:
        user["profile_id"] = profile_id
        _save_users()


def count_users_with_profile(profile_id: str) -> int:
    """Garde-fou de suppression d'un profil (page "Profils") — un profil encore assigné à au
    moins un compte ne peut pas être supprimé (voir `auth/vanitas_profiles.py::delete_profile`,
    qui reçoit ce compte plutôt que d'aller lire les comptes lui-même : séparation des
    responsabilités déjà établie entre les deux modules)."""
    _ensure_users_fresh()
    return sum(1 for u in _users.values() if u.get("profile_id") == profile_id)


def delete_user(username: str) -> None:
    user = find_user_by_username(username)
    if not user:
        raise ValueError(f"Compte « {username} » introuvable.")
    _ensure_sessions_fresh()
    with _lock:
        # Même garde-fou que `set_role` — supprimer le dernier admin serait un lockout total.
        if user["role"] == "admin" and _count_admins(exclude_user_id=user["id"]) == 0:
            raise ValueError("Impossible de supprimer le dernier compte administrateur.")
        _users.pop(user["id"], None)
        _save_users()
        # Toute session encore active pour ce compte doit cesser d'être valide immédiatement —
        # sans ça, un jeton déjà émis resterait utilisable jusqu'à expiration naturelle malgré
        # la suppression du compte.
        stale = [token for token, s in _sessions.items() if s["user_id"] == user["id"]]
        for token in stale:
            _sessions.pop(token, None)
        if stale:
            _save_sessions()


# ── Sessions ─────────────────────────────────────────────────────────────────────────────

def create_session(user_id: str) -> str:
    _ensure_sessions_fresh()
    with _lock:
        token = secrets.token_urlsafe(32)
        now = _now()
        _sessions[token] = {
            "token": token,
            "user_id": user_id,
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=SESSION_TTL_HOURS)).isoformat(),
        }
        _save_sessions()
        return token


def get_session(token: str) -> dict | None:
    """Renvoie l'utilisateur {id, username, role} lié à ce jeton, ou None si absent/expiré/
    compte supprimé entre-temps. Purge paresseusement la session expirée rencontrée — pas de
    tâche de fond dédiée, le volume de sessions est trivial pour ce dashboard."""
    if not token:
        return None
    _ensure_sessions_fresh()
    session = _sessions.get(token)
    if session is None:
        return None
    expires_at = datetime.fromisoformat(session["expires_at"])
    if _now() >= expires_at:
        with _lock:
            _sessions.pop(token, None)
            _save_sessions()
        return None
    _ensure_users_fresh()
    user = _users.get(session["user_id"])
    if user is None:
        # Compte supprimé après création de la session (delete_user purge déjà les siennes,
        # ce cas ne devrait plus se produire — gardé en filet de sécurité).
        with _lock:
            _sessions.pop(token, None)
            _save_sessions()
        return None
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        # Profils Vanitas (2026-09-10) — voyage avec CHAQUE requête authentifiée pour que
        # `require_vanitas_read/write` (auth/__init__.py) n'ait jamais besoin d'un aller-retour
        # supplémentaire vers `store`/`vanitas_profiles` par requête.
        "profile_id": user.get("profile_id"),
    }


def delete_session(token: str) -> None:
    _ensure_sessions_fresh()
    with _lock:
        if _sessions.pop(token, None) is not None:
            _save_sessions()


def delete_sessions_except(user_id: str, keep_token: str | None) -> None:
    """Invalide toutes les sessions actives d'un compte SAUF `keep_token` — appelée après un
    changement de mot de passe en self-service (page Paramètres, 2026-09-08) : les autres
    onglets/appareils connectés sous l'ancien mot de passe doivent être déconnectés (au cas où
    le motif du changement soit justement "je pense que quelqu'un d'autre le connaît"), mais
    pas la session qui vient de faire le changement elle-même — sinon l'utilisateur se
    retrouverait déconnecté de sa propre page Paramètres immédiatement après avoir cliqué
    "Enregistrer"."""
    _ensure_sessions_fresh()
    with _lock:
        stale = [t for t, s in _sessions.items() if s["user_id"] == user_id and t != keep_token]
        for t in stale:
            _sessions.pop(t, None)
        if stale:
            _save_sessions()
