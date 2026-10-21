"""
Profils Vanitas (2026-09-10, demande de Nicolas — "comme dans Intune... un read pour voir et
un read-write pour lecture-écriture").

Jusqu'ici Vanitas ne connaissait que deux rôles Pandore globaux : admin (accès total) et
viewer (accès en lecture à peu près partout, sauf une poignée de capacités marquées
`require_admin` — terminal, catalogue de règles de conformité, groupes, installeurs). Ce module
introduit un niveau intermédiaire : des PROFILS nommés et réutilisables, chacun une matrice
`{module: "none"|"read"|"write"}` sur les 5 fonctionnalités Vanitas qui ont une vraie
distinction lecture/écriture (Postes, Terminal, Applications, Conformité, Groupes).

Décisions de cadrage (AskUserQuestion + échanges de suivi, 2026-09-09/10) :
- Vanitas SEULEMENT — Pandore garde son admin/viewer global inchangé (voir `auth/__init__.py::
  require_admin`, toujours utilisé tel quel pour les capacités Pandore-only).
- Profils nommés réutilisables (façon rôle Intune), PAS une matrice éditée compte par compte.
- Admin reste un super-rôle : accès total automatique, jamais besoin d'un profil.
- Un compte "viewer" SANS profil assigné n'a plus AUCUN accès à Vanitas (refus par défaut) —
  avant ce jalon, "viewer" avait un accès en lecture large par défaut sur Vanitas ; ce module
  inverse la polarité, un accès doit désormais être explicitement accordé via un profil.
- Gestion des comptes/profils déplacée de "Paramètres" vers une page "Profils" dédiée, sous
  Vanitas > Administration (demande de suivi de Nicolas — "gérer les comptes direct de la
  page plutôt que les paramètres").

Même motif de persistance que `auth/store.py` (JSON + verrou + invalidation par mtime) —
gitignored comme `auth_users.json`/`auth_sessions.json` : configuration d'instance propre à ce
déploiement, jamais un artefact à versionner (contrairement à `app_library.json`).
"""
import json
import threading
import uuid
from datetime import datetime, timezone

from common.atomic_io import atomic_write_text
from common.config import BACKEND_DIR

PROFILES_FILE = BACKEND_DIR / "data" / "vanitas_profiles.json"
PROFILES_FILE.parent.mkdir(exist_ok=True)

_lock = threading.Lock()

# Les fonctionnalités Vanitas qui ont une vraie distinction lecture/écriture — voir la
# maquette validée par Nicolas (page "Profils"). Les pages purement d'observation fleet-wide
# (Vue d'ensemble, Journal, Vulnérabilités, Logiciels obsolètes) n'ont pas leur propre module :
# elles exigent seulement qu'un profil quelconque soit assigné (voir `auth/__init__.py::
# require_vanitas_any`), pas une permission par fonctionnalité — ce sont des agrégats qui
# recoupent tous les modules, pas une fonctionnalité éditable en propre.
# "activites_suspectes" (jalon "détection d'activités suspectes sur les postes") — triage du
# journal d'événements comportementaux remontés par l'agent (processus/event log/réseau/USB) :
# lecture large, écriture = accuser réception/faux positif/escalade (action à conséquence).
MODULES = ("postes", "terminal", "applications", "conformite", "groupes", "activites_suspectes")
LEVELS = ("none", "read", "write")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json() -> dict:
    if not PROFILES_FILE.exists():
        return {}
    try:
        return json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Fichier corrompu/tronqué — repartir vide plutôt que de faire planter tout le
        # dashboard au démarrage (même choix que `auth/store.py::_read_json`).
        return {}


def _write_json(data: dict) -> None:
    atomic_write_text(PROFILES_FILE, json.dumps(data, ensure_ascii=False, indent=2))


def _mtime() -> float:
    try:
        return PROFILES_FILE.stat().st_mtime_ns
    except OSError:
        return -1


def _normalize_perms(perms: dict | None) -> dict:
    perms = perms or {}
    return {m: perms.get(m) if perms.get(m) in LEVELS else "none" for m in MODULES}


def _load() -> None:
    global _profiles, _profiles_mtime
    _profiles = _read_json().get("profiles_by_id", {})
    _profiles_mtime = _mtime()


_profiles: dict[str, dict] = {}
_profiles_mtime: float = -2  # jamais égal à _mtime() au premier appel -> force le 1er chargement
_load()


def _ensure_fresh() -> None:
    """Même correctif que `auth/store.py::_ensure_users_fresh` (revue du 2026-09-07) :
    `manage_users.py`/un futur script d'admin direct tournent dans un process séparé de
    `api_server.py` — un `stat()` avant chaque lecture, un rechargement complet seulement si le
    fichier a changé depuis la dernière lecture de CE process."""
    if _mtime() != _profiles_mtime:
        _load()


def _save() -> None:
    global _profiles_mtime
    _write_json({"profiles_by_id": _profiles})
    _profiles_mtime = _mtime()


def list_profiles() -> list[dict]:
    _ensure_fresh()
    return sorted(_profiles.values(), key=lambda p: p["name"].lower())


def get_profile(profile_id: str | None) -> dict | None:
    if not profile_id:
        return None
    _ensure_fresh()
    return _profiles.get(profile_id)


def create_profile(name: str, perms: dict | None = None) -> dict:
    name = name.strip()
    if not name:
        raise ValueError("Le nom du profil ne peut pas être vide.")
    with _lock:
        profile_id = uuid.uuid4().hex
        profile = {
            "id": profile_id,
            "name": name,
            "perms": _normalize_perms(perms),
            "created_at": _now(),
            "updated_at": _now(),
        }
        _profiles[profile_id] = profile
        _save()
        return profile


def update_profile(profile_id: str, name: str | None = None, perms: dict | None = None) -> dict:
    profile = get_profile(profile_id)
    if not profile:
        raise ValueError("Profil introuvable.")
    with _lock:
        if name is not None:
            name = name.strip()
            if not name:
                raise ValueError("Le nom du profil ne peut pas être vide.")
            profile["name"] = name
        if perms is not None:
            profile["perms"] = _normalize_perms(perms)
        profile["updated_at"] = _now()
        _save()
        return profile


def delete_profile(profile_id: str, assigned_count: int) -> None:
    """`assigned_count` calculé par l'appelant (`api_server.py`, via `auth/store.py::
    count_users_with_profile`) — ce module ignore tout des comptes, même séparation de
    responsabilité que `auth/store.py` qui ignore tout des profils."""
    if not get_profile(profile_id):
        raise ValueError("Profil introuvable.")
    if assigned_count > 0:
        raise ValueError(
            f"Impossible de supprimer ce profil : {assigned_count} compte(s) l'utilisent encore."
        )
    with _lock:
        _profiles.pop(profile_id, None)
        _save()


def resolved_perms(profile_id: str | None) -> dict:
    """Matrice EFFECTIVE pour un compte viewer donné — `{module: "none"}` sur les 5 modules si
    aucun profil n'est assigné ou si le profil référencé a été supprimé entre-temps (jamais une
    exception : un profil manquant doit se comporter comme "aucun accès", pas planter la
    fiche `/api/auth/me`)."""
    profile = get_profile(profile_id)
    if not profile:
        return {m: "none" for m in MODULES}
    return dict(profile["perms"])


def has_access(profile_id: str | None, module: str, level: str) -> bool:
    """`level` = "read" ou "write". Un profil "write" satisfait aussi une exigence "read"
    (l'écriture implique la lecture)."""
    granted = resolved_perms(profile_id).get(module, "none")
    if level == "read":
        return granted in ("read", "write")
    return granted == "write"
