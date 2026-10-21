"""Hachage de mot de passe (argon2id, via `argon2-cffi` — nouvelle dépendance ajoutée
`requirements.txt` spécifiquement pour cette fonctionnalité). Isolé dans son propre module
pour que `store.py` n'ait jamais à connaître le détail de l'algorithme."""
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


# Hash "leurre" (2026-09-07, revue de sécurité) — calculé une fois au démarrage sur une valeur
# aléatoire sans rapport avec aucun vrai mot de passe. Sert à `api_server.py::auth_login` pour
# TOUJOURS faire tourner argon2 (coûteux, volontairement) même quand l'identifiant fourni
# n'existe pas — sans lui, `if not user or not verify_password(...)` court-circuite en Python
# et ne hache RIEN pour un identifiant inconnu, ce qui répond quasi instantanément contre
# plusieurs dizaines de ms pour un identifiant réel avec un mauvais mot de passe : un minuteur
# côté client peut alors deviner quels identifiants existent sans jamais voir un mot de passe.
DUMMY_HASH = hash_password(secrets.token_hex(32))


def verify_password(plain: str, password_hash: str) -> bool:
    """Ne lève jamais — un hash corrompu/format inattendu doit se traduire par un login
    refusé, pas par une 500 qui remonterait un détail d'implémentation."""
    try:
        return _hasher.verify(password_hash, plain)
    except VerifyMismatchError:
        return False
    except Exception:
        return False
