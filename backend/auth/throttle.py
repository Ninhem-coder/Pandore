"""Anti-bruteforce léger sur `/api/auth/login` (2026-09-12, durcissement).

CLAUDE.md documentait explicitement l'absence de limitation de tentatives comme un choix
assumé de v1 ("outil interne, non exposé sur Internet, argon2 ralentit déjà nativement le
brute-force"). argon2 renchérit CHAQUE tentative (bon), mais ne STOPPE jamais un attaquant
persistant — un verrou temporaire après N échecs, si. Ajouté ici en défense en profondeur
maintenant que le dashboard peut être joignable en LAN.

Clé de comptage = **IP source**, pas l'identifiant visé — délibéré, pour deux raisons :
- un attaquant qui ferait tourner les identifiants depuis une même IP est throttlé quoi qu'il
  essaie ;
- keyer sur l'identifiant permettrait à un tiers de VERROUILLER le compte d'un utilisateur
  légitime en déclenchant volontairement des échecs sur son nom (déni de service) — keyer sur
  l'IP l'évite : un attaquant ne bloque que sa propre source.

En mémoire de process (dict + verrou), remis à zéro au redémarrage — acceptable pour un outil
interne à quelques comptes : un redémarrage n'est pas un vecteur qu'un attaquant contrôle, et
la persistance d'un compteur d'échecs n'apporterait rien face à la menace réelle (brute-force
en ligne soutenu). `time.monotonic()` plutôt que l'horloge murale : immunisé contre un
changement d'heure système (NTP, DST) qui fausserait une fenêtre calculée en temps absolu.
"""
import threading
import time

# Après _MAX_FAILURES échecs dans une fenêtre de _WINDOW_SECONDS, l'IP est verrouillée pendant
# _LOCKOUT_SECONDS. Valeurs volontairement généreuses : ne jamais gêner un humain qui se trompe
# deux-trois fois de mot de passe, tout en cassant net un brute-force automatisé.
_MAX_FAILURES = 10
_WINDOW_SECONDS = 300
_LOCKOUT_SECONDS = 300

_lock = threading.Lock()
_failures: dict[str, list[float]] = {}
_locked_until: dict[str, float] = {}


def check(key: str) -> float | None:
    """Renvoie le nombre de secondes de blocage restantes si `key` est verrouillée, sinon
    `None`. Purge l'entrée dès que le verrou a expiré (le prochain échec repart d'une fenêtre
    propre)."""
    now = time.monotonic()
    with _lock:
        until = _locked_until.get(key)
        if until is None:
            return None
        if now >= until:
            _locked_until.pop(key, None)
            _failures.pop(key, None)
            return None
        return until - now


def record_failure(key: str) -> None:
    """Enregistre un échec pour `key` ; déclenche le verrou si le seuil est atteint dans la
    fenêtre glissante."""
    now = time.monotonic()
    with _lock:
        window = [t for t in _failures.get(key, []) if now - t < _WINDOW_SECONDS]
        window.append(now)
        _failures[key] = window
        if len(window) >= _MAX_FAILURES:
            _locked_until[key] = now + _LOCKOUT_SECONDS
            _failures.pop(key, None)


def reset(key: str) -> None:
    """Réinitialise les compteurs pour `key` — appelé sur une connexion réussie, pour qu'une
    série d'échecs suivie d'un succès légitime ne laisse pas de résidu."""
    with _lock:
        _failures.pop(key, None)
        _locked_until.pop(key, None)
