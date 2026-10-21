"""
Résolution des noms d'application Android (2026-09-02, demande de Nicolas : "on sait que
fr.paylib.paylib c'est Paylib, on aurait pas une bibliothèque sur laquelle on peut se baser
pour afficher le nom display de l'app ?").

Constat vérifié en direct contre le tenant de production AVANT d'écrire ce module : sur
`get_device_detected_apps` (intune/apps.py), `displayName` est le nom convivial choisi par
l'éditeur pour Windows ("7-Zip 26.02 (x64 edition)") ET pour iOS ("Acrobat", "Bourse"...) —
mais reste l'identifiant de PAQUET brut (reverse-DNS, ex. "com.android.chrome",
"fr.paylib.paylib") pour à peu près TOUTE application Android, système ou non (460 apps
observées sur un device réel, quasiment aucune avec un nom lisible). C'est un défaut de
l'agent Intune côté Android, pas un bug de ce dashboard.

Aucune API Google officielle et gratuite n'existe pour ça — la seule "bibliothèque" praticable
est la fiche publique du Google Play Store elle-même, dont le titre EST le nom convivial de
l'app. Scraping (même motif déjà établi dans ce projet pour cert.ssi.gouv.fr,
`defender/anssi.py`) : `GET https://play.google.com/store/apps/details?id={package}`, titre
extrait du `<h1 itemprop="name">` (repli sur `<title>`).

**Testé en direct AVANT d'écrire ce module** : "com.android.chrome" → "Google Chrome",
"com.adobe.reader" → "Adobe Acrobat Reader pour PDF", tous deux résolus en ~250-850ms.
"com.android.bluetooth" (composant système AOSP, jamais publié sur le Play Store) → 404,
confirmé attendu (aucun listing public à trouver). "fr.paylib.paylib" (le paquet cité par
Nicolas) → 404 lui aussi, confirmé RÉEL (pas un bug de scraping — comparé à "com.android.
bluetooth" sur la même page Play Store, structure de page identique) : soit l'app a été
retirée/renommée depuis, soit c'est un paquet interne à l'app bancaire jamais indexé
publiquement. Documenté honnêtement : cette approche résout les apps grand public réellement
listées (Chrome, Adobe, la plupart des apps courantes), pas les paquets système ni les apps
délistées/privées — dans ce cas le nom brut reste affiché, jamais pire qu'avant.

Cache PERSISTANT tenant-wide (`backend/data/app_name_cache.json`, gitignoré — pure donnée
dérivée/regénérable, contrairement à `app_library.json`/`watched_cves.json` qui portent de
l'intention utilisateur) : le même paquet système (com.android.chrome...) revient sur des
centaines d'appareils du parc, une résolution unique suffit pour tout le tenant. Un 404
confirmé est mis en cache (jamais retenté) ; une erreur réseau/timeout ne l'est PAS (retenue
au prochain chargement plutôt que de marquer un paquet "introuvable" pour un problème
transitoire).
"""
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - même garde que defender/anssi.py
    BeautifulSoup = None

from common.config import BACKEND_DIR
from common.atomic_io import atomic_write_text

_CACHE_FILE = BACKEND_DIR / "data" / "app_name_cache.json"
_CACHE_FILE.parent.mkdir(exist_ok=True)
_lock = threading.Lock()

# Identifiant reverse-DNS Android (au moins un point, minuscules/chiffres/underscore) — jamais
# le format d'un nom convivial Windows/iOS (espaces, majuscules, parenthèses) déjà observé sur
# ce même endpoint.
_ANDROID_PACKAGE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")


def _looks_like_android_package(name: str) -> bool:
    return bool(_ANDROID_PACKAGE_RE.match(name or ""))


def _read_cache() -> dict[str, str | None]:
    if not _CACHE_FILE.exists():
        return {}
    try:
        return json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Fichier corrompu — repartir d'un cache vide plutôt que de casser tout l'onglet
        # (même choix que app_library.py::_read_raw).
        return {}


def _write_cache(cache: dict[str, str | None]) -> None:
    atomic_write_text(_CACHE_FILE, json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True))


def _resolve_play_store(package_id: str) -> tuple[str | None, bool]:
    """Retourne (nom_résolu_ou_None, doit_être_mis_en_cache). Voir docstring de fichier pour
    le détail des cas 404 (mis en cache, confirmé non listé) vs erreur réseau (jamais mis en
    cache, retenté au prochain chargement)."""
    try:
        resp = httpx.get(
            "https://play.google.com/store/apps/details",
            params={"id": package_id, "hl": "fr", "gl": "FR"},
            timeout=6.0,
            headers={"User-Agent": "Mozilla/5.0"},
            follow_redirects=True,
        )
    except httpx.HTTPError:
        return None, False
    if resp.status_code == 404:
        return None, True
    if resp.status_code != 200 or BeautifulSoup is None:
        return None, False
    try:
        soup = BeautifulSoup(resp.text, "html.parser")
        h1 = soup.find("h1", attrs={"itemprop": "name"})
        name = h1.get_text(strip=True) if h1 else None
        if not name and soup.title:
            title = soup.title.get_text(strip=True)
            name = (
                title.split(" - Apps on Google Play")[0]
                .split(" – Applications sur Google Play")[0]
                .strip()
            )
    except Exception:
        return None, False
    return (name or None), bool(name)


def resolve_android_app_names(apps: list[dict]) -> list[dict]:
    """Reçoit la liste renvoyée par `get_device_detected_apps` (id/displayName/version/
    platform/sizeInByte) et remplace `displayName` par le nom Play Store quand l'entrée
    ressemble à un paquet Android brut ET a pu être résolue — l'identifiant d'origine est
    conservé sous `packageId` pour ne perdre aucune information technique. Isolée par
    l'appelant dans un try/except : une résolution ratée ne doit jamais faire disparaître la
    liste d'apps elle-même, seulement laisser les noms bruts inchangés."""
    candidate_indices = [
        i
        for i, a in enumerate(apps)
        if (a.get("platform") or "").lower().startswith("android")
        and _looks_like_android_package(a.get("displayName") or "")
    ]
    if not candidate_indices:
        return apps

    with _lock:
        cache = dict(_read_cache())

    packages = sorted({apps[i]["displayName"] for i in candidate_indices})
    to_fetch = [p for p in packages if p not in cache]

    if to_fetch:
        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(_resolve_play_store, to_fetch))
        to_persist: dict[str, str | None] = {}
        for pkg, (name, should_cache) in zip(to_fetch, results):
            cache[pkg] = name
            if should_cache:
                to_persist[pkg] = name
        if to_persist:
            with _lock:
                fresh = _read_cache()
                fresh.update(to_persist)
                _write_cache(fresh)

    out = list(apps)
    for i in candidate_indices:
        pkg = out[i]["displayName"]
        resolved = cache.get(pkg)
        if resolved:
            out[i] = {**out[i], "packageId": pkg, "displayName": resolved}
    return out
