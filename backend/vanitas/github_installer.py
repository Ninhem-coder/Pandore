"""Recherche/récupération de releases GitHub pour le catalogue d'installeurs Vanitas
(2026-09-11, demande de Nicolas : "dans application la fonctionnalité permettait de me baser
sur un github mais la c'est pas possible sur Vanitas, tu peux regler ca") — parité avec
`DeployAppWizard.jsx`/`backend/intune/packaging.py` côté Pandore, qui a déjà cette capacité
pour l'assistant de packaging Win32 Intune.

Duplique volontairement (plutôt que d'importer) `intune/packaging.py::github_list_releases`/
`github_lookup_releases`/le garde-fou de sécurité de `github_fetch_asset` : Vanitas n'a aucune
notion de "job" de packaging multi-étapes (upload/téléchargement → IntuneWinAppUtil.exe →
zip) — un catalogue d'installeur Vanitas s'alimente en UN SEUL appel (voir
`vanitas/client.py::upload_installer`, qui accepte déjà n'importe quel flux binaire). Coupler
les deux modules pour ~15 lignes de code réseau générique aurait été plus risqué (une future
évolution de l'un cassant silencieusement l'autre) que de dupliquer une logique aussi petite et
stable.

`download_asset` télécharge l'asset choisi PAR L'ADMIN (jamais de sélection automatique — même
garde-fou que côté Pandore) EN MÉMOIRE (pas de scratch dir à gérer, contrairement au job
Pandore) puis le renvoie tel quel à l'appelant (`api_server.py`), qui le relaie IMMÉDIATEMENT à
`vanitas_client.upload_installer` dans la MÊME requête — les octets ne transitent jamais par le
navigateur.
"""
import hashlib
import re
from urllib.parse import quote, urlparse

import httpx

from common.http_client import handle_tool_errors

# 1 Go — même plafond que `intune/packaging.py::MAX_SOURCE_SIZE_BYTES`, même raisonnement
# (hygiène de base, pas une vraie frontière de sécurité pour l'admin de confiance unique de ce
# dashboard local).
MAX_ASSET_BYTES = 1024 * 1024 * 1024
_CHUNK_SIZE = 1024 * 1024

# Même liste blanche d'hôtes que `intune/packaging.py::_ALLOWED_DOWNLOAD_HOSTS`.
_ALLOWED_DOWNLOAD_HOSTS = {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
_GITHUB_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,255}$")


def _sanitize_filename(filename: str) -> str:
    """Même logique que `intune/packaging.py::_sanitize_filename` (y compris le correctif du
    2026-09-07 sur un nom composé uniquement de points)."""
    from pathlib import Path

    name = Path(filename or "installeur").name
    if _SAFE_FILENAME_RE.match(name) and name.strip(".") != "":
        return name
    ext = Path(name).suffix
    return f"installeur{ext}" if re.match(r"^\.[A-Za-z0-9]{1,10}$", ext) else "installeur"


@handle_tool_errors
def list_releases(owner: str, repo: str) -> dict:
    """Liste TOUTES les releases publiées d'un dépôt GitHub public — juste les métadonnées
    (tag/nom/date), PAS les assets de chacune (récupérés seulement une fois une release
    choisie, voir `lookup_release`)."""
    if not _GITHUB_SEGMENT_RE.match(owner or "") or not _GITHUB_SEGMENT_RE.match(repo or ""):
        raise ValueError("Organisation ou dépôt GitHub invalide.")
    resp = httpx.get(
        f"https://api.github.com/repos/{owner}/{repo}/releases",
        headers={"Accept": "application/vnd.github+json"},
        params={"per_page": 100},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return {
        "releases": [
            {"tagName": r.get("tag_name"), "name": r.get("name"), "publishedAt": r.get("published_at")}
            for r in data
        ],
    }


@handle_tool_errors
def lookup_release(owner: str, repo: str, tag: str | None = None) -> dict:
    """Liste TOUS les assets d'UNE release — ne télécharge rien, aucune sélection automatique
    (l'admin choisit toujours l'asset dans l'UI). `tag` absent → dernière release."""
    if not _GITHUB_SEGMENT_RE.match(owner or "") or not _GITHUB_SEGMENT_RE.match(repo or ""):
        raise ValueError("Organisation ou dépôt GitHub invalide.")
    if tag:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{quote(tag, safe='')}"
    else:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    resp = httpx.get(url, headers={"Accept": "application/vnd.github+json"}, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "tagName": data.get("tag_name"),
        "publishedAt": data.get("published_at"),
        "assets": [
            {"name": a.get("name"), "sizeBytes": a.get("size"), "downloadUrl": a.get("browser_download_url")}
            for a in data.get("assets", [])
        ],
    }


@handle_tool_errors
def download_asset(download_url: str, asset_name: str) -> dict:
    """Télécharge l'asset CHOISI PAR L'ADMIN en mémoire (pas de scratch dir, contrairement au
    job Pandore) et renvoie `{"content": bytes, "filename": str, "sizeBytes": int, "sha256": str}`
    — `content` n'est jamais sérialisé tel quel dans une réponse HTTP, uniquement consommé en
    interne par la route qui relaie vers `vanitas_client.upload_installer` dans la même requête.

    Revérifie l'hôte FINAL après redirections (`resp.url.host`, pas seulement l'URL de départ)
    — même correctif de sécurité que `intune/packaging.py::github_fetch_asset` (2026-09-02,
    protection contre une redirection GitHub menant hors de la liste blanche)."""
    host = urlparse(download_url or "").hostname or ""
    if host not in _ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError(f"URL de téléchargement hors GitHub refusée : {download_url!r}")

    sha256 = hashlib.sha256()
    size = 0
    chunks: list[bytes] = []
    with httpx.stream("GET", download_url, follow_redirects=True, timeout=120) as resp:
        final_host = resp.url.host or ""
        if final_host not in _ALLOWED_DOWNLOAD_HOSTS:
            raise ValueError(f"Redirection de téléchargement hors GitHub refusée : {str(resp.url)!r}")
        resp.raise_for_status()
        for chunk in resp.iter_bytes(_CHUNK_SIZE):
            if not chunk:
                continue
            size += len(chunk)
            if size > MAX_ASSET_BYTES:
                raise ValueError(f"Fichier trop volumineux (> {MAX_ASSET_BYTES // (1024 * 1024)} Mo).")
            sha256.update(chunk)
            chunks.append(chunk)

    return {
        "content": b"".join(chunks),
        "filename": _sanitize_filename(asset_name),
        "sizeBytes": size,
        "sha256": sha256.hexdigest(),
    }
