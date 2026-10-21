"""
Écriture atomique de petits fichiers texte (JSON de préférence) — extrait à la revue de code
du 2026-08-20 : `common/history.py`, `common/auth.py` (cache de token MSAL en mode
interactif) et `defender/watchlist.py` écrivaient chacun leur fichier directement via
`Path.write_text(...)`, sans passer par un fichier temporaire + renommage. Un crash/kill du
process pile pendant l'écriture (coupure de courant, `Ctrl+C` mal placé, OOM killer) laisse
alors un fichier tronqué — le prochain chargement échoue au `json.loads` et, dans les trois
cas, le code appelant retombe sur un état vide plutôt que de signaler une corruption
(historique 90 jours perdu, watchlist CVE vidée, ou re-authentification interactive forcée).
`os.replace` est atomique sur un même système de fichiers (POSIX comme Windows) : soit
l'ancien contenu reste intact, soit le nouveau est intégralement en place, jamais un état
intermédiaire.
"""
import os
import tempfile
from pathlib import Path


def atomic_write_text(path: Path, text: str, mode: int | None = None) -> None:
    """Écrit `text` dans `path` de façon atomique (fichier temporaire dans le MÊME dossier,
    puis `os.replace`). `mode` (ex. `0o600`) restreint les permissions du fichier final si
    fourni — utile pour un fichier contenant un secret (cache de token MSAL), inutile pour un
    JSON non sensible (historique, watchlist CVE) où `mode=None` laisse les permissions par
    défaut de l'OS."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        if mode is not None:
            os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        # Le fichier temporaire ne doit jamais rester derrière en cas d'échec avant le
        # renommage (ex. erreur d'écriture disque) — sans ce nettoyage, `.token_cache/`
        # accumulerait des `.tmp` orphelins à chaque échec.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
