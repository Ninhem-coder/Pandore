"""
Cache mémoire process générique, à durée de vie (TTL) par clé — extrait à la revue
d'architecture du 2026-08-17.

Avant ce module, `intune/tools.py::get_compliance_detail` et `defender/anssi.py::
get_anssi_matches` réimplémentaient chacun le même besoin ("mémoriser le résultat d'un
calcul coûteux en mémoire process, avec une expiration au bout de N secondes, thread-safe")
avec deux API légèrement différentes : `anssi.py` exposait un `force_refresh` câblé jusqu'au
bouton "Rafraîchir" du frontend, `get_compliance_detail` n'en avait aucun (il fallait
attendre l'expiration du TTL). Un futur troisième endroit ayant besoin du même pattern
aurait probablement recopié l'un des deux, avec le risque de reproduire un bug déjà corrigé
une fois sur chacun (cache devenu module-level partagé entre appels concurrents pour
`get_compliance_detail`, verrou manquant pour `anssi.py`).

Volontairement minimal : pas d'éviction LRU, pas de taille maximale — inutile pour un outil
mono-utilisateur où le nombre de clés distinctes par cache reste petit (quelques valeurs de
`max_devices`, quelques valeurs de `window_days`). Si un futur usage a besoin de bien plus
que ça, ce sera le signal qu'une dépendance dédiée (cachetools, par exemple) est justifiée.
"""
import threading
import time
import typing

_UNSET = object()


class TTLCache:
    """Cache clé → valeur avec expiration par entrée. Thread-safe (un seul verrou interne,
    suffisant vu le faible nombre de clés attendues — pas besoin d'un verrou par clé)."""

    def __init__(self, ttl_seconds: float):
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._store: dict[typing.Hashable, tuple[float, typing.Any]] = {}

    def get(self, key: typing.Hashable) -> typing.Any:
        """Renvoie la valeur en cache pour `key` si elle existe et n'a pas expiré, sinon
        `None`. Ne distingue pas "jamais mise en cache" de "valeur explicitement None" —
        aucun des deux appelants actuels (get_compliance_detail, get_anssi_matches) ne met
        `None` en cache, donc l'ambiguïté ne se pose pas en pratique."""
        with self._lock:
            entry = self._store.get(key, _UNSET)
        if entry is _UNSET:
            return None
        fetched_at, value = entry
        if time.monotonic() - fetched_at >= self._ttl_seconds:
            return None
        return value

    def set(self, key: typing.Hashable, value: typing.Any) -> None:
        with self._lock:
            self._store[key] = (time.monotonic(), value)
