"""Client HTTP vers l'API NVD 2.0 (National Vulnerability Database) — gratuite, sans les
contraintes de licence de `cve-bin-tool` (GPL-3.0, écarté pour ce projet — voir le plan du
jalon 2, décision prise avec Nicolas après avoir vérifié que la lib n'évite de toute façon pas
le vrai problème : la correspondance nom libre → identifiant CPE).

Respecte le rythme d'appel imposé par NVD : 0,6s entre requêtes avec une clé API, 6s sans
(https://nvd.nist.gov/developers/start-here).
"""
import asyncio
import time
from dataclasses import dataclass

import httpx

from . import config


@dataclass
class CveFindingData:
    cve_id: str
    cvss_score: float | None
    severity: str | None
    published: str | None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    exact_version: str | None = None

_BASE_URL = "https://services.nvd.nist.gov/rest/json"
_last_request_at: float = 0.0


def _min_delay_seconds() -> float:
    return 0.6 if config.NVD_API_KEY else 6.0


async def _throttle() -> None:
    """Respecte le délai minimum entre deux appels NVD, quel que soit l'endpoint appelé —
    état partagé au niveau module puisque NVD limite le rythme par client, pas par endpoint."""
    global _last_request_at
    elapsed = time.monotonic() - _last_request_at
    wait = _min_delay_seconds() - elapsed
    if wait > 0:
        await asyncio.sleep(wait)
    _last_request_at = time.monotonic()


def _headers() -> dict[str, str]:
    return {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}


async def search_cpe_candidates(keyword: str, max_results: int = 20) -> list[tuple[str, str]]:
    """Cherche des CPE dont les métadonnées contiennent `keyword`, renvoie les couples
    (vendor, product) distincts extraits des `cpeName` trouvés — pas de "meilleur candidat"
    ici, le scoring/la décision finale sont faits par cve_matching.py (jamais présenté comme
    une certitude à ce stade)."""
    await _throttle()

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{_BASE_URL}/cpes/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            headers=_headers(),
        )
    response.raise_for_status()
    payload = response.json()

    candidates: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for product in payload.get("products", []):
        cpe_name = product.get("cpe", {}).get("cpeName", "")
        parts = cpe_name.split(":")
        # cpe:2.3:part:vendor:product:version:... -> vendor à l'index 3, product à l'index 4
        if len(parts) > 4:
            vendor, name = parts[3], parts[4]
            if (vendor, name) not in seen:
                seen.add((vendor, name))
                candidates.append((vendor, name))

    return candidates


def _best_cvss(metrics: dict) -> tuple[float | None, str | None]:
    """Préfère la métrique la plus récente disponible (v3.1 > v3.0 > v2) — la sévérité vit
    dans cvssData pour v3.x, mais à côté de cvssData (pas dedans) pour v2."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = entries[0]
        cvss_data = entry.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or entry.get("baseSeverity")
        return score, severity
    return None, None


def _matches_target(criteria: str, vendor: str, product: str) -> bool:
    parts = criteria.split(":")
    return len(parts) > 4 and parts[3] == vendor and parts[4] == product


async def fetch_cves_for_cpe(vendor: str, product: str, max_results: int = 2000) -> list[CveFindingData]:
    """Récupère les CVE associées à ce couple (vendor, product), toutes versions confondues,
    avec les bornes de version affectées quand NVD les précise.

    Limite connue et assumée pour ce jalon : une seule page — `max_results=2000` est le
    MAXIMUM autorisé par l'API (`resultsPerPage`), pas une limite arbitraire choisie ici.
    Confirmé en testant contre Firefox : l'API trie du plus ancien au plus récent par défaut,
    donc plafonner plus bas (200, essayé initialement) ne renvoyait QUE des CVE de 2003-2006
    pour un produit aussi suivi — les plus anciennes, jamais les plus pertinentes pour une
    version récente. Un produit avec plus de 2000 CVE au total (extrêmement rare — Firefox
    lui-même n'en a que quelques milliers cumulés depuis 2003) verrait encore les plus
    récentes tronquées ; la vraie pagination (`startIndex`) reste à ajouter si un cas réel
    l'exige un jour.
    """
    await _throttle()

    virtual_match_string = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{_BASE_URL}/cves/2.0",
            params={"virtualMatchString": virtual_match_string, "resultsPerPage": max_results},
            headers=_headers(),
        )
    response.raise_for_status()
    payload = response.json()

    findings: list[CveFindingData] = []
    for vuln in payload.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        cvss_score, severity = _best_cvss(cve.get("metrics", {}))
        published = cve.get("published")

        # Une CVE peut avoir plusieurs conditions de version pour le même produit (plages
        # disjointes) — une ligne par condition trouvée, jamais une seule bornée au hasard.
        # NVD répète parfois la MÊME condition sur plusieurs nœuds (combinaisons d'OS) : on
        # déduplique par tuple de bornes pour ne pas stocker des dizaines de lignes identiques.
        match_found = False
        seen_bounds: set[tuple] = set()
        for configuration in cve.get("configurations", []):
            for node in configuration.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if not cpe_match.get("vulnerable") or not _matches_target(criteria, vendor, product):
                        continue

                    match_found = True
                    version_segment = criteria.split(":")[5] if len(criteria.split(":")) > 5 else "*"
                    exact_version = version_segment if version_segment not in ("*", "-") else None

                    bounds = (
                        cpe_match.get("versionStartIncluding"),
                        cpe_match.get("versionStartExcluding"),
                        cpe_match.get("versionEndIncluding"),
                        cpe_match.get("versionEndExcluding"),
                        exact_version,
                    )
                    if bounds in seen_bounds:
                        continue
                    seen_bounds.add(bounds)

                    findings.append(CveFindingData(
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        severity=severity,
                        published=published,
                        version_start_including=bounds[0],
                        version_start_excluding=bounds[1],
                        version_end_including=bounds[2],
                        version_end_excluding=bounds[3],
                        exact_version=bounds[4],
                    ))

        if not match_found:
            # La CVE est revenue par virtualMatchString mais aucune condition exploitable
            # n'a été retrouvée (configuration inhabituelle) — on la garde quand même, sans
            # borne de version, plutôt que de la perdre silencieusement.
            findings.append(CveFindingData(cve_id=cve_id, cvss_score=cvss_score, severity=severity, published=published))

    return findings
