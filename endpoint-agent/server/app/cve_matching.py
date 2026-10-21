"""Rapprochement approximatif entre un nom de produit issu du registre (texte libre) et un
identifiant CPE NVD (vendor, product) — jamais présenté comme une certitude : un nom trop
ambigu reste "non rapproché" plutôt que de deviner (même philosophie que le rapprochement
ANSSI/CERT-FR déjà en production sur le dashboard DSI, voir le plan du jalon 2).
"""
import re
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import nvd_client
from .models import CveFinding, InstalledApp, InventorySnapshot, ProductCpeMatch

_NOISE_TOKENS = {
    "x64", "x86", "64", "32", "bit", "edition", "version", "for", "windows",
    "fr", "en", "de", "it", "es", "nl", "the", "a", "and", "of", "co",
}


_VERSION_LIKE = re.compile(r"^v?\d+(\.\d+){1,3}[a-z]?$")


def _tokenize(text: str) -> set[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {w for w in words if w not in _NOISE_TOKENS and not w.isdigit()}


def _clean_search_query(name: str) -> str:
    """NVD `keywordSearch` matche mal un nom bruité par un numéro de version ou du texte entre
    parenthèses (ex. "7-Zip 26.02 (x64)" ne renvoie rien) — on nettoie avant de chercher, le
    scoring lui-même (via _tokenize) reste appliqué sur le nom d'origine."""
    without_parens = re.sub(r"\([^)]*\)", " ", name)
    words = [w for w in without_parens.split() if not _VERSION_LIKE.match(w.strip(",;"))]
    return " ".join(words).strip()


async def match_product_to_cpe(name: str) -> tuple[str, str] | None:
    """Cherche le meilleur candidat CPE pour ce nom de produit — renvoie None plutôt que de
    forcer une correspondance peu fiable sur un nom trop générique/ambigu."""
    name_tokens = _tokenize(name)
    if not name_tokens:
        return None

    query = _clean_search_query(name)
    if not query:
        return None

    candidates = await nvd_client.search_cpe_candidates(query)

    best: tuple[str, str] | None = None
    best_score = 0
    for vendor, product in candidates:
        product_tokens = _tokenize(product.replace("_", " ").replace("-", " "))
        vendor_tokens = _tokenize(vendor.replace("_", " ").replace("-", " "))

        product_overlap = len(name_tokens & product_tokens)
        if product_overlap == 0:
            continue  # jamais de correspondance sans au moins un mot du PRODUIT en commun

        score = product_overlap + len(name_tokens & vendor_tokens)
        if score > best_score:
            best_score = score
            best = (vendor, product)

    return best


def _parse_published(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _latest_snapshot_id_per_agent(db: Session) -> list[int]:
    """Le dernier snapshot de CHAQUE agent (pas tout l'historique) — on ne matche jamais sur
    une version d'app qui n'est plus installée."""
    latest = (
        select(InventorySnapshot.agent_id, func.max(InventorySnapshot.collected_at).label("max_at"))
        .group_by(InventorySnapshot.agent_id)
        .subquery()
    )
    rows = db.execute(
        select(InventorySnapshot.id).join(
            latest,
            (InventorySnapshot.agent_id == latest.c.agent_id)
            & (InventorySnapshot.collected_at == latest.c.max_at),
        )
    ).scalars().all()
    return list(rows)


def _distinct_product_names(db: Session, snapshot_ids: list[int]) -> list[str]:
    if not snapshot_ids:
        return []
    rows = db.execute(
        select(InstalledApp.name).where(InstalledApp.snapshot_id.in_(snapshot_ids)).distinct()
    ).scalars().all()
    return list(rows)


async def refresh_products(db: Session, product_names: list[str]) -> None:
    """Matche les noms jamais vus, puis refetch les CVE de TOUS les produits déjà matchés
    parmi `product_names` (nouveaux ET anciens — un produit déjà matché peut avoir de
    nouvelles CVE publiées depuis le dernier passage)."""
    distinct_names = sorted({n for n in product_names if n})
    if not distinct_names:
        return

    already_cached = set(
        db.execute(
            select(ProductCpeMatch.product_name).where(ProductCpeMatch.product_name.in_(distinct_names))
        ).scalars().all()
    )

    for name in distinct_names:
        if name in already_cached:
            continue
        match = await match_product_to_cpe(name)
        vendor, product = match if match else (None, None)
        db.add(ProductCpeMatch(product_name=name, cpe_vendor=vendor, cpe_product=product))
    db.commit()

    matched = db.execute(
        select(ProductCpeMatch).where(
            ProductCpeMatch.product_name.in_(distinct_names),
            ProductCpeMatch.cpe_vendor.is_not(None),
        )
    ).scalars().all()

    for entry in matched:
        findings = await nvd_client.fetch_cves_for_cpe(entry.cpe_vendor, entry.cpe_product)
        db.execute(delete(CveFinding).where(CveFinding.product_name == entry.product_name))
        db.add_all(
            CveFinding(
                product_name=entry.product_name,
                cve_id=f.cve_id,
                cvss_score=f.cvss_score,
                severity=f.severity,
                published=_parse_published(f.published),
                version_start_including=f.version_start_including,
                version_start_excluding=f.version_start_excluding,
                version_end_including=f.version_end_including,
                version_end_excluding=f.version_end_excluding,
                exact_version=f.exact_version,
            )
            for f in findings
        )
        db.commit()


async def refresh_fleet(db: Session) -> None:
    """Rafraîchit tous les agents — le cycle automatique périodique."""
    names = _distinct_product_names(db, _latest_snapshot_id_per_agent(db))
    await refresh_products(db, names)


def _version_tuple(version: str) -> tuple[int, ...] | None:
    """Convertit une chaîne de version en tuple d'entiers comparable — renvoie None si aucun
    chiffre n'est exploitable (jamais un résultat inventé sur un format non reconnu)."""
    digits = re.findall(r"\d+", version)
    return tuple(int(d) for d in digits) if digits else None


def _compare_versions(a: str, b: str) -> int | None:
    """-1/0/1 (a <, =, > b), ou None si l'une des deux versions n'est pas comparable."""
    ta, tb = _version_tuple(a), _version_tuple(b)
    if ta is None or tb is None:
        return None
    length = max(len(ta), len(tb))
    ta = ta + (0,) * (length - len(ta))
    tb = tb + (0,) * (length - len(tb))
    return (ta > tb) - (ta < tb)


def is_version_affected(installed_version: str | None, finding: CveFinding) -> bool | None:
    """La version installée tombe-t-elle dans la plage vulnérable de cette CVE ?

    `None` = indéterminable (version manquante, format non comparable, ou borne NVD non
    exploitable) — jamais élevé au rang de conclusion positive ou négative, même philosophie
    que le reste de ce module."""
    if not installed_version:
        return None

    if finding.exact_version is not None:
        cmp = _compare_versions(installed_version, finding.exact_version)
        return None if cmp is None else cmp == 0

    bounds = (
        finding.version_start_including,
        finding.version_start_excluding,
        finding.version_end_including,
        finding.version_end_excluding,
    )
    if all(b is None for b in bounds):
        # NVD ne précise aucune restriction de version pour cette CVE sur ce produit : on
        # suit NVD lui-même, toutes les versions sont considérées concernées.
        return True

    if finding.version_start_including is not None:
        cmp = _compare_versions(installed_version, finding.version_start_including)
        if cmp is None:
            return None
        if cmp < 0:
            return False
    if finding.version_start_excluding is not None:
        cmp = _compare_versions(installed_version, finding.version_start_excluding)
        if cmp is None:
            return None
        if cmp <= 0:
            return False
    if finding.version_end_including is not None:
        cmp = _compare_versions(installed_version, finding.version_end_including)
        if cmp is None:
            return None
        if cmp > 0:
            return False
    if finding.version_end_excluding is not None:
        cmp = _compare_versions(installed_version, finding.version_end_excluding)
        if cmp is None:
            return None
        if cmp >= 0:
            return False

    return True
